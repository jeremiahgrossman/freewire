package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// essentialsResolver is the scoped DNS resolver for Essentials Mode's domain
// allowlist (Phase 2). It answers ONLY allowlisted domains -- forwarding them to
// an upstream reachable through the tunnel, and dynamically routing the resolved
// IPs into the tunnel so the app's subsequent connection is carried -- and refuses
// everything else with NXDOMAIN, so a non-allowlisted app cannot resolve and stays
// blackholed on the physical path.
//
// It binds the DoH forwarder's address (127.0.0.1:53). In Essentials Mode over the
// DNS carrier the DoH forwarder is not running (that carrier is too slow for DoH),
// so the port is free and the system resolver is pointed here instead.
//
// The upstream is a plain resolver IP (e.g. 1.1.1.1:53) that setupRouting routes
// INTO the tunnel, so allowlisted lookups egress from our server, not the local
// network. This matches the DNS-1 tradeoff: encrypted to the server, resolved by
// the server's egress.
type essentialsResolver struct {
	domains  []string
	upstream string
	udp      *net.UDPConn
	tcp      net.Listener
	// addRoute installs ip/32 -> utun and tracks it for cleanup. Provided by
	// setupRouting, which owns the route table and its lock.
	addRoute func(ip string)

	mu     sync.Mutex
	routed map[string]bool // IPs already routed, so we do not re-add on every lookup
}

func startEssentialsResolver(domains []string, upstream string, addRoute func(ip string)) (*essentialsResolver, error) {
	ua, err := net.ResolveUDPAddr("udp4", dohListenAddr)
	if err != nil {
		return nil, err
	}
	uc, err := net.ListenUDP("udp4", ua)
	if err != nil {
		return nil, fmt.Errorf("essentials resolver bind %s: %w", dohListenAddr, err)
	}
	tl, err := net.Listen("tcp4", dohListenAddr)
	if err != nil {
		uc.Close()
		return nil, fmt.Errorf("essentials resolver bind tcp %s: %w", dohListenAddr, err)
	}
	r := &essentialsResolver{
		domains:  domains,
		upstream: upstream,
		udp:      uc,
		tcp:      tl,
		addRoute: addRoute,
		routed:   map[string]bool{},
	}
	go r.serveUDP()
	go r.serveTCP()
	fmt.Fprintf(os.Stderr,
		"freewire-tunnel: essentials resolver up on %s for %v (upstream %s, routed through the tunnel)\n",
		dohListenAddr, domains, upstream)
	return r, nil
}

func (r *essentialsResolver) Close() {
	if r == nil {
		return
	}
	if r.udp != nil {
		r.udp.Close()
	}
	if r.tcp != nil {
		r.tcp.Close()
	}
}

func (r *essentialsResolver) serveUDP() {
	buf := make([]byte, 4096)
	for {
		n, from, err := r.udp.ReadFromUDP(buf)
		if err != nil {
			return // listener closed
		}
		query := make([]byte, n)
		copy(query, buf[:n])
		go func() {
			reply := r.handle(query)
			if reply != nil {
				r.udp.WriteToUDP(reply, from) //nolint:errcheck
			}
		}()
	}
}

func (r *essentialsResolver) serveTCP() {
	for {
		conn, err := r.tcp.Accept()
		if err != nil {
			return
		}
		go r.handleTCP(conn)
	}
}

func (r *essentialsResolver) handleTCP(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	var lenBuf [2]byte
	if _, err := readFull(conn, lenBuf[:]); err != nil {
		return
	}
	qlen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if qlen == 0 || qlen > 4096 {
		return
	}
	query := make([]byte, qlen)
	if _, err := readFull(conn, query); err != nil {
		return
	}
	reply := r.handle(query)
	if reply == nil {
		return
	}
	var out [2]byte
	binary.BigEndian.PutUint16(out[:], uint16(len(reply)))
	conn.Write(out[:])  //nolint:errcheck
	conn.Write(reply)   //nolint:errcheck
}

// handle answers one query: forward if the name is allowlisted, else NXDOMAIN.
func (r *essentialsResolver) handle(query []byte) []byte {
	name, ok := essentialsQueryName(query)
	if !ok {
		return refusedReply(query)
	}
	if !domainAllowed(name, r.domains) {
		// Not allowlisted: refuse, so the app cannot connect and stays blackholed.
		return nxdomainReply(query)
	}
	reply, err := r.forward(query)
	if err != nil || reply == nil {
		return servfailReply(query)
	}
	// Route every resolved address into the tunnel so the app's connection to it
	// is carried, then hand the answer back.
	for _, ip := range extractAnswerIPs(reply) {
		r.routeOnce(ip)
	}
	return reply
}

func (r *essentialsResolver) routeOnce(ip string) {
	r.mu.Lock()
	already := r.routed[ip]
	if !already {
		r.routed[ip] = true
	}
	r.mu.Unlock()
	if already || r.addRoute == nil {
		return
	}
	r.addRoute(ip)
}

// forward relays the query to the upstream resolver over UDP (which reaches it
// through the tunnel, since setupRouting routed the upstream IP in).
func (r *essentialsResolver) forward(query []byte) ([]byte, error) {
	c, err := net.DialTimeout("udp", r.upstream, 4*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(4 * time.Second)) //nolint:errcheck
	if _, err := c.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// essentialsQueryName returns the queried hostname in dotted form (lowercased),
// decoded from the wire-format question, or ok=false if it cannot be parsed.
func essentialsQueryName(msg []byte) (string, bool) {
	if len(msg) < 13 {
		return "", false
	}
	var out []byte
	off := 12
	for {
		if off >= len(msg) {
			return "", false
		}
		l := int(msg[off])
		if l == 0 {
			break
		}
		if l&0xC0 != 0 { // compression pointer in a question is invalid
			return "", false
		}
		off++
		if off+l > len(msg) {
			return "", false
		}
		if len(out) > 0 {
			out = append(out, '.')
		}
		for _, b := range msg[off : off+l] {
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			out = append(out, b)
		}
		off += l
	}
	if len(out) == 0 {
		return "", false
	}
	return string(out), true
}

// extractAnswerIPs walks the answer section and returns every A / AAAA address.
func extractAnswerIPs(reply []byte) []string {
	if len(reply) < 12 || reply[3]&0x0F != 0 { // short, or rcode != NOERROR
		return nil
	}
	ancount := int(binary.BigEndian.Uint16(reply[6:8]))
	off := questionEnd(reply)
	if off < 0 {
		return nil
	}
	var ips []string
	for i := 0; i < ancount; i++ {
		nameEnd := skipName(reply, off)
		if nameEnd < 0 || nameEnd+10 > len(reply) {
			return ips
		}
		typ := binary.BigEndian.Uint16(reply[nameEnd : nameEnd+2])
		rdlen := int(binary.BigEndian.Uint16(reply[nameEnd+8 : nameEnd+10]))
		rdata := nameEnd + 10
		if rdata+rdlen > len(reply) {
			return ips
		}
		switch typ {
		case 1: // A
			if rdlen == 4 {
				ips = append(ips, net.IP(reply[rdata:rdata+4]).String())
			}
		case 28: // AAAA
			if rdlen == 16 {
				ips = append(ips, net.IP(reply[rdata:rdata+16]).String())
			}
		}
		off = rdata + rdlen
	}
	return ips
}

// setReplyRcode copies the query header and sets QR=1 plus an rcode, producing a
// minimal response with the original question echoed and no answers.
func setReplyRcode(query []byte, rcode byte) []byte {
	end := questionEnd(query)
	if end < 0 || end > len(query) {
		end = len(query)
	}
	out := make([]byte, end)
	copy(out, query[:end])
	if len(out) >= 12 {
		out[2] |= 0x80                    // QR = response
		out[3] = (out[3] &^ 0x0F) | rcode // rcode
		binary.BigEndian.PutUint16(out[6:8], 0)   // ANCOUNT = 0
		binary.BigEndian.PutUint16(out[8:10], 0)  // NSCOUNT
		binary.BigEndian.PutUint16(out[10:12], 0) // ARCOUNT
	}
	return out
}

func nxdomainReply(query []byte) []byte { return setReplyRcode(query, 3) } // NXDOMAIN
func servfailReply(query []byte) []byte { return setReplyRcode(query, 2) } // SERVFAIL
func refusedReply(query []byte) []byte  { return setReplyRcode(query, 5) } // REFUSED

// readFull reads len(b) bytes or returns an error.
func readFull(conn net.Conn, b []byte) (int, error) {
	got := 0
	for got < len(b) {
		n, err := conn.Read(b[got:])
		if err != nil {
			return got, err
		}
		got += n
	}
	return got, nil
}
