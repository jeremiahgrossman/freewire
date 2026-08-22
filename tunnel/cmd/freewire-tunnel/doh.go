package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// DNS-over-HTTPS forwarder.
//
// Taking over the system resolver stopped queries leaking to the local network,
// which is the leak that matters on a captive portal. It did not stop them
// being readable: they went to 1.1.1.1 as plain DNS on port 53, so they crossed
// the tunnel in the clear and left the VPN server in the clear. Captured on the
// server's own uplink, every domain was legible:
//
//	172.31.17.212.20590 > 1.1.1.1.53: A? browser-intake-us5-datadoghq.com
//
// That moved the observer from the portal operator to whoever runs the VPN,
// which for this product is the one party that must not be able to see it. The
// preferences sheet says "What you browse — We see only encrypted data", and
// DNS was the exception.
//
// So the system resolver now points at a forwarder on loopback, which relays
// each query over HTTPS. The query still crosses the tunnel, but as TLS to
// 1.1.1.1:443, which the server can no more read than any other TLS it carries.
//
// The forwarder does not parse queries to answer them: it relays the wire
// format unchanged, which is exactly what RFC 8484 carries. It parses only
// enough to decide whether a reply fits in the client's UDP budget.
type dohForwarder struct {
	udp    *net.UDPConn
	tcp    net.Listener
	client *http.Client
	wg     sync.WaitGroup
	closed chan struct{}
	once   sync.Once
	cache  *dnsCache
}

// dnsCache holds answers for as long as their records say they are valid.
//
// Keyed on the question, not the whole query: the transaction id and any EDNS0
// padding differ per request, so keying on the raw bytes would never hit. The
// cached reply carries the requester's id stamped back in.
type dnsCache struct {
	mu      sync.Mutex
	entries map[string]dnsCacheEntry
}

type dnsCacheEntry struct {
	reply   []byte
	expires time.Time
}

// Bounded so a flood of distinct names cannot grow it without limit, and
// dropped wholesale when full rather than evicted one by one -- this is a
// cache, and the cost of a miss is one upstream query.
const dnsCacheMax = 2048

func newDNSCache() *dnsCache {
	return &dnsCache{entries: make(map[string]dnsCacheEntry)}
}

func (c *dnsCache) get(query []byte) ([]byte, bool) {
	key, ok := questionKey(query)
	if !ok {
		return nil, false
	}
	c.mu.Lock()
	entry, found := c.entries[key]
	c.mu.Unlock()
	if !found || time.Now().After(entry.expires) {
		return nil, false
	}
	reply := make([]byte, len(entry.reply))
	copy(reply, entry.reply)
	if len(reply) >= 2 && len(query) >= 2 {
		// Stamp the caller's transaction id in, or the stub discards the reply
		// as an answer to someone else's question.
		copy(reply[:2], query[:2])
	}
	return reply, true
}

func (c *dnsCache) put(query, reply []byte) {
	key, ok := questionKey(query)
	if !ok {
		return
	}
	ttl := minTTL(reply)
	if ttl <= 0 {
		return
	}
	stored := make([]byte, len(reply))
	copy(stored, reply)

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= dnsCacheMax {
		c.entries = make(map[string]dnsCacheEntry)
	}
	c.entries[key] = dnsCacheEntry{reply: stored, expires: time.Now().Add(ttl)}
}

// questionKey identifies a query by its question section alone.
func questionKey(msg []byte) (string, bool) {
	end := questionEnd(msg)
	if end < 0 || end > len(msg) || end <= 12 {
		return "", false
	}
	return string(msg[12:end]), true
}

// minTTL returns the shortest TTL among the answer records, which is how long
// the whole reply may be reused. Capped so a record claiming days does not pin
// an answer across a network change.
func minTTL(reply []byte) time.Duration {
	const maxCacheTTL = 5 * time.Minute
	if len(reply) < 12 {
		return 0
	}
	// Only cache successful answers. Caching a failure would make a transient
	// upstream problem persist past its cause.
	if reply[3]&0x0F != 0 {
		return 0
	}
	ancount := int(binary.BigEndian.Uint16(reply[6:8]))
	if ancount == 0 {
		return 0
	}
	off := questionEnd(reply)
	if off < 0 {
		return 0
	}
	shortest := -1
	for i := 0; i < ancount; i++ {
		nameEnd := skipName(reply, off)
		if nameEnd < 0 || nameEnd+10 > len(reply) {
			return 0
		}
		ttl := int(binary.BigEndian.Uint32(reply[nameEnd+4 : nameEnd+8]))
		rdlen := int(binary.BigEndian.Uint16(reply[nameEnd+8 : nameEnd+10]))
		if shortest < 0 || ttl < shortest {
			shortest = ttl
		}
		off = nameEnd + 10 + rdlen
	}
	if shortest <= 0 {
		return 0
	}
	d := time.Duration(shortest) * time.Second
	if d > maxCacheTTL {
		d = maxCacheTTL
	}
	return d
}

// Resolver addresses, by IP rather than by name.
//
// A resolver named by hostname cannot be reached before there is a resolver, so
// naming one would be a bootstrap loop. Cloudflare's certificate carries these
// addresses as IP SANs, so connecting to the bare IP still gets full
// certificate verification rather than a skipped check.
var dohEndpoints = []string{"https://1.1.1.1/dns-query", "https://1.0.0.1/dns-query"}

const (
	dohListenAddr = "127.0.0.1:53"
	// Generous, because this has to work on the slow fallback transports too.
	// A DoH round trip over the DNS tunnel measured 5-10 seconds; timing out
	// below that turned every lookup into SERVFAIL on exactly the networks the
	// product exists for.
	dohTimeout = 15 * time.Second
	// A DNS message is at most 64 KB, and anything near it is not a real reply
	// to a stub resolver's question.
	dohMaxMessage = 65535
)

// startDoHForwarder binds loopback:53 and relays queries over HTTPS.
func startDoHForwarder() (*dohForwarder, error) {
	udpAddr, err := net.ResolveUDPAddr("udp4", dohListenAddr)
	if err != nil {
		return nil, err
	}
	uc, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("bind %s: %w", dohListenAddr, err)
	}
	// TCP as well: a stub resolver that receives a truncated reply retries over
	// TCP, and without a listener that retry fails rather than falling back.
	tl, err := net.Listen("tcp4", dohListenAddr)
	if err != nil {
		uc.Close()
		return nil, fmt.Errorf("bind tcp %s: %w", dohListenAddr, err)
	}

	f := &dohForwarder{
		udp:    uc,
		tcp:    tl,
		closed: make(chan struct{}),
		cache:  newDNSCache(),
		client: &http.Client{
			Timeout: dohTimeout,
			Transport: &http.Transport{
				// Verified against the endpoint's IP SANs. Nothing here skips
				// verification: the whole point is that the carrier of this
				// traffic -- including our own server -- cannot read it.
				TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
				MaxIdleConnsPerHost: 4,
				IdleConnTimeout:     90 * time.Second,
				ForceAttemptHTTP2:   true,
			},
		},
	}

	f.wg.Add(2)
	go func() { defer f.wg.Done(); f.serveUDP() }()
	go func() { defer f.wg.Done(); f.serveTCP() }()
	return f, nil
}

func (f *dohForwarder) Close() {
	f.once.Do(func() {
		close(f.closed)
		f.udp.Close()
		f.tcp.Close()
	})
	f.wg.Wait()
}

func (f *dohForwarder) serveUDP() {
	buf := make([]byte, dohMaxMessage)
	for {
		n, from, err := f.udp.ReadFromUDP(buf)
		if err != nil {
			return
		}
		query := make([]byte, n)
		copy(query, buf[:n])
		go f.answerUDP(query, from)
	}
}

func (f *dohForwarder) answerUDP(query []byte, to *net.UDPAddr) {
	reply, err := f.resolve(query)
	if err != nil {
		// SERVFAIL rather than silence: a stub resolver that gets no answer
		// waits out its own timeout on every lookup, which reads to the user as
		// the whole network being broken rather than one resolver failing.
		if failure := servfail(query); failure != nil {
			f.udp.WriteToUDP(failure, to) //nolint:errcheck
		}
		return
	}
	// A reply larger than the client's budget is returned truncated with TC
	// set, which is the signal to retry over TCP. Sending it oversize instead
	// would be dropped or mis-parsed by the stub.
	if budget := udpBudget(query); len(reply) > budget {
		reply = truncate(query)
	}
	f.udp.WriteToUDP(reply, to) //nolint:errcheck
}

func (f *dohForwarder) serveTCP() {
	for {
		conn, err := f.tcp.Accept()
		if err != nil {
			return
		}
		go f.answerTCP(conn)
	}
}

// answerTCP speaks the two-byte length prefix DNS uses over TCP.
func (f *dohForwarder) answerTCP(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(dohTimeout)) //nolint:errcheck

	var lb [2]byte
	if _, err := io.ReadFull(conn, lb[:]); err != nil {
		return
	}
	n := binary.BigEndian.Uint16(lb[:])
	if n == 0 {
		return
	}
	query := make([]byte, n)
	if _, err := io.ReadFull(conn, query); err != nil {
		return
	}

	reply, err := f.resolve(query)
	if err != nil {
		reply = servfail(query)
		if reply == nil {
			return
		}
	}
	out := make([]byte, 2+len(reply))
	binary.BigEndian.PutUint16(out[:2], uint16(len(reply)))
	copy(out[2:], reply)
	conn.Write(out) //nolint:errcheck
}

// resolve relays one query, trying each endpoint in turn.
//
// Answers are cached. That is ordinary resolver behaviour, and it is what makes
// this usable on the slow transports: a DoH round trip over the DNS tunnel
// costs seconds, and real browsing asks for the same handful of names
// repeatedly. Without a cache every image on a page pays the full cost again.
func (f *dohForwarder) resolve(query []byte) ([]byte, error) {
	if reply, ok := f.cache.get(query); ok {
		return reply, nil
	}
	var lastErr error
	for _, endpoint := range dohEndpoints {
		reply, err := f.post(endpoint, query)
		if err == nil {
			f.cache.put(query, reply)
			return reply, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (f *dohForwarder) post(endpoint string, query []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dohTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh: %s returned HTTP %d", endpoint, resp.StatusCode)
	}
	// Bounded: the body is attacker-influenced only via the resolver, but an
	// unbounded read is an unbounded allocation regardless of who is on the
	// other end.
	return io.ReadAll(io.LimitReader(resp.Body, dohMaxMessage))
}

// udpBudget reports how large a UDP reply the client said it could accept.
//
// EDNS0 advertises it in the CLASS field of an OPT record in the additional
// section. Without one the limit is the classic 512 bytes.
func udpBudget(query []byte) int {
	const noEDNS = 512
	if len(query) < 12 {
		return noEDNS
	}
	arcount := binary.BigEndian.Uint16(query[10:12])
	if arcount == 0 {
		return noEDNS
	}
	off := questionEnd(query)
	if off < 0 {
		return noEDNS
	}
	// Walk the additional section looking for OPT (type 41). Answer and
	// authority are empty in a query, so the additional section starts here.
	for off+11 <= len(query) {
		nameEnd := skipName(query, off)
		if nameEnd < 0 || nameEnd+10 > len(query) {
			return noEDNS
		}
		rrType := binary.BigEndian.Uint16(query[nameEnd : nameEnd+2])
		class := binary.BigEndian.Uint16(query[nameEnd+2 : nameEnd+4])
		rdlen := int(binary.BigEndian.Uint16(query[nameEnd+8 : nameEnd+10]))
		if rrType == 41 { // OPT
			if class < noEDNS {
				return noEDNS
			}
			return int(class)
		}
		off = nameEnd + 10 + rdlen
	}
	return noEDNS
}

// truncate returns the query's header and question with TC set and no records,
// which tells the stub resolver to retry over TCP.
func truncate(query []byte) []byte {
	end := questionEnd(query)
	if end < 0 || end > len(query) {
		end = min(12, len(query))
	}
	out := make([]byte, end)
	copy(out, query[:end])
	if len(out) >= 12 {
		out[2] |= 0x80                            // QR: this is a response
		out[2] |= 0x02                            // TC: truncated
		binary.BigEndian.PutUint16(out[6:8], 0)   // ANCOUNT
		binary.BigEndian.PutUint16(out[8:10], 0)  // NSCOUNT
		binary.BigEndian.PutUint16(out[10:12], 0) // ARCOUNT
	}
	return out
}

// servfail turns a query into a SERVFAIL response to the same question.
func servfail(query []byte) []byte {
	out := truncate(query)
	if len(out) < 12 {
		return nil
	}
	out[2] &^= 0x02 // not truncated; it failed
	out[3] = (out[3] &^ 0x0F) | 0x02
	return out
}

// questionEnd returns the offset just past the question section.
func questionEnd(msg []byte) int {
	if len(msg) < 12 || binary.BigEndian.Uint16(msg[4:6]) == 0 {
		return -1
	}
	off := skipName(msg, 12)
	if off < 0 || off+4 > len(msg) {
		return -1
	}
	return off + 4 // QTYPE and QCLASS
}

// skipName walks a DNS name and returns the offset just past it.
func skipName(msg []byte, off int) int {
	for off < len(msg) {
		l := int(msg[off])
		switch {
		case l == 0:
			return off + 1
		case l&0xC0 == 0xC0: // compression pointer, two bytes, ends the name
			if off+2 > len(msg) {
				return -1
			}
			return off + 2
		case l > 63:
			return -1
		default:
			off += l + 1
		}
	}
	return -1
}

// dohNotice reports the forwarder's state to stderr once at startup.
func dohNotice(err error) {
	if err == nil {
		fmt.Fprintf(os.Stderr, "freewire-tunnel: DNS-over-HTTPS forwarder on %s\n", dohListenAddr)
		return
	}
	// Not fatal, and loud. Without the forwarder the resolver stays where it
	// was, which means queries go to the local network -- the leak this
	// replaced -- so the user has to be able to find out.
	fmt.Fprintf(os.Stderr,
		"freewire-tunnel: WARNING: DNS-over-HTTPS unavailable: %v\n"+
			"freewire-tunnel: DNS is NOT being taken over; lookups use the network's resolver\n", err)
}
