package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// tcbitSweep measures the largest answer a public recursor will relay from our
// authoritative server when we force a TCP fallback with the TC bit.
//
//	freewire-tunnel --tcbit [--zone t.pinghop.net] [--resolver 1.1.1.1:53]
//
// Rootless, non-routed, changes nothing. See server/internal/transport/tcbit.go
// for the question and what was already settled without a server.
//
// Method, and why each part is necessary:
//
//   - Each query carries a random nonce label. A recursor that answered from
//     cache would report its cache, not its relay limit.
//   - The query goes to the recursor over TCP. Our server truncates over UDP, so
//     the recursor fetches over TCP; but the recursor would then truncate right
//     back to us over UDP, and we would measure the recursor-to-client UDP
//     ceiling rather than the recursor-to-authoritative one. Asking over TCP
//     removes that second ceiling and isolates the question.
//   - The answer is checked for the payload actually arriving, not merely for a
//     NOERROR: a recursor that relays the header and drops records would
//     otherwise read as success.
func tcbitSweep(args []string) int {
	zone := defaultDNSTunnelDomain
	resolvers := []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--zone":
			if i+1 < len(args) {
				zone, i = args[i+1], i+1
			}
		case "--resolver":
			if i+1 < len(args) {
				resolvers, i = []string{args[i+1]}, i+1
			}
		default:
			fmt.Fprintf(os.Stderr, "tcbit: unknown argument %q\n", args[i])
			return 2
		}
	}

	sizes := []int{512, 1232, 2048, 4096, 5209, 8192, 12288, 16384, 24576, 32768, 49152, 60000}

	fmt.Fprintf(os.Stderr, "tcbit: largest answer each recursor will relay from %s over a TC-forced TCP fetch\n", zone)
	fmt.Fprintln(os.Stderr, "  (each query is nonce-labelled so no answer comes from cache; asked over TCP so the")
	fmt.Fprintln(os.Stderr, "   recursor->client leg is not a second ceiling)")
	fmt.Fprintf(os.Stderr, "\n  %-10s", "REQUESTED")
	for _, r := range resolvers {
		fmt.Fprintf(os.Stderr, " %-18s", r)
	}
	fmt.Fprintln(os.Stderr)

	best := map[string]int{}
	for _, size := range sizes {
		fmt.Fprintf(os.Stderr, "  %-10d", size)
		for _, r := range resolvers {
			got, err := tcbitAsk(r, zone, size)
			switch {
			case err != nil:
				fmt.Fprintf(os.Stderr, " %-18s", "-- "+trimErr(err))
			case got < size:
				fmt.Fprintf(os.Stderr, " %-18s", fmt.Sprintf("short (%d B)", got))
			default:
				best[r] = size
				fmt.Fprintf(os.Stderr, " %-18s", fmt.Sprintf("OK (%d B)", got))
			}
		}
		fmt.Fprintln(os.Stderr)
	}

	fmt.Fprintln(os.Stderr)
	// The verdict is the decision this experiment exists to make. Our carrier's
	// per-query downstream today is ~4096 bytes on the wire (EDNS0 4096), so the
	// gain is the measured ceiling over that -- and a carrier is only worth
	// building at a large multiple, not at 1.3x.
	const current = 4096
	for _, r := range resolvers {
		b := best[r]
		if b == 0 {
			fmt.Fprintf(os.Stderr, "tcbit: %s relayed nothing — is the zone delegated and the server deployed?\n", r)
			continue
		}
		fmt.Fprintf(os.Stderr, "tcbit: %s relayed up to %d bytes = %.1fx our current ~%d-byte per-query budget\n",
			r, b, float64(b)/current, current)
	}
	return 0
}

// tcbitAsk asks one recursor for a payload of `size` bytes and returns how many
// payload bytes actually came back.
func tcbitAsk(resolver, zone string, size int) (int, error) {
	var nonce [6]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return 0, err
	}
	name := hex.EncodeToString(nonce[:]) + ".s" + strconv.Itoa(size) + ".tcbit." + strings.TrimSuffix(zone, ".")

	query, id := tcbitBuildTXTQuery(name)
	c, err := net.DialTimeout("tcp", resolver, 8*time.Second)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second)) //nolint:errcheck

	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(query)))
	copy(framed[2:], query)
	if _, err := c.Write(framed); err != nil {
		return 0, err
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
		return 0, err
	}
	reply := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(c, reply); err != nil {
		return 0, err
	}
	if len(reply) < 12 || binary.BigEndian.Uint16(reply[:2]) != id {
		return 0, fmt.Errorf("reply id mismatch")
	}
	if rcode := reply[3] & 0x0F; rcode != 0 {
		return 0, fmt.Errorf("rcode %d", rcode)
	}
	// Count the payload that actually arrived, not the message size: a recursor
	// relaying the header while dropping records must not read as success.
	return tcbitCountTXTPayload(reply), nil
}

// tcbitCountTXTPayload sums the TXT character-string bytes in the answer
// section. It walks the message rather than trusting ANCOUNT, so a truncated or
// malformed relay counts only what really arrived.
func tcbitCountTXTPayload(msg []byte) int {
	off := 12
	// Skip the question section.
	for off < len(msg) && msg[off] != 0 {
		if msg[off]&0xC0 != 0 {
			off++
			break
		}
		off += int(msg[off]) + 1
	}
	off += 5 // root label + QTYPE + QCLASS
	total := 0
	for off+10 <= len(msg) {
		// Owner name: a pointer (2 bytes) or a sequence of labels.
		if msg[off]&0xC0 != 0 {
			off += 2
		} else {
			for off < len(msg) && msg[off] != 0 {
				off += int(msg[off]) + 1
			}
			off++
		}
		if off+10 > len(msg) {
			break
		}
		rrType := binary.BigEndian.Uint16(msg[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		off += 10
		if off+rdlen > len(msg) {
			break
		}
		if rrType == 16 { // TXT
			for i := off; i < off+rdlen; {
				l := int(msg[i])
				total += l
				i += l + 1
			}
		}
		off += rdlen
	}
	return total
}

func tcbitBuildTXTQuery(name string) ([]byte, uint16) {
	var idb [2]byte
	rand.Read(idb[:]) //nolint:errcheck
	id := binary.BigEndian.Uint16(idb[:])

	msg := make([]byte, 12, 64+len(name))
	binary.BigEndian.PutUint16(msg[0:2], id)
	msg[2] = 0x01 // recursion desired
	binary.BigEndian.PutUint16(msg[4:6], 1)
	for _, l := range strings.Split(name, ".") {
		if l == "" {
			continue
		}
		msg = append(msg, byte(len(l)))
		msg = append(msg, l...)
	}
	msg = append(msg, 0)
	msg = append(msg, 0x00, 0x10) // QTYPE = TXT
	msg = append(msg, 0x00, 0x01) // QCLASS = IN
	return msg, id
}
