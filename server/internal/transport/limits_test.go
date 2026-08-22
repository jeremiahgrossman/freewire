package transport

import (
	"bufio"
	"strings"
	"testing"
)

// bufio.Reader.ReadString accumulates until it finds its delimiter, so a peer
// that never sends a newline sets the server's memory budget. Nothing is
// authenticated at this point in the CONNECT exchange.
func TestReadLineLimitedRefusesAnEndlessLine(t *testing.T) {
	br := bufio.NewReader(strings.NewReader(strings.Repeat("A", 1<<20)))
	if _, err := readLineLimited(br, maxConnectLine); err == nil {
		t.Error("a line with no newline was accepted without bound")
	}
}

func TestReadLineLimitedReturnsAWholeLine(t *testing.T) {
	br := bufio.NewReader(strings.NewReader("CONNECT example.com:443 HTTP/1.1\r\nHost: x\r\n\r\n"))
	line, err := readLineLimited(br, maxConnectLine)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if line != "CONNECT example.com:443 HTTP/1.1\r" {
		t.Errorf("line = %q", line)
	}
	// The reader must still hold what followed, because the client commonly
	// pipelines its TLS handshake behind the headers.
	next, err := readLineLimited(br, maxConnectLine)
	if err != nil || next != "Host: x\r" {
		t.Errorf("second line = %q, err = %v", next, err)
	}
}

func TestReadLineLimitedAcceptsALineAtTheLimit(t *testing.T) {
	exact := strings.Repeat("A", maxConnectLine) + "\n"
	br := bufio.NewReader(strings.NewReader(exact))
	line, err := readLineLimited(br, maxConnectLine)
	if err != nil {
		t.Fatalf("a line exactly at the limit was refused: %v", err)
	}
	if len(line) != maxConnectLine {
		t.Errorf("line is %d bytes, want %d", len(line), maxConnectLine)
	}
}

// The frame ceiling was introduced to stop a connection committing 64 KB before
// the peer had proven anything, and was applied to only one direction.
func TestBridgeBuffersAreBounded(t *testing.T) {
	if tlsMaxFrame > 8192 {
		t.Errorf("tlsMaxFrame is %d; the point of the bound is that it is small", tlsMaxFrame)
	}
	// A WireGuard datagram must still fit, or reads truncate silently.
	if wgReadBuffer < 2048 {
		t.Errorf("wgReadBuffer is %d, too small for a WireGuard datagram", wgReadBuffer)
	}
	if tlsMaxFrame < 2048 {
		t.Errorf("tlsMaxFrame is %d, too small for a WireGuard datagram", tlsMaxFrame)
	}
}

// Every ceiling here bounds something an unauthenticated peer can allocate, so
// each must actually be set, and set below what exhausts the process.
func TestUnauthenticatedCeilingsAreSet(t *testing.T) {
	for name, v := range map[string]int{
		"maxTLSConnections":          maxTLSConnections,
		"maxPendingDNSSessions":      maxPendingDNSSessions,
		"maxPendingICMPSessions":     maxPendingICMPSessions,
		"maxEstablishedDNSSessions":  maxEstablishedDNSSessions,
		"maxEstablishedICMPSessions": maxEstablishedICMPSessions,
		"maxConnectHeaders":          maxConnectHeaders,
	} {
		if v <= 0 {
			t.Errorf("%s is %d; the ceiling is not in effect", name, v)
		}
		if v > 1024 {
			t.Errorf("%s is %d, high enough that the ceiling protects nothing", name, v)
		}
	}
	// A tunnel holds a socket per session on two transports plus one per TLS
	// connection. The total has to stay clear of a default 1024 descriptor
	// limit with room for the listeners and the API.
	total := maxTLSConnections + maxEstablishedDNSSessions + maxEstablishedICMPSessions
	if total > 768 {
		t.Errorf("the transports can hold %d sockets at once, too close to a 1024 fd limit", total)
	}
}
