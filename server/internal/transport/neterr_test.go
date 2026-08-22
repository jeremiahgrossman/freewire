package transport

import (
	"errors"
	"net"
	"strings"
	"testing"
)

// Architecture rule 1: a client address must never reach a log. net.OpError
// formats itself as "read tcp <local>-><remote>: <cause>", so logging one with
// zap.Error put the client's IP in the line -- through a field nobody reads
// twice, which is why it survived two audits.

func TestNetErrCauseStripsAddresses(t *testing.T) {
	client := &net.TCPAddr{IP: net.ParseIP("203.0.113.45"), Port: 54321}
	local := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 443}

	err := &net.OpError{
		Op:     "read",
		Net:    "tcp",
		Source: local,
		Addr:   client,
		Err:    errors.New("connection reset by peer"),
	}

	// The raw error is exactly what must not be logged.
	if !strings.Contains(err.Error(), "203.0.113.45") {
		t.Fatal("test is not exercising the case: the raw error has no address in it")
	}

	got := netErrCause(err)
	for _, forbidden := range []string{"203.0.113.45", "54321", "10.0.0.1"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("netErrCause leaked %q: %q", forbidden, got)
		}
	}
	if !strings.Contains(got, "connection reset by peer") {
		t.Errorf("lost the useful part of the error: %q", got)
	}
	if !strings.Contains(got, "read") {
		t.Errorf("lost the operation: %q", got)
	}
}

func TestNetErrCauseStripsNestedAddresses(t *testing.T) {
	inner := &net.OpError{
		Op:   "dial",
		Addr: &net.TCPAddr{IP: net.ParseIP("198.51.100.7"), Port: 9},
		Err:  errors.New("refused"),
	}
	outer := &net.OpError{
		Op:   "write",
		Addr: &net.TCPAddr{IP: net.ParseIP("203.0.113.99"), Port: 1},
		Err:  inner,
	}
	got := netErrCause(outer)
	for _, forbidden := range []string{"198.51.100.7", "203.0.113.99"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("nested address leaked %q: %q", forbidden, got)
		}
	}
}

func TestNetErrCauseStripsDNSAndAddrErrors(t *testing.T) {
	dns := &net.DNSError{Err: "no such host", Name: "secret.example.com"}
	if got := netErrCause(dns); strings.Contains(got, "secret.example.com") {
		t.Errorf("DNSError leaked the name: %q", got)
	}
	addr := &net.AddrError{Err: "invalid port", Addr: "203.0.113.5:70000"}
	if got := netErrCause(addr); strings.Contains(got, "203.0.113.5") {
		t.Errorf("AddrError leaked the address: %q", got)
	}
}

func TestNetErrCausePassesPlainErrors(t *testing.T) {
	if got := netErrCause(errors.New("plain failure")); got != "plain failure" {
		t.Errorf("plain error became %q", got)
	}
	if got := netErrCause(nil); got != "" {
		t.Errorf("nil became %q", got)
	}
}
