package main

import (
	"testing"
	"time"
)

// DoH costs a full HTTPS round trip per uncached lookup, and the takeover is
// system-wide, so a transport that cannot deliver one quickly stalls every
// application on the machine. That took the developer's machine down three
// times. See DNS-ON-SLOW-TRANSPORTS in DECISIONS.md.
func TestDoHIsSkippedOnTransportsThatCannotCarryIt(t *testing.T) {
	for _, transport := range []string{"dns", "icmp_udp"} {
		if transportCanCarryDoH(transport) {
			t.Errorf("%s: DoH enabled on a transport that resolves in 5-10s; "+
				"this makes the whole machine unusable", transport)
		}
	}
}

func TestDoHIsUsedOnTransportsThatCanCarryIt(t *testing.T) {
	for _, transport := range []string{"wireguard", "tls443", "http_connect"} {
		if !transportCanCarryDoH(transport) {
			t.Errorf("%s: DoH skipped on a fast transport, leaving DNS in "+
				"cleartext for no reason", transport)
		}
	}
}

// An unrecognised transport must get DoH rather than silently skipping it: a
// new fast transport added later should be private by default, and one that
// turns out to be slow will announce itself by stalling in testing.
func TestUnknownTransportGetsEncryptedDNS(t *testing.T) {
	if !transportCanCarryDoH("something_new") {
		t.Error("an unknown transport defaults to cleartext DNS; the safe default is the private one")
	}
}

// The probe budget must scale with the transport for the same reason the
// handshake budget does. A flat value fails at one end or the other: 2s tore
// down a working DNS tunnel that could not answer in time, and 12s left a dead
// fast tunnel undetected for three attempts while the user was unprotected.
func TestProbeBudgetScalesWithTransport(t *testing.T) {
	fast := probeBudgetFor("tls443")
	dns := probeBudgetFor("dns")
	icmp := probeBudgetFor("icmp_udp")

	if !(dns > icmp && icmp > fast) {
		t.Errorf("budgets do not scale with transport speed: fast=%v icmp=%v dns=%v", fast, icmp, dns)
	}
	if fast > 5_000_000_000 {
		t.Errorf("fast-path budget %v is long enough to leave a dead tunnel unnoticed", fast)
	}
	// Verification must fit inside the client's 30s ready timeout with room for
	// the fallback chain, or the tunnel loses to its own deadline. The chain is
	// budgeted at 11s, so verification gets well under the remaining 19s.
	for _, transport := range []string{"dns", "icmp_udp", "tls443"} {
		total := time.Duration(probeAttempts(transport)) * probeBudgetFor(transport)
		if total > 15*time.Second {
			t.Errorf("%s: verification can take %v, leaving too little of the 30s "+
				"ready timeout for the fallback chain", transport, total)
		}
	}
}
