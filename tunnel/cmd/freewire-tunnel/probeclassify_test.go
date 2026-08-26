package main

import (
	"errors"
	"testing"
)

// The block classification drives the desync decision (a SYN-RST is not
// desyncable; a post-handshake reset is), so the mapping from a carrier's error
// to its class is load-bearing and worth pinning against the exact strings the
// Go net stack produces.
func TestClassifyBlock(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		// "connection refused" is what Dial returns when a RST answers the SYN --
		// the café's behavior, and NOT desyncable.
		{"dial refused", errors.New("tls443: dial: dial tcp 1.2.3.4:443: connect: connection refused"), "syn-rst"},
		// A reset AFTER the handshake is content/SNI gating -- desync's target.
		{"mid-stream reset", errors.New("wss443: read: connection reset by peer"), "content-rst"},
		// Silent drop.
		{"io timeout", errors.New("tls443: dial: i/o timeout"), "timeout"},
		{"deadline exceeded", errors.New("context deadline exceeded"), "timeout"},
		{"no route", errors.New("dial udp [2600::1]:443: connect: no route to host"), "timeout"},
		// A cert/interop failure is neither a portal reject nor a drop.
		{"cert failure", errors.New("utls: handshake: tls: failed to verify certificate"), ""},
		{"nil", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyBlock(tc.err); got != tc.want {
				t.Fatalf("classifyBlock(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

// The tag shown per line must match the class, since the operator reads it in
// the field to decide what (if anything) is left to try.
func TestBlockTag(t *testing.T) {
	cases := map[string]string{
		"connection refused":           "[SYN-RST] ",
		"connection reset by peer":     "[reset] ",
		"i/o timeout":                  "[timeout] ",
		"failed to verify certificate": "",
	}
	for msg, want := range cases {
		if got := blockTag(errors.New(msg)); got != want {
			t.Errorf("blockTag(%q) = %q, want %q", msg, got, want)
		}
	}
}

// A SYN-RST and a content reset must NOT collapse to the same class -- that
// collapse is exactly the bug the café result exposed (a destination SYN-RST
// mislabeled as "possibly desyncable").
func TestSynRstAndContentRstAreDistinct(t *testing.T) {
	syn := classifyBlock(errors.New("connect: connection refused"))
	content := classifyBlock(errors.New("read: connection reset by peer"))
	if syn == content {
		t.Fatalf("SYN-RST and content-RST both classified as %q; they must differ", syn)
	}
	if syn != "syn-rst" || content != "content-rst" {
		t.Fatalf("got syn=%q content=%q, want syn-rst / content-rst", syn, content)
	}
}
