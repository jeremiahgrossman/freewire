package transport

import (
	"bytes"
	"crypto/sha256"
	"io"
	"testing"

	"golang.org/x/crypto/hkdf"
)

// deriveThree mirrors the handshake key schedule: three 32-byte reads off one
// HKDF stream, in the order sessionKey, keyC2S, keyS2C.
func deriveThree(t *testing.T, shared, salt, info []byte) (sessionKey, keyC2S, keyS2C [32]byte) {
	t.Helper()
	hk := hkdf.New(sha256.New, shared, salt, info)
	for _, k := range []*[32]byte{&sessionKey, &keyC2S, &keyS2C} {
		if _, err := io.ReadFull(hk, k[:]); err != nil {
			t.Fatalf("hkdf read: %v", err)
		}
	}
	return
}

// Regression: both peers number packets from zero, so a single shared key put
// the same (key, nonce) pair on the first packet in each direction. That is a
// keystream reuse and Poly1305 forgery break, not a theoretical concern.
func TestDirectionalKeysDiffer(t *testing.T) {
	for _, info := range []string{"freewire-dns-tunnel-v1", "freewire-icmp-tunnel-v1"} {
		shared := bytes.Repeat([]byte{0xAB}, 32)
		salt := []byte{0x01, 0x02}
		sk, c2s, s2c := deriveThree(t, shared, salt, []byte(info))

		if c2s == s2c {
			t.Errorf("%s: client→server and server→client keys are identical", info)
		}
		if sk == c2s || sk == s2c {
			t.Errorf("%s: a directional key collides with the confirm-MAC key", info)
		}
	}
}

func TestKeyScheduleIsDeterministic(t *testing.T) {
	shared := bytes.Repeat([]byte{0x11}, 32)
	salt := []byte{0xAA, 0xBB}
	info := []byte("freewire-dns-tunnel-v1")

	sk1, c2s1, s2c1 := deriveThree(t, shared, salt, info)
	sk2, c2s2, s2c2 := deriveThree(t, shared, salt, info)

	if sk1 != sk2 || c2s1 != c2s2 || s2c1 != s2c2 {
		t.Error("same inputs produced different keys; client and server would not agree")
	}
}

func TestDistinctSessionsGetDistinctKeys(t *testing.T) {
	shared := bytes.Repeat([]byte{0x22}, 32)
	info := []byte("freewire-icmp-tunnel-v1")

	_, a, _ := deriveThree(t, shared, []byte{0x00, 0x01}, info)
	_, b, _ := deriveThree(t, shared, []byte{0x00, 0x02}, info)

	if a == b {
		t.Error("different session tokens produced the same key; tokens are not salting the schedule")
	}
}

func TestTunnelsDoNotShareKeys(t *testing.T) {
	shared := bytes.Repeat([]byte{0x33}, 32)
	salt := []byte{0x09, 0x09}

	_, dnsC2S, _ := deriveThree(t, shared, salt, []byte("freewire-dns-tunnel-v1"))
	_, icmpC2S, _ := deriveThree(t, shared, salt, []byte("freewire-icmp-tunnel-v1"))

	if dnsC2S == icmpC2S {
		t.Error("DNS and ICMP tunnels derived the same key from one shared secret")
	}
}
