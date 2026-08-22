package tunnel

import "testing"

// wireguard-go names peers by a fragment of their public key, which is the only
// identifier this product has. Its log lines arrive from vendored code, so no
// amount of care in our own log statements would keep them out.
func TestPeerReferencesAreRedacted(t *testing.T) {
	cases := map[string]string{
		"peer(eU6d…Zzho) - Failed to send handshake initiation": "peer(redacted) - Failed to send handshake initiation",
		"Received handshake from peer(AAAA…BBBB) at once":       "Received handshake from peer(redacted) at once",
		"peer(x) and peer(y) both":                              "peer(redacted) and peer(redacted) both",
		"no peer reference here":                                "no peer reference here",
	}
	for in, want := range cases {
		if got := peerRef.ReplaceAllString(in, "peer(redacted)"); got != want {
			t.Errorf("redact(%q) = %q, want %q", in, got, want)
		}
	}
}
