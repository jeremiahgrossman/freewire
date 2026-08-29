package tunnel

import (
	"os"
	"path/filepath"
	"testing"
)

// A restart must not orphan a client relying on a cached registration -- that
// is exactly the captive-portal fallback path, where the client cannot
// re-register because the API is blocked.
func TestPeersFileSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peers.json")

	want := []persistedPeer{
		{PeerToken: "tok-a", PublicKey: "keyA", TunnelIP: "10.0.0.2", TunnelIPv6: "fd00::2"},
		{PeerToken: "tok-b", PublicKey: "keyB", TunnelIP: "10.0.0.3", TunnelIPv6: "fd00::3"},
	}
	if err := writePeersFile(path, want); err != nil {
		t.Fatalf("write: %v", err)
	}

	got := loadPeersFile(path)
	if len(got) != len(want) {
		t.Fatalf("loaded %d peers, want %d", len(got), len(want))
	}
	byToken := make(map[string]persistedPeer, len(got))
	for _, p := range got {
		byToken[p.PeerToken] = p
	}
	for _, w := range want {
		g, ok := byToken[w.PeerToken]
		if !ok {
			t.Errorf("token %q missing after reload", w.PeerToken)
			continue
		}
		if g != w {
			t.Errorf("token %q reloaded as %+v, want %+v", w.PeerToken, g, w)
		}
	}
}

func TestLoadPeersFileMissingIsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.json")
	if got := loadPeersFile(path); len(got) != 0 {
		t.Errorf("missing file loaded %d peers, want 0", len(got))
	}
}

// A corrupt file must not take the server down: every legitimate entry can
// simply re-register once the network allows it.
func TestLoadPeersFileCorruptIsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peers.json")
	if err := writePeersFile(path, nil); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Corrupt it after a valid empty write.
	if err := os.WriteFile(path, []byte("{not valid json"), 0o600); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	if got := loadPeersFile(path); len(got) != 0 {
		t.Errorf("corrupt file loaded %d peers, want 0", len(got))
	}
}

// An empty peersPath (as used by tests that build a Manager with no state
// directory) must disable persistence rather than erroring.
func TestWritePeersFileEmptyPathIsNoop(t *testing.T) {
	if err := writePeersFile("", []persistedPeer{{PeerToken: "x"}}); err != nil {
		t.Errorf("empty path returned an error: %v", err)
	}
}

// A rewrite must leave a complete, reloadable file even if it is called many
// times -- the temp-file-and-rename pattern is what makes a crash mid-write
// lose nothing rather than truncating the previous good file.
func TestWritePeersFileOverwritesCleanly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peers.json")
	if err := writePeersFile(path, []persistedPeer{{PeerToken: "a", PublicKey: "1", TunnelIP: "10.0.0.2"}}); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := writePeersFile(path, []persistedPeer{{PeerToken: "b", PublicKey: "2", TunnelIP: "10.0.0.3"}}); err != nil {
		t.Fatalf("second write: %v", err)
	}
	got := loadPeersFile(path)
	if len(got) != 1 || got[0].PeerToken != "b" {
		t.Errorf("after overwrite, loaded %+v, want exactly [{PeerToken: b, ...}]", got)
	}
}
