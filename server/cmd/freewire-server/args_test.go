package main

import (
	"strings"
	"testing"
)

// The config path is also the server's identity: config.Load CREATES a missing
// path and generates a fresh WireGuard private key into it. So an argument that
// is not meant to be a path must never reach it.
//
// This is a regression test for a real incident. `freewire-server --help` was
// taken as a config path, which wrote a live keypair to a file named "--help"
// -- and that file was then committed and pushed into the repo's history.
func TestResolveConfigPathNeverTreatsFlagsAsPaths(t *testing.T) {
	flags := []string{
		"-h", "--help", "help",
		"-v", "--version", "--config", "-c", "--", "-",
		"--probe-ports", "--dry-run",
	}
	for _, f := range flags {
		path, _, _, stop := resolveConfigPath([]string{f})
		if !stop {
			t.Errorf("%q: did not stop; would be used as a config path", f)
		}
		if path != "" {
			t.Errorf("%q: returned path %q, want none -- this mints a keypair", f, path)
		}
	}
}

func TestResolveConfigPathHelpExitsZero(t *testing.T) {
	for _, arg := range []string{"-h", "--help", "help"} {
		_, msg, code, stop := resolveConfigPath([]string{arg})
		if !stop || code != 0 {
			t.Errorf("%q: stop=%v code=%d, want stop=true code=0", arg, stop, code)
		}
		if !strings.Contains(msg, "usage:") {
			t.Errorf("%q: message is not the usage text: %q", arg, msg)
		}
		// The surprising behaviour has to be documented where someone typing
		// --help will actually see it.
		if !strings.Contains(msg, "keypair") {
			t.Errorf("%q: usage does not warn that a missing path generates a keypair", arg)
		}
	}
}

func TestResolveConfigPathUnknownOptionExitsTwo(t *testing.T) {
	_, msg, code, stop := resolveConfigPath([]string{"--nope"})
	if !stop || code != 2 {
		t.Fatalf("stop=%v code=%d, want stop=true code=2", stop, code)
	}
	if !strings.Contains(msg, "unknown option") {
		t.Errorf("message = %q, want it to name the unknown option", msg)
	}
}

func TestResolveConfigPathAcceptsPaths(t *testing.T) {
	if p, _, _, stop := resolveConfigPath(nil); stop || p != "freewire-server.json" {
		t.Errorf("no args: got (%q, stop=%v), want the default path", p, stop)
	}
	for _, arg := range []string{"freewire-server.json", "/var/lib/freewire/freewire-server.json", "./cfg.json"} {
		p, _, _, stop := resolveConfigPath([]string{arg})
		if stop || p != arg {
			t.Errorf("%q: got (%q, stop=%v), want it accepted as a path", arg, p, stop)
		}
	}
}

func TestResolveConfigPathRejectsExtraArgs(t *testing.T) {
	_, _, code, stop := resolveConfigPath([]string{"a.json", "b.json"})
	if !stop || code != 2 {
		t.Errorf("stop=%v code=%d, want stop=true code=2", stop, code)
	}
}
