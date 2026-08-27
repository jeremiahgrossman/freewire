package transport

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Architecture rule 1 (CLAUDE.md, non-negotiable): a client IP address is never
// written to disk, DB, log, or error -- anywhere on the server. The data must not
// exist, so it cannot be compelled. CLAUDE.md's "Common Mistakes" asks for a lint
// that fails on RemoteAddr in server log statements; this is that lint, one step
// stronger. The server has ZERO legitimate uses of net.Conn.RemoteAddr() today
// (the client tunnel binary uses it for carrier pinning, but that is a different
// module and not covered here), so this fails on ANY appearance in server source.
//
// If a real need for RemoteAddr() ever arises, this test forces the author to
// confront rule 1 at that moment -- strip the address before it reaches any sink,
// then add a narrow, commented exemption here -- rather than let the call slip in
// through "a field nobody reads twice," which is exactly how the netErrCause leak
// survived two audits.
func TestServerSourceNeverUsesRemoteAddr(t *testing.T) {
	// internal/ root, from this package dir (internal/transport).
	internalRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}

	const forbidden = "RemoteAddr("
	var offenders []string
	scanned := 0
	err = filepath.WalkDir(internalRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		// Skip tests (they construct fake client addresses on purpose, e.g. the
		// netErrCause scrubbing tests) and non-Go files.
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		scanned++
		for i, line := range strings.Split(string(src), "\n") {
			if strings.Contains(line, forbidden) {
				rel, _ := filepath.Rel(internalRoot, path)
				offenders = append(offenders, rel+":"+itoa(i+1))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk server source: %v", err)
	}
	// Guard against a vacuous pass: if the path resolved wrong and we scanned
	// nothing, the "no offenders" result would be meaningless. The server has many
	// non-test .go files under internal/; require a plausible floor.
	if scanned < 10 {
		t.Fatalf("only scanned %d source files under %s; the lint path is wrong, not the code clean", scanned, internalRoot)
	}
	if len(offenders) != 0 {
		t.Fatalf("net.Conn.RemoteAddr() appears in server source, which risks a client IP "+
			"reaching a log/error/store (architecture rule 1):\n  %s\n"+
			"Strip the address before any sink and add a narrow commented exemption here if the use is truly safe.",
			strings.Join(offenders, "\n  "))
	}
}

// itoa avoids importing strconv for a single conversion.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
