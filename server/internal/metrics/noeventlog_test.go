package metrics_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The privacy policy states: "We do not record when you connected, how long you
// were connected, or how much data you transferred." The data model says the
// same -- hourly rollups only, no per-connection data ever written.
//
// The code did not honour it. Registrations, transport sessions and evictions
// each wrote a timestamped line. None named a client IP, so the strongest
// guarantee held, but a timestamped record that a connection happened is
// exactly what the policy says does not exist.
//
// This test fails if such a line comes back. It reads source rather than
// behaviour deliberately: the failure mode is a log statement added in good
// faith years from now, and the cheapest place to catch that is where it is
// written.
func TestNoPerConnectionLogStatements(t *testing.T) {
	// Phrases that describe a single connection event rather than an aggregate.
	banned := regexp.MustCompile(
		`log\.(Info|Warn)\([^)]*"(peer added|peer removed|session established|session activated|session evicted|peer connected|client connected)`)

	root := filepath.Join("..", "..")
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for i, line := range strings.Split(string(src), "\n") {
			if banned.MatchString(line) {
				t.Errorf("%s:%d logs a single connection event; count it in "+
					"internal/metrics instead\n    %s", path, i+1, strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}

// The rollup must emit only numbers.
//
// A count cannot name anyone; a string field can. Checking the field
// constructors rather than the words in the file is the difference between an
// invariant and a spell-check -- a counter called SessionsEvicted is fine, a
// zap.String in this line is not, whatever it is called.
func TestRollupEmitsOnlyNumbers(t *testing.T) {
	src, err := os.ReadFile("metrics.go")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	body := string(src)
	start := strings.Index(body, "func RunRollup")
	if start < 0 {
		t.Fatal("RunRollup not found")
	}
	body = body[start:]

	for _, forbidden := range []string{
		"zap.String(", "zap.Any(", "zap.Stringer(", "zap.Reflect(",
		"zap.ByteString(", "zap.Time(",
	} {
		if strings.Contains(body, forbidden) {
			t.Errorf("RunRollup uses %s; a rollup that can carry a value can carry an identifier", forbidden)
		}
	}
	if !strings.Contains(body, "zap.Int64(") {
		t.Error("RunRollup emits no counts at all")
	}
}
