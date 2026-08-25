package transport

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/freewire/server/internal/certs"
	"github.com/freewire/server/internal/metrics"
)

// Real cross-module interop: the actual server listener against the actual
// client binary.
//
// The RFC-vector tests prove each side matches the standard in isolation, which
// is the stronger check for "will a gateway accept this" -- but it cannot catch
// the two ends disagreeing about something the RFC leaves to us (which port
// carries what, how the carriers are told apart inside TLS, whether bytes
// pipelined behind the 101 survive). Those are exactly the mistakes that would
// show up first as a mysterious field failure, so they are worth a real
// end-to-end run at the desk.
//
// Skipped when the client binary has not been built, so it never breaks a
// server-only checkout or CI job:
//
//	(cd tunnel && go build -o freewire-tunnel ./cmd/freewire-tunnel)
func TestWSSInteropWithClientBinary(t *testing.T) {
	bin, err := filepath.Abs("../../../tunnel/freewire-tunnel")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skip("client binary not built; run: (cd tunnel && go build -o freewire-tunnel ./cmd/freewire-tunnel)")
	}

	// A UDP socket standing in for wireguard-go, echoing whatever the bridge
	// forwards. The real device would discard the probe's unauthentic packet and
	// stay silent; echoing instead lets the probe's --expect-echo assert the
	// server->client direction of the carrier (unmasked frames on the wire),
	// which a silent server would leave untested.
	wgConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer wgConn.Close()
	_, wgPortStr, _ := net.SplitHostPort(wgConn.LocalAddr().String())
	wgPort, _ := strconv.Atoi(wgPortStr)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := wgConn.ReadFrom(buf)
			if err != nil {
				return
			}
			wgConn.WriteTo(buf[:n], from) //nolint:errcheck
		}
	}()

	// A self-signed certificate, as a fresh deployment uses. The client probes
	// with --insecure, which is what the dev config already does.
	dir := t.TempDir()
	tlsCfg, err := certs.Build(
		filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"),
		certs.ACMEOptions{}, zap.NewNop())
	if err != nil {
		t.Fatalf("build tls config: %v", err)
	}

	port := freePort(t)
	srv, err := NewTLS443Server(tlsCfg, wgPort, zap.NewNop())
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Run(ctx, port) //nolint:errcheck

	waitForListener(t, port)

	before := metrics.Global.WSSessions.Load()

	cmd := exec.Command(bin, "--wss-probe",
		"--server", "127.0.0.1", "--port", strconv.Itoa(port), "--insecure", "--expect-echo")
	out, err := cmd.CombinedOutput()
	t.Logf("client probe output:\n%s", out)
	if err != nil {
		t.Fatalf("probe failed (exit %v); both carriers should work against our own listener", err)
	}

	got := string(out)
	// Both carriers share the port and both must work: the discriminator is
	// only correct if neither is shadowed by the other.
	if !strings.Contains(got, "raw TLS/443   OK") {
		t.Error("raw TLS carrier failed against our own listener")
	}
	if !strings.Contains(got, "WebSocket/443  OK") {
		t.Error("WebSocket carrier failed against our own listener")
	}

	if after := metrics.Global.WSSessions.Load(); after <= before {
		t.Errorf("WSSessions did not increment (%d -> %d): the server took the raw path "+
			"for a WebSocket client, so the in-TLS discriminator is wrong", before, after)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func waitForListener(t *testing.T, port int) {
	t.Helper()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("listener on %d never came up", port)
}

// Guard the assumption the interop test rests on: a self-signed config is
// enough to serve both carriers.
var _ = tls.Config{}
