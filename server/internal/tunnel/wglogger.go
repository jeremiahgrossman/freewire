package tunnel

import (
	"fmt"
	"regexp"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.zx2c4.com/wireguard/device"
)

// peerRef matches wireguard-go's way of naming a peer in a log line.
//
// It prints `peer(base64prefix…base64suffix)`, which is a fragment of the
// device's public key -- the one identifier this product has. The ellipsis is
// the Unicode character wireguard-go uses, not three dots.
var peerRef = regexp.MustCompile(`peer\([^)]*\)`)

// newWireGuardLogger returns a wireguard-go logger that cannot record who.
//
// wireguard-go logs at its own discretion, and its error messages name peers:
// "peer(eU6d…Zzho) - Failed to send handshake initiation". That is a
// timestamped record identifying a device, which is precisely what the rest of
// this server was changed to stop writing -- and it was arriving from vendored
// code that no amount of care in our own log statements would have caught.
//
// The messages are kept because they are the only diagnostics the WireGuard
// layer produces, and losing them would make a broken tunnel unreadable. Only
// the peer reference is removed.
func newWireGuardLogger(log *zap.Logger) *device.Logger {
	redact := func(format string, args ...any) string {
		return peerRef.ReplaceAllString(fmt.Sprintf(format, args...), "peer(redacted)")
	}
	// No stack traces. These messages are routine -- "no known endpoint for
	// peer" fires on every registration, before the client has sent anything --
	// and each one attached a forty-line trace naming the build machine's
	// filesystem paths, which is both noise and a small thing about the
	// operator's setup that a server log has no reason to carry.
	quiet := log.WithOptions(zap.AddStacktrace(zapcore.FatalLevel))
	return &device.Logger{
		Verbosef: func(format string, args ...any) {
			quiet.Debug("wireguard: " + redact(format, args...))
		},
		Errorf: func(format string, args ...any) {
			quiet.Error("wireguard: " + redact(format, args...))
		},
	}
}
