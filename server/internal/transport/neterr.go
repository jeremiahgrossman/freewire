package transport

import (
	"errors"
	"net"
)

// netErrCause renders a network error without the addresses it carries.
//
// net.OpError.Error() formats as "read tcp <local>-><remote>: <cause>", so
// logging one with zap.Error puts the client's IP and port in the log line.
// That breaks the first architecture rule -- client addresses are never written
// anywhere -- and it does so through a field nobody looks at twice, which is
// exactly why it survived two audits.
//
// The operation and the underlying cause are what a reader needs; the addresses
// are the part that must not exist.
func netErrCause(err error) string {
	if err == nil {
		return ""
	}
	var oe *net.OpError
	if errors.As(err, &oe) {
		if oe.Err != nil {
			return oe.Op + ": " + netErrCause(oe.Err)
		}
		return oe.Op
	}
	var ae *net.AddrError
	if errors.As(err, &ae) {
		// AddrError.Error() includes the address itself.
		return ae.Err
	}
	var de *net.DNSError
	if errors.As(err, &de) {
		// DNSError.Error() includes the name being resolved.
		return de.Err
	}
	return err.Error()
}
