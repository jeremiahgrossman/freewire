// Package metrics keeps counts, not events.
//
// The privacy policy states plainly: "We do not record when you connected, how
// long you were connected, or how much data you transferred. We cannot tell you
// when your device last connected to our servers, because we don't store that
// information." The data model says the same -- hourly rollups only, and no
// per-device, per-connection or per-IP data ever written.
//
// The code did not honour that. Every registration, every transport session and
// every eviction wrote a timestamped line: "peer added", "session established",
// "session evicted". None named a client IP, so the strongest guarantee held --
// but a timestamped record that a connection happened is exactly what the
// policy says does not exist, and on a server with few users the connection
// timeline is close to a usage history. The promise was written before the
// logging was, and the logging won by default.
//
// So the events are counted rather than logged. A count answers the operational
// question ("is the server doing anything, is anything failing") and cannot be
// replayed into a timeline. The rollup carries no identifiers of any kind: the
// most it can say is that some number of peers connected in the last hour.
package metrics

import (
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// Counters holds the aggregate figures a rollup reports.
//
// Deliberately coarse. Nothing here can be attributed to a device, an address
// or a session, and nothing carries a per-event timestamp -- a counter that
// remembered when it was incremented would be an event log wearing a different
// name.
type Counters struct {
	PeersAdded   atomic.Int64
	PeersRemoved atomic.Int64
	TLSSessions  atomic.Int64
	// WSSessions counts WebSocket-carrier sessions. They arrive on the same
	// port as TLSSessions and are counted there too, so this is the subset that
	// took the WebSocket upgrade -- which is how we learn whether portals are
	// passing web-443 while refusing raw 443.
	WSSessions      atomic.Int64
	DNSSessions     atomic.Int64
	ICMPSessions    atomic.Int64
	SessionsEvicted atomic.Int64
}

var Global Counters

// RunRollup logs an aggregate line every interval until stop is closed.
//
// Counters are read and reset together, so each line covers exactly the period
// since the last one and no figure is double-counted.
func RunRollup(log *zap.Logger, interval time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			log.Info("rollup",
				zap.Duration("period", interval),
				zap.Int64("peers_added", Global.PeersAdded.Swap(0)),
				zap.Int64("peers_removed", Global.PeersRemoved.Swap(0)),
				zap.Int64("tls_sessions", Global.TLSSessions.Swap(0)),
				zap.Int64("ws_sessions", Global.WSSessions.Swap(0)),
				zap.Int64("dns_sessions", Global.DNSSessions.Swap(0)),
				zap.Int64("icmp_sessions", Global.ICMPSessions.Swap(0)),
				zap.Int64("sessions_evicted", Global.SessionsEvicted.Swap(0)),
			)
		}
	}
}
