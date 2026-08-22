package main

// replayWindow tracks which server->client packet sequence numbers this client
// has already accepted, so a captured response cannot be replayed at it.
//
// The DNS transport's response carries its sequence number in cleartext in the
// TXT payload, and that number builds the AEAD nonce, so a resent response
// decrypts cleanly every time. Only a record of what has been seen tells a
// replay from a fresh packet. The server already protects the client->server
// direction this way (internal/transport/replay.go); this is the mirror image
// for the direction the client receives, which had no such protection.
//
// Same shape as the server's: highest sequence accepted plus a bitmap of the
// window below it, so out-of-order arrival on a lossy path is still accepted
// exactly once. Not safe for concurrent use; the caller holds the session lock.
type replayWindow struct {
	highest uint32
	bitmap  uint64
	seen    bool // distinguishes "nothing accepted yet" from "accepted seq 0"
}

const replayWindowSize = 64

// check reports whether seq would be accepted, without changing anything. It is
// separate from commit because the window must not advance for a packet that has
// not been authenticated: the sequence number is attacker-visible on the wire,
// so one forged packet carrying a huge seq would otherwise push highest to the
// maximum and every real packet afterwards would fall outside the window.
func (w *replayWindow) check(seq uint32) bool {
	if !w.seen {
		return true
	}
	switch {
	case seq > w.highest:
		return true
	case w.highest-seq >= replayWindowSize:
		return false
	default:
		return w.bitmap&(uint64(1)<<(w.highest-seq)) == 0
	}
}

// commit records seq as seen. Call only after the packet has been authenticated.
func (w *replayWindow) commit(seq uint32) {
	if !w.seen {
		w.seen = true
		w.highest = seq
		w.bitmap = 1
		return
	}
	switch {
	case seq > w.highest:
		if shift := seq - w.highest; shift >= replayWindowSize {
			w.bitmap = 0
		} else {
			w.bitmap <<= shift
		}
		w.bitmap |= 1
		w.highest = seq
	case w.highest-seq >= replayWindowSize:
		// Outside the window; nothing to record.
	default:
		w.bitmap |= uint64(1) << (w.highest - seq)
	}
}
