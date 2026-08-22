package transport

// replayWindow tracks which packet sequence numbers have already been accepted
// on one direction of a session.
//
// Both tunnel transports need this and neither may go without it: the sequence
// number is visible to anyone on the path and is used to build the AEAD nonce,
// so a captured packet decrypts cleanly every time it is resent. Only a record
// of what has already been seen distinguishes a replay from a fresh packet.
//
// The shape is the WireGuard/IPsec convention: the highest sequence accepted so
// far, plus a bitmap of the window below it, so packets that arrive out of
// order on a lossy path are still accepted exactly once.
//
// Not safe for concurrent use; callers hold the session lock.
type replayWindow struct {
	highest uint32
	bitmap  uint64
}

// replayWindowSize is how far behind the highest accepted sequence a packet may
// arrive and still be provably fresh.
const replayWindowSize = 64

// accept reports whether seq is fresh, recording it when it is.
//
// Prefer check/commit on any path where the packet has not yet been
// authenticated. accept is only safe once the sender is known to hold the key.
func (w *replayWindow) accept(seq uint32) bool {
	if !w.check(seq) {
		return false
	}
	w.commit(seq)
	return true
}

// check reports whether seq would be accepted, without changing anything.
//
// Separate from commit because the window must not move for a packet that has
// not been authenticated. Advancing on receipt looked like a cheap way to make
// a replay flood cost no AEAD work, but the sequence number is attacker-visible
// on both transports -- it rides in the DNS query name in cleartext -- so one
// forged packet carrying seq 0xFFFFFFFF would push `highest` to the maximum and
// every real packet afterwards would fall outside the window. The session stays
// dead until eviction, from an attacker who holds no key material at all.
func (w *replayWindow) check(seq uint32) bool {
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
