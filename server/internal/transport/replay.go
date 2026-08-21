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
func (w *replayWindow) accept(seq uint32) bool {
	switch {
	case seq > w.highest:
		// Advance, shifting the bitmap by the gap.
		if shift := seq - w.highest; shift >= replayWindowSize {
			w.bitmap = 0
		} else {
			w.bitmap <<= shift
		}
		w.bitmap |= 1
		w.highest = seq
		return true

	case w.highest-seq >= replayWindowSize:
		// Too old to prove it is not a replay.
		return false

	default:
		bit := uint64(1) << (w.highest - seq)
		if w.bitmap&bit != 0 {
			return false // already seen
		}
		w.bitmap |= bit
		return true
	}
}
