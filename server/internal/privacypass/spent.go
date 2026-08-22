package privacypass

import (
	"sync"
	"time"
)

// SpentStore records which tokens have been redeemed.
//
// It holds SHA-256(nonce) and a timestamp, and nothing else. No device key, no
// address, no session identifier — recording any of those alongside a
// redemption would let the two halves of the exchange be correlated after the
// fact, which is the one thing the blind signature exists to prevent. The
// entries are deliberately useless for anything except answering "has this
// exact nonce been seen before".
//
// Entries expire after the token validity window, so the store does not grow
// without bound and a redemption becomes unprovable once its token could no
// longer have been used anyway.
type SpentStore struct {
	mu     sync.Mutex
	seen   map[[32]byte]time.Time
	ttl    time.Duration
	nowFn  func() time.Time // injectable for tests
	maxLen int
}

// DefaultTokenTTL matches the 30-day validity window in the spec.
const DefaultTokenTTL = 30 * 24 * time.Hour

// maxSpentEntries bounds memory. Reaching it means something is very wrong --
// legitimate use spends a token per connection -- so the oldest entries are
// dropped rather than refusing new redemptions and locking everyone out.
const maxSpentEntries = 5_000_000

// NewSpentStore creates an empty store.
func NewSpentStore(ttl time.Duration) *SpentStore {
	if ttl <= 0 {
		ttl = DefaultTokenTTL
	}
	return &SpentStore{
		seen:   make(map[[32]byte]time.Time),
		ttl:    ttl,
		nowFn:  time.Now,
		maxLen: maxSpentEntries,
	}
}

// Redeem records a token as spent and reports whether it was fresh.
//
// The check and the record happen under one lock: doing them separately would
// let two concurrent redemptions of the same token both observe it unspent,
// which is exactly the double-spend the store exists to prevent.
func (s *SpentStore) Redeem(hash [32]byte) bool {
	now := s.nowFn()

	s.mu.Lock()
	defer s.mu.Unlock()

	if spentAt, ok := s.seen[hash]; ok {
		if now.Sub(spentAt) < s.ttl {
			return false // already spent, still within the window
		}
		// Expired: the token could no longer be used anyway, so the slot is
		// free to reuse.
	}

	if len(s.seen) >= s.maxLen {
		s.evictOldestLocked()
	}
	s.seen[hash] = now
	return true
}

// Expire drops entries past the validity window.
func (s *SpentStore) Expire() int {
	now := s.nowFn()

	s.mu.Lock()
	defer s.mu.Unlock()

	removed := 0
	for h, t := range s.seen {
		if now.Sub(t) >= s.ttl {
			delete(s.seen, h)
			removed++
		}
	}
	return removed
}

// Len reports how many redemptions are currently recorded.
func (s *SpentStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.seen)
}

// evictOldestLocked drops the oldest tenth of the store.
//
// Called only at the ceiling. Dropping a batch rather than one entry avoids
// doing this scan on every subsequent redemption.
func (s *SpentStore) evictOldestLocked() {
	type entry struct {
		h [32]byte
		t time.Time
	}
	oldest := make([]entry, 0, len(s.seen))
	for h, t := range s.seen {
		oldest = append(oldest, entry{h, t})
	}
	// Partial selection is enough: an exact ordering is not required to drop a
	// tenth of the entries by age.
	target := len(oldest) / 10
	if target == 0 {
		target = 1
	}
	for i := 0; i < target; i++ {
		minIdx := i
		for j := i + 1; j < len(oldest); j++ {
			if oldest[j].t.Before(oldest[minIdx].t) {
				minIdx = j
			}
		}
		oldest[i], oldest[minIdx] = oldest[minIdx], oldest[i]
		delete(s.seen, oldest[i].h)
	}
}

// RunExpiry expires entries periodically until stop is closed.
func (s *SpentStore) RunExpiry(every time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			s.Expire()
		}
	}
}
