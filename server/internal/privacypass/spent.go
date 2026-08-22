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
	mu sync.Mutex
	// Two generations. Redemptions land in `current`; `previous` holds the
	// preceding window and is still consulted, so a token stays unusable for at
	// least one full TTL. Rotation drops a whole map, which is why nothing here
	// ever has to sort or scan to make room.
	//
	// The first version evicted by selection sort over the whole store while
	// holding this mutex -- at the ceiling that is on the order of 10^12
	// comparisons, with every redemption blocked behind it, and reachable by
	// anyone who can mint tokens.
	current  map[[32]byte]struct{}
	previous map[[32]byte]struct{}
	rotated  time.Time

	ttl    time.Duration
	nowFn  func() time.Time // injectable for tests
	maxLen int

	// journal persists the two generations, so a restart does not un-spend
	// every outstanding token. Nil for a purely in-memory store.
	journal    *spentJournal
	journalErr error
}

// DefaultTokenTTL matches the 30-day validity window in the spec.
const DefaultTokenTTL = 30 * 24 * time.Hour

// maxSpentEntries bounds a single generation. Reaching it rotates early rather
// than refusing redemptions, which would lock everyone out. Two generations of
// this size is roughly 64 MB of hashes.
const maxSpentEntries = 1_000_000

// NewSpentStore creates an empty store.
func NewSpentStore(ttl time.Duration) *SpentStore {
	if ttl <= 0 {
		ttl = DefaultTokenTTL
	}
	now := time.Now()
	return &SpentStore{
		current:  make(map[[32]byte]struct{}),
		previous: make(map[[32]byte]struct{}),
		rotated:  now,
		ttl:      ttl,
		nowFn:    time.Now,
		maxLen:   maxSpentEntries,
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

	s.rotateIfDueLocked(now)

	if _, ok := s.current[hash]; ok {
		return false
	}
	if _, ok := s.previous[hash]; ok {
		return false
	}
	s.current[hash] = struct{}{}
	if s.journal != nil {
		// A write failure is not a reason to refuse the redemption -- the token
		// is spent in memory either way and refusing would lock the user out
		// over a disk problem -- but it does mean this spend will not survive a
		// restart, so it must not pass silently.
		if err := s.journal.append(genCurrent, hash); err != nil {
			s.journalErr = err
		}
	}
	return true
}

// JournalError reports the last failure to persist a redemption, if any.
//
// Surfaced rather than swallowed: a store that has silently stopped persisting
// looks identical to one that is working, right up until a restart makes every
// token in flight spendable again.
func (s *SpentStore) JournalError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.journalErr
}

// Close flushes the journal.
func (s *SpentStore) Close() error {
	s.mu.Lock()
	j := s.journal
	s.mu.Unlock()
	if j == nil {
		return nil
	}
	return j.close()
}

// Refund un-spends a token whose redemption did not end in a peer.
//
// Redemption happens before the registration it pays for can fail, so without
// this a server that was at capacity destroyed the caller's token and charged
// them again for the retry. Refunding is safe because the token never left the
// caller's hands: nothing was issued against the spend, so returning it puts
// the exchange back exactly where it started.
//
// Only the current generation is touched. A hash found in `previous` was spent
// in an earlier window and is not this request's to give back.
func (s *SpentStore) Refund(hash [32]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.current, hash)
	// The journal keeps its line. Replaying it after a restart re-spends a
	// token that was refunded, which costs the user one token and costs the
	// server nothing -- the safe direction. Rewriting the file to remove a
	// single line would mean a full rewrite on a path that runs whenever the
	// server is full.
}

// rotateIfDueLocked ages out the older generation.
//
// Rotation is a map drop, so it is O(1) in the work done under the lock however
// many entries it discards. A token therefore stays unusable for between one
// and two TTLs -- never less than the validity window, which is the property
// that matters.
func (s *SpentStore) rotateIfDueLocked(now time.Time) {
	if now.Sub(s.rotated) < s.ttl && len(s.current) < s.maxLen {
		return
	}
	s.previous = s.current
	s.current = make(map[[32]byte]struct{})
	s.rotated = now
	if s.journal != nil {
		// Rewrite rather than append: rotation is where the older generation is
		// dropped, and a file that only ever grew would keep proving spends the
		// store itself has forgotten.
		if err := s.journal.rewrite(s.previous, s.current); err != nil {
			s.journalErr = err
		}
	}
}

// Expire drops entries past the validity window.
func (s *SpentStore) Expire() int {
	now := s.nowFn()

	s.mu.Lock()
	defer s.mu.Unlock()

	before := len(s.previous)
	s.rotateIfDueLocked(now)
	if len(s.previous) == 0 {
		return before
	}
	return 0
}

// Len reports how many redemptions are currently recorded.
func (s *SpentStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.current) + len(s.previous)
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
