package api

import (
	"sync"
	"time"
)

// tokenBucket is a leaky-bucket rate limiter with no notion of who is calling.
//
// Rate limiting is normally keyed on the caller, and every usual key is
// unavailable here. The client IP must not exist anywhere in this process, per
// the first non-negotiable constraint. A device identifier would defeat the
// entire point of blind issuance by letting the server correlate an issuance
// with the redemption that follows it. That leaves one honest option: a single
// global budget shared by everyone.
//
// The cost is real and worth stating. A global bucket means one heavy caller
// can exhaust the budget for everyone, which is a denial of service the
// per-caller version would not have. It is accepted because the alternative is
// to hold identifying data, and because the budget below is far above what any
// legitimate client consumes: a client asks for a batch of tokens occasionally,
// not continuously.
type tokenBucket struct {
	mu       sync.Mutex
	capacity float64
	tokens   float64
	perSec   float64
	last     time.Time
	nowFn    func() time.Time
}

func newTokenBucket(capacity int, perSec float64) *tokenBucket {
	return &tokenBucket{
		capacity: float64(capacity),
		tokens:   float64(capacity),
		perSec:   perSec,
		nowFn:    time.Now,
	}
}

// allow removes n from the budget, reporting whether it was available and, when
// it was not, how long the caller should wait before the budget covers n again.
func (b *tokenBucket) allow(n int) (bool, time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.nowFn()
	if b.last.IsZero() {
		b.last = now
	}
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens += elapsed * b.perSec
		if b.tokens > b.capacity {
			b.tokens = b.capacity
		}
		b.last = now
	}

	want := float64(n)
	if b.tokens >= want {
		b.tokens -= want
		return true, 0
	}
	// Round up to a whole second so a caller that honours Retry-After succeeds
	// on its next attempt rather than arriving a few milliseconds early.
	wait := time.Duration((want-b.tokens)/b.perSec*float64(time.Second)) + time.Second
	return false, wait.Truncate(time.Second)
}
