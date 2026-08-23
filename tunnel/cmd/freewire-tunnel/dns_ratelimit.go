package main

import (
	"math"
	"sync"
)

// adaptiveLimiter paces concurrent DNS carrier queries to whatever rate the
// current path actually sustains, discovered at runtime rather than fixed.
//
// The field test showed why a fixed concurrency is wrong: a café rate-limited
// DNS to our server, so firing at a fixed 24 tripped the limiter, drove loss, and
// collapsed -- while a lower concurrency held 0% loss. The right value is
// whatever the path allows, and that differs per network, so it has to be found,
// not assumed.
//
// AIMD, on the in-flight query limit:
//   - additive increase: after a full limit's worth of successes, +1 (probe for
//     more capacity while the path is clean),
//   - multiplicative decrease: on a failed query (a timeout is the carrier
//     saturating or the portal throttling), cut the limit by a factor (back off
//     fast off a cliff).
//
// Clamped to [min, max]. Unlike the old sliding window this REPLACED, it never
// drops a packet -- it only makes a worker wait for a slot, so the bounded queue
// still absorbs bursts and WireGuard is not pushed into a retransmit storm.
type adaptiveLimiter struct {
	mu        sync.Mutex
	cond      *sync.Cond
	limit     float64 // current concurrency ceiling
	inFlight  int
	successes int // successes since the last increase, toward the next +1
	min, max  float64
}

func newAdaptiveLimiter(start, min, max int) *adaptiveLimiter {
	a := &adaptiveLimiter{limit: float64(start), min: float64(min), max: float64(max)}
	a.cond = sync.NewCond(&a.mu)
	return a
}

// acquire blocks until an in-flight slot is available under the current limit.
func (a *adaptiveLimiter) acquire() {
	a.mu.Lock()
	for a.inFlight >= int(a.limit) {
		a.cond.Wait()
	}
	a.inFlight++
	a.mu.Unlock()
}

// release returns a slot and adjusts the limit: additive increase on a clean
// query, multiplicative decrease on a failed one.
func (a *adaptiveLimiter) release(ok bool) {
	a.mu.Lock()
	a.inFlight--
	if ok {
		a.successes++
		// One full window of successes buys one more slot: the window grows about
		// one per RTT of clean traffic, not once per packet, so it probes for
		// capacity gently instead of overshooting the path's limit immediately.
		if a.successes >= int(a.limit) {
			a.successes = 0
			if a.limit < a.max {
				a.limit++
			}
		}
	} else {
		a.limit = math.Max(a.min, a.limit*aimdDecrease)
		a.successes = 0
	}
	a.mu.Unlock()
	// A decrease can free conceptual room only for waiters already under the new
	// limit; a slot always frees one. Broadcast so blocked workers re-check.
	a.cond.Broadcast()
}

// currentLimit reports the limit (for diagnostics/tests).
func (a *adaptiveLimiter) currentLimit() float64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.limit
}

const aimdDecrease = 0.7 // multiplicative back-off factor on loss
