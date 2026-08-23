package main

import (
	"sync"
	"testing"
)

func TestAdaptiveLimiter_GrowsWhileClean(t *testing.T) {
	a := newAdaptiveLimiter(4, 2, 64)
	// A full window of successes should buy exactly one more slot.
	start := a.currentLimit()
	for i := 0; i < int(start); i++ {
		a.acquire()
		a.release(true)
	}
	if got := a.currentLimit(); got != start+1 {
		t.Fatalf("after one clean window limit = %v, want %v", got, start+1)
	}
}

func TestAdaptiveLimiter_BacksOffOnLoss(t *testing.T) {
	a := newAdaptiveLimiter(20, 2, 64)
	a.acquire()
	a.release(false) // a timeout
	if got := a.currentLimit(); got != 20*aimdDecrease {
		t.Fatalf("after loss limit = %v, want %v", got, 20*aimdDecrease)
	}
}

func TestAdaptiveLimiter_ClampsToBounds(t *testing.T) {
	a := newAdaptiveLimiter(3, 3, 5)
	for i := 0; i < 50; i++ { // hammer losses
		a.acquire()
		a.release(false)
	}
	if got := a.currentLimit(); got < 3 {
		t.Errorf("limit %v fell below min 3", got)
	}
	a = newAdaptiveLimiter(5, 2, 5)
	for i := 0; i < 500; i++ { // hammer successes
		a.acquire()
		a.release(true)
	}
	if got := a.currentLimit(); got > 5 {
		t.Errorf("limit %v grew past max 5", got)
	}
}

// The limiter must never admit more concurrent holders than its current limit --
// that is the whole safety property. Run many goroutines and check the observed
// peak in-flight never exceeds the limit at the time.
func TestAdaptiveLimiter_NeverExceedsLimit(t *testing.T) {
	a := newAdaptiveLimiter(6, 2, 6) // fixed band so the check is simple
	var mu sync.Mutex
	inFlight, peak := 0, 0
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.acquire()
			mu.Lock()
			inFlight++
			if inFlight > peak {
				peak = inFlight
			}
			mu.Unlock()
			mu.Lock()
			inFlight--
			mu.Unlock()
			a.release(true)
		}()
	}
	wg.Wait()
	if peak > 6 {
		t.Errorf("peak in-flight %d exceeded the limit 6", peak)
	}
}

// Convergence: a path that fails any query while more than K are concurrently in
// flight (a portal rate-limit) and succeeds otherwise. The limiter must settle
// near K -- not run away to max, not collapse to the floor. This needs real
// concurrency: sequentially only one query is ever in flight.
func TestAdaptiveLimiter_ConvergesToPathCapacity(t *testing.T) {
	const K = 8
	a := newAdaptiveLimiter(4, 2, 64)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	// Enough workers to push past K when the limit allows it.
	for w := 0; w < 40; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				a.acquire()
				// A query "fails" when the path saw more than K concurrent -- read
				// the limiter's own in-flight count (includes this holder).
				a.mu.Lock()
				over := a.inFlight > K
				a.mu.Unlock()
				// Hold briefly so holders genuinely overlap.
				for i := 0; i < 200; i++ {
				}
				a.release(!over)
			}
		}()
	}
	// Let it run enough rounds to settle.
	sampleLimits := []float64{}
	for i := 0; i < 200; i++ {
		sampleLimits = append(sampleLimits, a.currentLimit())
	}
	close(stop)
	wg.Wait()

	got := a.currentLimit()
	if got < K-3 || got > K+6 {
		t.Errorf("limit settled at %v, want near the path capacity %d", got, K)
	}
}
