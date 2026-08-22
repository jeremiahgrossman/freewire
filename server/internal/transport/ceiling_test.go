package transport

import (
	"sync"
	"sync/atomic"
	"testing"
)

// The ceilings were load-then-add, so every caller in a concurrent burst read
// the same under-limit value and all proceeded. The bound could be overshot by
// however many arrived together -- the exact shape of the flood it exists to
// stop. This models both forms and shows only the claim-then-rollback one holds.
func TestClaimThenRollbackHoldsUnderConcurrency(t *testing.T) {
	const limit = 8
	const callers = 200

	claim := func(counter *atomic.Int64, loadThenAdd bool) bool {
		if loadThenAdd {
			if counter.Load() >= limit {
				return false
			}
			counter.Add(1)
			return true
		}
		if counter.Add(1) > limit {
			counter.Add(-1)
			return false
		}
		return true
	}

	run := func(loadThenAdd bool) int64 {
		var counter atomic.Int64
		var admitted atomic.Int64
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < callers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if claim(&counter, loadThenAdd) {
					admitted.Add(1)
				}
			}()
		}
		close(start)
		wg.Wait()
		return admitted.Load()
	}

	if got := run(false); got > limit {
		t.Errorf("claim-then-rollback admitted %d past a limit of %d", got, limit)
	}
	// Not asserted as a failure: the old form overshoots only when the race is
	// actually hit, which is scheduler-dependent. Reported so the difference is
	// visible when it does.
	if got := run(true); got > limit {
		t.Logf("load-then-add admitted %d past a limit of %d — the race this replaced", got, limit)
	}
}
