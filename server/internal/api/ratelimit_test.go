package api

import (
	"testing"
	"time"
)

func TestTokenBucketAllowsBurstThenRefuses(t *testing.T) {
	now := time.Unix(0, 0)
	b := newTokenBucket(10, 1)
	b.nowFn = func() time.Time { return now }

	if ok, _ := b.allow(10); !ok {
		t.Fatal("a full bucket refused a request its capacity covers")
	}
	ok, wait := b.allow(1)
	if ok {
		t.Fatal("an empty bucket allowed a request")
	}
	if wait <= 0 {
		t.Errorf("Retry-After = %v, want a positive wait", wait)
	}
}

func TestTokenBucketRefills(t *testing.T) {
	now := time.Unix(0, 0)
	b := newTokenBucket(10, 1)
	b.nowFn = func() time.Time { return now }

	b.allow(10) //nolint:errcheck
	now = now.Add(5 * time.Second)
	if ok, _ := b.allow(5); !ok {
		t.Error("5 seconds at 1/sec did not restore 5 tokens")
	}
	if ok, _ := b.allow(1); ok {
		t.Error("the refill overshot the elapsed time")
	}
}

// Waiting the advertised Retry-After must actually succeed; a wait rounded down
// leaves a caller that honours it retrying a few milliseconds early, forever.
func TestTokenBucketRetryAfterIsSufficient(t *testing.T) {
	now := time.Unix(0, 0)
	b := newTokenBucket(10, 3)
	b.nowFn = func() time.Time { return now }

	b.allow(10) //nolint:errcheck
	_, wait := b.allow(7)
	now = now.Add(wait)
	if ok, _ := b.allow(7); !ok {
		t.Errorf("waiting the advertised %v was still not enough", wait)
	}
}

func TestTokenBucketDoesNotAccumulatePastCapacity(t *testing.T) {
	now := time.Unix(0, 0)
	b := newTokenBucket(10, 1)
	b.nowFn = func() time.Time { return now }

	b.allow(1) //nolint:errcheck
	now = now.Add(time.Hour)
	if ok, _ := b.allow(11); ok {
		t.Error("an idle hour let the bucket exceed its capacity")
	}
	if ok, _ := b.allow(10); !ok {
		t.Error("an idle bucket did not refill to capacity")
	}
}
