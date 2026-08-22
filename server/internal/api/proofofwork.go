package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/bits"
	"strings"
	"sync"
	"time"
)

// Proof of work for token issuance.
//
// The problem this solves is that every ordinary rate-limit key is unavailable
// here. The client IP must not exist anywhere in this process, per the first
// non-negotiable constraint. A device handle would defeat blind signing outright
// by letting the server correlate an issuance with the redemption that follows
// it. An account does not exist -- the product has none by design.
//
// A single global budget was the first answer and it has a real cost: one heavy
// caller exhausts it for everyone, which is a denial of service a per-caller
// limit would not have. Proof of work restores the per-caller property without
// reintroducing a caller identity. The cost is paid in CPU rather than in
// identity, so a flood becomes expensive for the flooder while an ordinary
// client pays a fraction of a second once per batch.
//
// It is not a replacement for the global budget. An attacker with a large
// machine still buys tokens faster than a laptop does; proof of work changes the
// price, and the budget caps the absolute rate. Both are kept.
//
// Nothing here records anything about who solved a challenge. The challenge is
// an HMAC over a coarse time window under a server secret, so it is verifiable
// without being stored, and the only state kept is the set of solutions already
// spent within the current window -- which says how many challenges were solved,
// not by whom.
type proofOfWork struct {
	secret     [32]byte
	difficulty uint8
	window     time.Duration
	nowFn      func() time.Time

	mu    sync.Mutex
	used  map[string]struct{}
	epoch int64
}

// Difficulty is in leading zero bits of SHA-256. 20 bits is roughly a million
// hashes: a few hundred milliseconds on one core, unnoticeable once per batch,
// and enough that saturating the global budget costs an attacker real time
// rather than a loop.
const (
	powDifficulty = 20
	powWindow     = 5 * time.Minute
)

func newProofOfWork() (*proofOfWork, error) {
	p := &proofOfWork{
		difficulty: powDifficulty,
		window:     powWindow,
		nowFn:      time.Now,
		used:       make(map[string]struct{}),
	}
	if _, err := rand.Read(p.secret[:]); err != nil {
		return nil, fmt.Errorf("proof of work secret: %w", err)
	}
	return p, nil
}

// Challenge returns the current challenge and its difficulty.
//
// Every client in a window gets the same challenge. That is deliberate: a
// per-client challenge would need a client to distinguish, which is the thing
// that must not exist. Sharing it is safe because a solution is single-use --
// the nonce that satisfies it is spent on first presentation.
func (p *proofOfWork) Challenge() (string, uint8) {
	return p.challengeAt(p.epochOf(p.nowFn())), p.difficulty
}

func (p *proofOfWork) epochOf(t time.Time) int64 {
	return t.UnixNano() / int64(p.window)
}

func (p *proofOfWork) challengeAt(epoch int64) string {
	mac := hmac.New(sha256.New, p.secret[:])
	binary.Write(mac, binary.BigEndian, epoch) //nolint:errcheck
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:16])
}

// Verify checks a solution and spends it.
//
// The current and previous windows are both accepted, so a client that fetched
// a challenge just before a boundary is not refused for being a moment late.
func (p *proofOfWork) Verify(challenge, nonce string) error {
	if challenge == "" || nonce == "" {
		return fmt.Errorf("a proof of work is required")
	}
	if len(nonce) > 64 || strings.ContainsAny(nonce, " \t\r\n") {
		return fmt.Errorf("malformed proof of work")
	}

	now := p.nowFn()
	epoch := p.epochOf(now)
	if challenge != p.challengeAt(epoch) && challenge != p.challengeAt(epoch-1) {
		return fmt.Errorf("the challenge has expired; request a new one")
	}

	sum := sha256.Sum256([]byte(challenge + ":" + nonce))
	if leadingZeroBits(sum[:]) < int(p.difficulty) {
		return fmt.Errorf("the proof of work does not meet the required difficulty")
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	// Drop the whole set when the window turns over. A solution from an expired
	// window is refused above, so nothing older needs remembering, and dropping
	// a map keeps this O(1) instead of scanning.
	if epoch != p.epoch {
		p.used = make(map[string]struct{})
		p.epoch = epoch
	}
	key := challenge + ":" + nonce
	if _, seen := p.used[key]; seen {
		return fmt.Errorf("this proof of work has already been used")
	}
	p.used[key] = struct{}{}
	return nil
}

func leadingZeroBits(b []byte) int {
	n := 0
	for _, c := range b {
		if c != 0 {
			return n + bits.LeadingZeros8(c)
		}
		n += 8
	}
	return n
}
