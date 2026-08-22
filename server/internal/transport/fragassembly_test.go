package transport

import (
	"bytes"
	"testing"
	"time"
)

func newAssembly(total int) *dnsFragAssembly {
	return &dnsFragAssembly{
		chunks:  make([][][]byte, total),
		total:   total,
		started: time.Now(),
	}
}

// add mirrors the collection logic in handleData, so the two stay in step.
func (a *dnsFragAssembly) add(index int, chunk []byte) {
	switch alts := a.chunks[index]; {
	case len(alts) == 0:
		a.chunks[index] = [][]byte{chunk}
		a.received++
	case chunkKnown(alts, chunk):
	case len(alts) < maxFragCandidates && a.conflicts < maxFragConflicts:
		a.chunks[index] = append(alts, chunk)
		a.conflicts++
	}
}

func TestUncontestedAssemblyYieldsOneCandidate(t *testing.T) {
	a := newAssembly(3)
	a.add(0, []byte("aa"))
	a.add(1, []byte("bb"))
	a.add(2, []byte("cc"))

	got := a.candidates()
	if len(got) != 1 {
		t.Fatalf("candidates = %d, want 1 when nothing conflicted", len(got))
	}
	if !bytes.Equal(got[0], []byte("aabbcc")) {
		t.Errorf("reassembly = %q, want aabbcc", got[0])
	}
}

// The attack this defends against: an on-path resolver reads the session token
// and sequence out of the cleartext query name and injects its own fragment.
// First-writer-wins made that a guaranteed kill -- the forged chunk displaced
// the real one and the packet failed its tag check. The real chunks must still
// be reachable.
func TestForgedFragmentDoesNotDisplaceTheRealOne(t *testing.T) {
	a := newAssembly(2)
	a.add(0, []byte("forged")) // attacker wins the race
	a.add(0, []byte("real"))
	a.add(1, []byte("tail"))

	var found bool
	for _, c := range a.candidates() {
		if bytes.Equal(c, []byte("realtail")) {
			found = true
		}
	}
	if !found {
		t.Error("the client's own fragments were not among the reassemblies tried")
	}
}

func TestRetransmissionIsNotAConflict(t *testing.T) {
	a := newAssembly(1)
	a.add(0, []byte("same"))
	a.add(0, []byte("same"))

	if a.conflicts != 0 {
		t.Errorf("conflicts = %d after a retransmission, want 0", a.conflicts)
	}
	if len(a.candidates()) != 1 {
		t.Error("a retransmission produced a second candidate")
	}
}

// A flood must not turn the candidate set into an amplifier: the work an
// attacker can force per packet is what the bound exists to cap.
func TestCandidateCountIsBounded(t *testing.T) {
	a := newAssembly(6)
	for i := 0; i < 6; i++ {
		a.add(i, []byte{byte(i), 'a'})
		a.add(i, []byte{byte(i), 'b'})
		a.add(i, []byte{byte(i), 'c'})
	}
	if got := len(a.candidates()); got > maxReassemblyTries {
		t.Errorf("candidates = %d, want at most %d", got, maxReassemblyTries)
	}
	if a.conflicts > maxFragConflicts {
		t.Errorf("conflicts = %d, want at most %d", a.conflicts, maxFragConflicts)
	}
}

func TestIncompleteAssemblyHasNoCandidates(t *testing.T) {
	a := newAssembly(3)
	a.add(0, []byte("aa"))
	a.add(2, []byte("cc"))

	if got := a.candidates(); got != nil {
		t.Errorf("candidates = %v for a packet missing a fragment, want none", got)
	}
}
