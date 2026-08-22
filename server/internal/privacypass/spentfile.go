package privacypass

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// spentJournal persists the spent set across restarts.
//
// Without it a restart un-spent every outstanding token. That is not a
// theoretical loss: the whole guarantee the store provides is "this nonce has
// been seen before", and a process that forgets on every deploy provides it
// only between deploys. An attacker who can prompt a restart -- or who simply
// waits for one -- replays every token they hold.
//
// The file holds SHA-256(nonce) and a generation marker, and nothing else. It
// must stay as useless as the in-memory store for any purpose other than
// answering that one question: no addresses, no timestamps per entry, no
// ordering that could be read as a session history. Entries are written in
// arrival order because appending is what makes a crash lose nothing, and
// arrival order across a 30-day window says nothing about who arrived.
type spentJournal struct {
	mu   sync.Mutex
	path string
	f    *os.File
	w    *bufio.Writer
}

// Journal line format: "<generation> <base64url hash>". Two generations exist at
// any time and rotation rewrites the file, so the marker only has to
// distinguish current from previous.
const (
	genPrevious = "p"
	genCurrent  = "c"
)

func openSpentJournal(path string) (*spentJournal, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("spent journal directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open spent journal: %w", err)
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		f.Close()
		return nil, err
	}
	return &spentJournal{path: path, f: f, w: bufio.NewWriter(f)}, nil
}

func (j *spentJournal) append(gen string, hash [32]byte) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if _, err := j.w.WriteString(gen + " " + base64.RawURLEncoding.EncodeToString(hash[:]) + "\n"); err != nil {
		return err
	}
	// Flushed on every write. A buffered redemption that is lost to a crash is
	// a token that becomes spendable again, which is the failure this file
	// exists to prevent; the cost is one small write per registration.
	return j.w.Flush()
}

// rewrite replaces the file with exactly the two generations given.
//
// Called on rotation, when the older generation is dropped. Writing a temporary
// file and renaming it means a crash mid-rewrite leaves the previous complete
// file rather than a truncated one.
func (j *spentJournal) rewrite(previous, current map[[32]byte]struct{}) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	tmp := j.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	write := func(gen string, set map[[32]byte]struct{}) error {
		for h := range set {
			if _, err := w.WriteString(gen + " " + base64.RawURLEncoding.EncodeToString(h[:]) + "\n"); err != nil {
				return err
			}
		}
		return nil
	}
	if err := write(genPrevious, previous); err != nil {
		f.Close()
		return err
	}
	if err := write(genCurrent, current); err != nil {
		f.Close()
		return err
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, j.path); err != nil {
		return err
	}

	j.f.Close()
	f2, err := os.OpenFile(j.path, os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	j.f, j.w = f2, bufio.NewWriter(f2)
	return nil
}

func (j *spentJournal) close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.w.Flush(); err != nil {
		j.f.Close()
		return err
	}
	return j.f.Close()
}

// loadSpentJournal reads a journal back into two generations.
//
// A malformed line is skipped rather than fatal. The alternative -- refusing to
// start -- turns a single corrupt byte into an outage, and skipping loses at
// most one nonce's protection while a refusal loses all of them.
func loadSpentJournal(path string) (previous, current map[[32]byte]struct{}, err error) {
	previous = make(map[[32]byte]struct{})
	current = make(map[[32]byte]struct{})

	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return previous, current, nil
	}
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		gen, encoded, ok := strings.Cut(sc.Text(), " ")
		if !ok {
			continue
		}
		raw, decErr := base64.RawURLEncoding.DecodeString(encoded)
		if decErr != nil || len(raw) != 32 {
			continue
		}
		var h [32]byte
		copy(h[:], raw)
		switch gen {
		case genPrevious:
			previous[h] = struct{}{}
		case genCurrent:
			current[h] = struct{}{}
		}
	}
	return previous, current, sc.Err()
}

// NewPersistentSpentStore restores a store from disk and keeps it there.
//
// The rotation timestamp is not persisted: the file records what was spent, not
// when, and a restart therefore restarts the window. Erring toward a longer
// window keeps tokens unusable for at least the validity period, which is the
// direction that cannot cause a double-spend.
func NewPersistentSpentStore(ttl time.Duration, path string) (*SpentStore, error) {
	previous, current, err := loadSpentJournal(path)
	if err != nil {
		return nil, err
	}
	j, err := openSpentJournal(path)
	if err != nil {
		return nil, err
	}
	s := NewSpentStore(ttl)
	s.previous = previous
	s.current = current
	s.journal = j
	return s, nil
}
