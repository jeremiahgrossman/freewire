package tunnel

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"go.uber.org/zap"
)

// persistedPeer is one row of the peers file: everything AddPeer produced,
// plus the token that authorizes removing it (the in-memory map's key).
type persistedPeer struct {
	PeerToken  string `json:"peer_token"`
	PublicKey  string `json:"public_key"`
	TunnelIP   string `json:"tunnel_ip"`
	TunnelIPv6 string `json:"tunnel_ip_v6"`
}

// loadPeersFile reads the peers file back. Never a hard failure: a missing
// file just means no peers to restore, and a corrupt one is treated the same
// way rather than refusing to start -- every entry can simply re-register once
// the network allows it, so losing this file costs convenience, not safety
// (unlike the spent-token journal, where losing state would let a used token
// be spent again).
//
// A missing file (the expected first-boot case) and an unexpected read/parse
// failure (wrong ownership after a deploy change, disk error, a genuinely
// corrupt file) both return zero peers, but only the second is logged -- so
// "0 peers restored" reads the same on a fresh server as it does when
// something is actually wrong, unless log is watched for this warning.
func loadPeersFile(path string, log *zap.Logger) []persistedPeer {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		log.Warn("could not read peers file; starting with no restored peers", zap.Error(err))
		return nil
	}
	var peers []persistedPeer
	if err := json.Unmarshal(data, &peers); err != nil {
		log.Warn("peers file is not valid JSON; starting with no restored peers", zap.Error(err))
		return nil
	}
	return peers
}

// writePeersFile replaces the peers file with exactly the given set.
//
// Writes to a temp file, fsyncs, and renames over the target -- the same
// pattern spentfile.go uses -- so a crash mid-write leaves the previous
// complete file rather than a truncated one. An empty path disables
// persistence entirely (used by tests that build a Manager with no state
// directory).
func writePeersFile(path string, peers []persistedPeer) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if peers == nil {
		peers = []persistedPeer{}
	}
	data, err := json.Marshal(peers)
	if err != nil {
		return err
	}

	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close() //nolint:errcheck
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close() //nolint:errcheck
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
