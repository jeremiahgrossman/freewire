// Command freewire-tokens runs the client half of Privacy Pass issuance.
//
// The app shells out to this rather than implementing RFC 9474 in Swift.
// Blinding requires EMSA-PSS encoding, modular multiplication and modular
// inversion over 2048-bit integers, none of which Security.framework exposes,
// so a Swift implementation would mean hand-rolling all three.
//
// That is a bad place to hand-roll. A subtly wrong blinding factor still
// produces tokens the server accepts, while leaking the linkage between
// issuance and redemption that the whole scheme exists to prevent -- the
// failure is silent and the guarantee is gone. Reusing the implementation the
// server verifies against removes the possibility of the two diverging.
//
//	freewire-tokens issue --server https://host:8080 --count 10
//
// Prints one base64url token per line. Nothing is stored here; the caller owns
// the tokens.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cloudflare/circl/blindsign/blindrsa"
)

const tokenType uint16 = 0x0001

func main() {
	if len(os.Args) < 2 || os.Args[1] != "issue" {
		fmt.Fprintln(os.Stderr, "usage: freewire-tokens issue --server <url> [--count n] [--insecure] [--issuer-pin path]")
		os.Exit(2)
	}

	fs := flag.NewFlagSet("issue", flag.ExitOnError)
	server := fs.String("server", "", "base URL, e.g. https://host:8080")
	count := fs.Int("count", 10, "tokens to request")
	insecure := fs.Bool("insecure", false, "accept a self-signed certificate (pinned deployments)")
	pinFile := fs.String("issuer-pin", "", "file recording the issuer key fingerprint; a change is refused")
	fs.Parse(os.Args[2:]) //nolint:errcheck

	if *server == "" {
		fmt.Fprintln(os.Stderr, "freewire-tokens: --server is required")
		os.Exit(2)
	}
	if *count < 1 || *count > 20 {
		fmt.Fprintln(os.Stderr, "freewire-tokens: --count must be between 1 and 20")
		os.Exit(2)
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			//nolint:gosec // Only when the caller pins the server key out of band.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: *insecure},
		},
	}

	pub, keyID, err := fetchIssuerKey(client, *server)
	if err != nil {
		fmt.Fprintf(os.Stderr, "freewire-tokens: %v\n", err)
		os.Exit(1)
	}
	if err := checkPin(*pinFile, keyID); err != nil {
		fmt.Fprintf(os.Stderr, "freewire-tokens: %v\n", err)
		os.Exit(1)
	}

	tokens, err := issue(client, *server, pub, *count)
	if err != nil {
		fmt.Fprintf(os.Stderr, "freewire-tokens: %v\n", err)
		os.Exit(1)
	}
	for _, t := range tokens {
		fmt.Println(t)
	}
}

func fetchIssuerKey(c *http.Client, base string) (*rsa.PublicKey, [32]byte, error) {
	var keyID [32]byte

	r, err := c.Get(base + "/v1/server/config")
	if err != nil {
		return nil, keyID, fmt.Errorf("fetch server config: %w", err)
	}
	defer r.Body.Close()

	var cfg struct {
		N     string `json:"privacy_pass_key_n"`
		E     int    `json:"privacy_pass_key_e"`
		KeyID string `json:"privacy_pass_key_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		return nil, keyID, fmt.Errorf("decode server config: %w", err)
	}
	if cfg.N == "" {
		// A self-hosted server does not issue tokens, and says so here rather
		// than by failing at /tokens/issue.
		return nil, keyID, fmt.Errorf("this server does not issue tokens")
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(cfg.N)
	if err != nil {
		return nil, keyID, fmt.Errorf("decode issuer modulus: %w", err)
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: cfg.E}
	keyID = issuerKeyID(pub)

	// The server also advertises the fingerprint of the key it is serving. It
	// costs nothing to check, and a mismatch means the two halves of the
	// response disagree -- which is not something a healthy server produces.
	if cfg.KeyID != "" {
		if want := base64.RawURLEncoding.EncodeToString(keyID[:]); cfg.KeyID != want {
			return nil, keyID, fmt.Errorf(
				"server's advertised issuer key id does not match the key it served")
		}
	}
	return pub, keyID, nil
}

// issuerKeyID mirrors the server's Issuer.KeyID: SHA-256 over the modulus
// followed by the three low bytes of the exponent. The two derivations must
// agree, or a pin recorded here would never match again.
func issuerKeyID(pk *rsa.PublicKey) [32]byte {
	buf := pk.N.Bytes()
	buf = append(buf, byte(pk.E>>16), byte(pk.E>>8), byte(pk.E))
	return sha256.Sum256(buf)
}

// checkPin enforces trust-on-first-use over the issuer key.
//
// This is the defence against a tagging attack, and it is the whole reason the
// fingerprint is worth carrying. Blind signing hides the token from the issuer,
// but it does not hide which key signed it: an issuer that hands every client
// its own distinct keypair learns, at redemption, exactly which client a token
// came from. Every signature still verifies and no error is ever raised, so
// nothing but a key-consistency check catches it.
//
// First use records the fingerprint. Any later change is refused rather than
// followed, because following it is precisely the attack. A legitimate rotation
// therefore requires the user to delete this file, which is the intended cost:
// a rotation is rare and an unexplained key change is not something to accept
// silently.
func checkPin(path string, keyID [32]byte) error {
	if path == "" {
		return nil
	}
	want := base64.RawURLEncoding.EncodeToString(keyID[:])

	seen, err := os.ReadFile(path)
	switch {
	case err == nil:
		if got := strings.TrimSpace(string(seen)); got != want {
			return fmt.Errorf(
				"issuer key changed since first use; refusing to sign against it.\n"+
					"If the server legitimately rotated its key, delete %s and retry", path)
		}
		return nil
	case errors.Is(err, fs.ErrNotExist):
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return fmt.Errorf("create pin directory: %w", err)
		}
		if err := os.WriteFile(path, []byte(want+"\n"), 0o600); err != nil {
			return fmt.Errorf("record issuer key pin: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("read issuer key pin: %w", err)
	}
}

func issue(c *http.Client, base string, pub *rsa.PublicKey, count int) ([]string, error) {
	blindClient, err := blindrsa.NewClient(blindrsa.SHA384PSSDeterministic, pub)
	if err != nil {
		return nil, fmt.Errorf("blind client: %w", err)
	}

	nonces := make([][32]byte, count)
	states := make([]blindrsa.State, count)
	blinded := make([]string, count)

	for i := range nonces {
		if _, err := rand.Read(nonces[i][:]); err != nil {
			return nil, fmt.Errorf("nonce: %w", err)
		}
		b, st, err := blindClient.Blind(rand.Reader, tokenInput(nonces[i]))
		if err != nil {
			return nil, fmt.Errorf("blind: %w", err)
		}
		states[i] = st
		blinded[i] = base64.RawURLEncoding.EncodeToString(b)
	}

	body, _ := json.Marshal(map[string]any{"blinded": blinded})
	r, err := c.Post(base+"/v1/tokens/issue", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("issuance request: %w", err)
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("issuance returned HTTP %d", r.StatusCode)
	}

	var resp struct {
		BlindSignatures []string `json:"blind_signatures"`
	}
	if err := json.NewDecoder(r.Body).Decode(&resp); err != nil {
		return nil, fmt.Errorf("decode issuance: %w", err)
	}
	if len(resp.BlindSignatures) != count {
		return nil, fmt.Errorf("asked for %d signatures, got %d", count, len(resp.BlindSignatures))
	}

	out := make([]string, 0, count)
	for i, b64 := range resp.BlindSignatures {
		blindSig, err := base64.RawURLEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("decode signature %d: %w", i, err)
		}
		sig, err := blindClient.Finalize(states[i], blindSig)
		if err != nil {
			// One bad signature does not invalidate the rest of the batch.
			fmt.Fprintf(os.Stderr, "freewire-tokens: discarding token %d: %v\n", i, err)
			continue
		}
		out = append(out, base64.RawURLEncoding.EncodeToString(marshalToken(nonces[i], sig)))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no token in the batch verified")
	}
	return out, nil
}

func tokenInput(nonce [32]byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, tokenType), nonce[:]...)
}

func marshalToken(nonce [32]byte, sig []byte) []byte {
	out := binary.BigEndian.AppendUint16(nil, tokenType)
	out = append(out, nonce[:]...)
	return append(out, sig...)
}
