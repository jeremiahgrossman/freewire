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
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/cloudflare/circl/blindsign/blindrsa"
)

const tokenType uint16 = 0x0001

func main() {
	if len(os.Args) < 2 || os.Args[1] != "issue" {
		fmt.Fprintln(os.Stderr, "usage: freewire-tokens issue --server <url> [--count n] [--insecure]")
		os.Exit(2)
	}

	fs := flag.NewFlagSet("issue", flag.ExitOnError)
	server := fs.String("server", "", "base URL, e.g. https://host:8080")
	count := fs.Int("count", 10, "tokens to request")
	insecure := fs.Bool("insecure", false, "accept a self-signed certificate (pinned deployments)")
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

	pub, err := fetchIssuerKey(client, *server)
	if err != nil {
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

func fetchIssuerKey(c *http.Client, base string) (*rsa.PublicKey, error) {
	r, err := c.Get(base + "/v1/server/config")
	if err != nil {
		return nil, fmt.Errorf("fetch server config: %w", err)
	}
	defer r.Body.Close()

	var cfg struct {
		N string `json:"privacy_pass_key_n"`
		E int    `json:"privacy_pass_key_e"`
	}
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode server config: %w", err)
	}
	if cfg.N == "" {
		// A self-hosted server does not issue tokens, and says so here rather
		// than by failing at /tokens/issue.
		return nil, fmt.Errorf("this server does not issue tokens")
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(cfg.N)
	if err != nil {
		return nil, fmt.Errorf("decode issuer modulus: %w", err)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: cfg.E}, nil
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
