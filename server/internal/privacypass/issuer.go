// Package privacypass implements the issuance and verification halves of
// Privacy Pass public verifiable tokens (RFC 9578 token type 0x0001, RSA blind
// signatures per RFC 9474).
//
// The point of the scheme is that the server can rate-limit a device without
// being able to tell which device it is rate-limiting. Issuance signs a blinded
// value the server never sees unblinded; redemption presents the unblinded
// token, which the server can verify but cannot correlate with any issuance.
//
// That property is fragile in a specific way: it survives only as long as
// nothing else in the request links the two events. A device identifier, a
// session id, or a client address recorded alongside a redemption would undo
// the entire construction while every signature still verified. Redemption here
// therefore takes a token and nothing else.
package privacypass

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/cloudflare/circl/blindsign/blindrsa"
)

// TokenType is the RFC 9578 identifier for publicly verifiable tokens backed by
// RSA blind signatures.
const TokenType uint16 = 0x0001

// Sizes fixed by the token type.
const (
	NonceSize     = 32
	SignatureSize = 256 // 2048-bit RSA
	TokenSize     = 2 + NonceSize + SignatureSize
)

// variant selects RSASSA-PSS with SHA-384 and a deterministic salt length, as
// the spec requires.
var variant = blindrsa.SHA384PSSDeterministic

// Issuer signs blinded tokens and verifies the unblinded results.
type Issuer struct {
	key *rsa.PrivateKey
}

// NewIssuer wraps an RSA private key.
func NewIssuer(key *rsa.PrivateKey) (*Issuer, error) {
	if key == nil {
		return nil, fmt.Errorf("privacypass: nil issuer key")
	}
	if key.N.BitLen() != 2048 {
		return nil, fmt.Errorf("privacypass: issuer key is %d bits, want 2048", key.N.BitLen())
	}
	return &Issuer{key: key}, nil
}

// GenerateIssuerKey creates a fresh 2048-bit issuer keypair.
func GenerateIssuerKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// PublicKey returns the key clients verify against.
func (i *Issuer) PublicKey() *rsa.PublicKey { return &i.key.PublicKey }

// KeyID is the SHA-256 fingerprint of the public key, used by clients to notice
// a rotation and re-request issuance rather than failing verification silently.
func (i *Issuer) KeyID() [32]byte {
	return sha256.Sum256(publicKeyBytes(&i.key.PublicKey))
}

// BlindSign signs one blinded message.
//
// The server cannot recover the token from what it signs here, which is the
// entire point: this is the half of the exchange that must not be linkable to
// the redemption that follows.
func (i *Issuer) BlindSign(blinded []byte) ([]byte, error) {
	if len(blinded) != SignatureSize {
		return nil, fmt.Errorf("privacypass: blinded message is %d bytes, want %d",
			len(blinded), SignatureSize)
	}
	signer := blindrsa.NewSigner(i.key)
	return signer.BlindSign(blinded)
}

// Token is a redeemed credential.
type Token struct {
	Type      uint16
	Nonce     [NonceSize]byte
	Signature []byte
}

// ParseToken decodes the wire format: type(2) || nonce(32) || signature(256).
func ParseToken(b []byte) (*Token, error) {
	if len(b) != TokenSize {
		return nil, fmt.Errorf("privacypass: token is %d bytes, want %d", len(b), TokenSize)
	}
	t := &Token{Type: binary.BigEndian.Uint16(b[:2])}
	if t.Type != TokenType {
		return nil, fmt.Errorf("privacypass: token type 0x%04x is not supported", t.Type)
	}
	copy(t.Nonce[:], b[2:2+NonceSize])
	t.Signature = append([]byte(nil), b[2+NonceSize:]...)
	return t, nil
}

// Marshal encodes a token in the wire format.
func (t *Token) Marshal() []byte {
	out := make([]byte, 0, TokenSize)
	out = binary.BigEndian.AppendUint16(out, t.Type)
	out = append(out, t.Nonce[:]...)
	return append(out, t.Signature...)
}

// NonceHash is the only record kept of a spent token.
//
// The nonce itself is not stored: keeping it would let anyone with the database
// forge a matching token if they also held a signature, and it is not needed to
// answer the only question asked, which is whether this nonce has been seen.
func (t *Token) NonceHash() [32]byte {
	return sha256.Sum256(t.Nonce[:])
}

// TokenInput is the message the signature covers: type || nonce.
func TokenInput(nonce [NonceSize]byte) []byte {
	out := make([]byte, 0, 2+NonceSize)
	out = binary.BigEndian.AppendUint16(out, TokenType)
	return append(out, nonce[:]...)
}

// Verify reports whether a token carries a valid signature from this issuer.
//
// Verification says nothing about whether the token has already been spent;
// that is the store's job, and both checks are required.
func (i *Issuer) Verify(t *Token) error {
	verifier, err := blindrsa.NewVerifier(variant, &i.key.PublicKey)
	if err != nil {
		return fmt.Errorf("privacypass: verifier: %w", err)
	}
	if err := verifier.Verify(TokenInput(t.Nonce), t.Signature); err != nil {
		return fmt.Errorf("privacypass: signature: %w", err)
	}
	return nil
}

func publicKeyBytes(pk *rsa.PublicKey) []byte {
	out := pk.N.Bytes()
	return append(out, byte(pk.E>>16), byte(pk.E>>8), byte(pk.E))
}
