// Derives a WireGuard public key from a base64 private key.
//
// Exists because the tunnel binary has no key-derivation mode and `wg` is not
// installed by default on macOS. Only used by testing/connect.sh, which needs a
// throwaway identity rather than the app's.
//
// Run from the tunnel module so it can reach curve25519:
//
//	cd tunnel && go run ../testing/pubkey.go <base64-private-key>
package main

import (
	"encoding/base64"
	"fmt"
	"os"

	"golang.org/x/crypto/curve25519"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: pubkey.go <base64-private-key>")
		os.Exit(2)
	}
	raw, err := base64.StdEncoding.DecodeString(os.Args[1])
	if err != nil || len(raw) != 32 {
		fmt.Fprintln(os.Stderr, "private key must be 32 base64-encoded bytes")
		os.Exit(1)
	}
	// Curve25519 scalar clamping, as WireGuard does.
	raw[0] &= 248
	raw[31] = (raw[31] & 127) | 64

	pub, err := curve25519.X25519(raw, curve25519.Basepoint)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(pub))
}
