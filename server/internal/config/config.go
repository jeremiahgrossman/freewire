package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"

	"golang.org/x/crypto/curve25519"
)

// DefaultDNSTunnelDomain is the zone used when a config names none. It must
// match the delegation set up in the registrar's DNS (an NS record for this
// name pointing at a nameserver A record on this server's public IP).
const DefaultDNSTunnelDomain = "t.pinghop.net"

type Config struct {
	PrivateKey       string `json:"private_key"`
	PublicKey        string `json:"public_key"`
	ListenPort       int    `json:"listen_port"`
	APIPort          int    `json:"api_port"`
	TunnelCIDR       string `json:"tunnel_cidr"`
	ServerTunnelIP   string `json:"server_tunnel_ip"`
	Capacity         int    `json:"capacity"`
	Region           string `json:"region"`
	ServerVersion    string `json:"server_version"`
	MinClientVersion string `json:"min_client_version"`

	// Phase 2: additional transport listeners.
	TLSPort       int    `json:"tls_port"`        // default 443
	TLSCertFile   string `json:"tls_cert_file"`   // path to cert PEM; empty = self-signed
	TLSKeyFile    string `json:"tls_key_file"`    // path to key PEM; empty = self-signed
	DNSTunnelPort int    `json:"dns_tunnel_port"` // default 53
	ICMPUDPPort   int    `json:"icmp_udp_port"`   // default 4500

	// DNSTunnelDomain is the authoritative zone this server answers for and
	// advertises to clients. It must be delegated to this host's public IP (an
	// NS record in the parent zone) or the DNS tunnel cannot be reached through
	// a resolver the client does not control. Default "t.pinghop.net".
	DNSTunnelDomain string `json:"dns_tunnel_domain"`

	// PrivacyPassKey is the PEM-encoded RSA issuer key, empty on self-hosted
	// servers.
	//
	// Its presence is what turns anonymous rate limiting on: a self-hosted
	// operator controls which device keys are registered, so blind tokens would
	// add ceremony without adding a guarantee.
	PrivacyPassKey string `json:"privacy_pass_key"`

	// PublicHost is the externally reachable IP or hostname for this server.
	// Used in /v1/server/config responses so clients know where to connect.
	// Defaults to empty string; clients fall back to the address they connected from.
	PublicHost string `json:"public_host"`

	// ACME (Let's Encrypt) automatic certificate management. When ACMEDomain is
	// set, the server provisions and auto-renews a real certificate and
	// TLSCertFile/TLSKeyFile are ignored. Requires port 80 reachable for the
	// HTTP-01 challenge and a public DNS A record pointing at this host.
	ACMEDomain   string `json:"acme_domain"`    // e.g. "vpn.freewire.com"; empty disables ACME
	ACMEEmail    string `json:"acme_email"`     // contact for expiry notices
	ACMECacheDir string `json:"acme_cache_dir"` // cert cache; defaults to "./acme-cache"

	// SpentStoreFile records which Privacy Pass tokens have been redeemed, so a
	// restart does not make every outstanding token spendable again. It holds
	// nonce hashes and nothing else. Defaults to "./spent-tokens".
	SpentStoreFile string `json:"spent_store_file"`
}

// SpentStorePath is where redeemed token hashes are kept between restarts.
func (c *Config) SpentStorePath() string {
	if c.SpentStoreFile == "" {
		return "./spent-tokens"
	}
	return c.SpentStoreFile
}

// ParseRSAPrivateKey decodes a PEM-encoded RSA private key.
func ParseRSAPrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is %T, want an RSA private key", parsed)
	}
	return key, nil
}

// MarshalRSAPrivateKey encodes a key as PEM for storage in the config file.
func MarshalRSAPrivateKey(key *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
}

// Load reads config from path. If the file does not exist, a new config with a
// fresh WireGuard keypair is generated and written to path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return generate(path)
	}
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDefaults()
	return &cfg, nil
}

// applyDefaults fills in zero-value fields with sensible defaults.
func (c *Config) applyDefaults() {
	if c.TLSPort == 0 {
		c.TLSPort = 443
	}
	if c.DNSTunnelPort == 0 {
		c.DNSTunnelPort = 53
	}
	if c.ICMPUDPPort == 0 {
		c.ICMPUDPPort = 4500
	}
	if c.DNSTunnelDomain == "" {
		c.DNSTunnelDomain = DefaultDNSTunnelDomain
	}
	if c.ACMECacheDir == "" {
		c.ACMECacheDir = "./acme-cache"
	}
}

func generate(path string) (*Config, error) {
	privateKey := make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		return nil, fmt.Errorf("generate private key: %w", err)
	}
	// Curve25519 clamping (RFC 7748 §5).
	privateKey[0] &= 248
	privateKey[31] = (privateKey[31] & 127) | 64

	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("derive public key: %w", err)
	}

	cfg := &Config{
		PrivateKey:       base64.StdEncoding.EncodeToString(privateKey),
		PublicKey:        base64.StdEncoding.EncodeToString(publicKey),
		ListenPort:       51820,
		APIPort:          8080,
		TunnelCIDR:       "10.0.0.0/24",
		ServerTunnelIP:   "10.0.0.1",
		Capacity:         253,
		Region:           "local",
		ServerVersion:    "0.1.0",
		MinClientVersion: "0.1.0",
		TLSPort:          443,
		DNSTunnelPort:    53,
		ICMPUDPPort:      4500,
		DNSTunnelDomain:  DefaultDNSTunnelDomain,
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return nil, fmt.Errorf("write config: %w", err)
	}
	return cfg, nil
}
