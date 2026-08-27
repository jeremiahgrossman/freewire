package api

import (
	"encoding/json"
	"sort"
	"testing"
)

// The /v1/config response is a cross-language wire contract: the Go server writes
// it, and both the Swift app (ServerConfig in macos/.../ServerAPI.swift) and,
// downstream, the Go tunnel helper (Config in tunnel/.../main.go) read it. A
// field renamed or added on the server with no matching client change makes a
// carrier silently unreachable -- the failure class this project keeps closing.
// This pins the exact JSON key set so any such change fails loudly here, with a
// message that names the client decoders to update in lockstep.
//
// The map also records who consumes each key, so the audit is not lost: several
// keys are advertised but deliberately NOT consumed yet (documented inline).
func TestServerConfigJSONContract(t *testing.T) {
	// consumers of each advertised key. Keep this current: it is the map an author
	// changing the contract reads before touching either client.
	consumedBy := map[string]string{
		"public_key":         "Swift ServerConfig.publicKey -> Go server_public_key",
		"endpoint_host":      "Swift ServerConfig.endpointHost -> Go server_host (TLS/DNS/ICMP) + server_endpoint (WireGuard)",
		"endpoint_port":      "Swift ServerConfig.endpointPort -> Go server_endpoint",
		"tls_endpoint_port":  "Swift ServerConfig.tlsEndpointPort -> Go tls_port",
		"dns_tunnel_port":    "Swift ServerConfig.dnsTunnelPort -> Go dns_tunnel_port",
		"icmp_udp_port":      "Swift ServerConfig.icmpUDPPort -> Go icmp_udp_port",
		"dns_tunnel_domain":  "Swift ServerConfig.dnsTunnelDomain -> Go dns_tunnel_domain",
		"cdn_host":           "Swift ServerConfig.cdnHost -> Go cdn_host (enables cdn_wss)",
		"capacity_available": "Swift ServerConfig.capacityAvailable (CONN-4 gate)",
		"privacy_pass_key_n": "Swift issuer-key pinning (Privacy Pass blinding)",
		"privacy_pass_key_e": "Swift issuer-key pinning",
		"privacy_pass_key_id": "Swift issuer-key pinning (advertised id vs served key)",

		// Advertised but intentionally NOT consumed by any current client. Listed
		// so the audit survives: a future client that needs one has an explicit
		// entry to flip, and this test proves the server still sends it.
		"tls_endpoint_host": "UNCONSUMED: no distinct-TLS-host path client-side; must equal endpoint_host (see struct comment)",
		"endpoint_host_v6":  "UNCONSUMED: IPv6 client carrier deferred (server-side ready) -- see IPV6-CARRIER-REMAINING.md",
		"allowed_ips":       "UNCONSUMED: client uses the per-peer tunnel IPs from RegisteredPeer, not this",
		"server_version":    "UNCONSUMED: informational",
		"min_client_version": "UNCONSUMED: informational (no client-side min-version gate yet)",
		"region":            "UNCONSUMED: informational",
	}

	// Populate every field, including the omitempty ones, so all keys appear.
	resp := serverConfigResponse{
		PublicKey:         "pk",
		EndpointHost:      "1.2.3.4",
		EndpointPort:      51820,
		TLSEndpointHost:   "1.2.3.4",
		TLSEndpointPort:   443,
		DNSTunnelPort:     53,
		ICMPUDPPort:       4500,
		DNSTunnelDomain:   "t.example",
		EndpointHostV6:    "2001:db8::1",
		CDNHost:           "d1.cloudfront.net",
		AllowedIPs:        []string{"0.0.0.0/0"},
		ServerVersion:     "1.0.0",
		MinClientVersion:  "1.0.0",
		Region:            "us-east-1",
		CapacityAvailable: true,
		PrivacyPassKeyN:   "n",
		PrivacyPassKeyE:   65537,
		PrivacyPassKeyID:  "kid",
	}
	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	gotKeys := keysOf(got)
	wantKeys := keysOf(consumedBy)
	if !equalStringSets(gotKeys, wantKeys) {
		t.Fatalf("config JSON keys drifted from the documented contract.\n"+
			"  on wire:   %v\n"+
			"  documented:%v\n"+
			"  If you added or renamed a field, update BOTH client decoders "+
			"(Swift ServerConfig, Go Config) and the consumedBy map here.",
			gotKeys, wantKeys)
	}

	// Every field the Swift ServerConfig decoder actually reads must be present on
	// the wire, spelled exactly. This is the subset a missing/renamed key would
	// break at connect time.
	swiftReads := []string{
		"public_key", "endpoint_host", "endpoint_port", "tls_endpoint_port",
		"dns_tunnel_port", "icmp_udp_port", "capacity_available",
		"dns_tunnel_domain", "cdn_host",
	}
	for _, k := range swiftReads {
		if _, ok := got[k]; !ok {
			t.Errorf("Swift ServerConfig decodes %q but the server does not send it", k)
		}
	}
}

func keysOf[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func equalStringSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
