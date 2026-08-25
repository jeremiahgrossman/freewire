package api

import (
	"encoding/base64"
	"net"
	"net/http"
	"sync"
)

// publicIPv6 returns the advertised IPv6 endpoint: the configured override, or
// the first global-unicast IPv6 address found on the host. Cached: the address
// does not change over a process lifetime, and enumerating interfaces per config
// request is wasteful. Empty when the host has no global v6 (the v6 carrier is
// then simply never offered).
func publicIPv6(override string) string {
	if override != "" {
		return override
	}
	detectV6Once.Do(func() { detectedV6 = detectGlobalIPv6() })
	return detectedV6
}

var (
	detectV6Once sync.Once
	detectedV6   string
)

func detectGlobalIPv6() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipnet.IP
		// Global unicast v6 only: skip v4, link-local, loopback, and ULA
		// (fc00::/7), none of which a remote client can reach.
		if ip.To4() != nil || ip.To16() == nil {
			continue
		}
		if !ip.IsGlobalUnicast() || ip.IsPrivate() {
			continue
		}
		return ip.String()
	}
	return ""
}

type serverConfigResponse struct {
	PublicKey         string   `json:"public_key"`
	EndpointHost      string   `json:"endpoint_host"`
	EndpointPort      int      `json:"endpoint_port"`
	TLSEndpointHost   string   `json:"tls_endpoint_host"`
	TLSEndpointPort   int      `json:"tls_endpoint_port"`
	DNSTunnelPort     int      `json:"dns_tunnel_port"`
	ICMPUDPPort       int      `json:"icmp_udp_port"`
	DNSTunnelDomain   string   `json:"dns_tunnel_domain"`
	EndpointHostV6    string   `json:"endpoint_host_v6,omitempty"`
	CDNHost           string   `json:"cdn_host,omitempty"`
	AllowedIPs        []string `json:"allowed_ips"`
	ServerVersion     string   `json:"server_version"`
	MinClientVersion  string   `json:"min_client_version"`
	Region            string   `json:"region"`
	CapacityAvailable bool     `json:"capacity_available"`

	// Privacy Pass issuer public key, absent on self-hosted servers.
	//
	// A client cannot blind a token without it, so withholding it would leave
	// issuance reachable but unusable. Publishing it costs nothing: it is a
	// public key, and its whole purpose is that anyone can verify a token
	// against it.
	PrivacyPassKeyN  string `json:"privacy_pass_key_n,omitempty"`
	PrivacyPassKeyE  int    `json:"privacy_pass_key_e,omitempty"`
	PrivacyPassKeyID string `json:"privacy_pass_key_id,omitempty"`
}

func (s *Server) handleServerConfig(w http.ResponseWriter, r *http.Request) {
	// Fall back to the Host header, which is the address the client dialed.
	// RemoteAddr is deliberately not consulted: it is the client's own source
	// address, so echoing it would hand back a useless endpoint and would put a
	// client IP on a live code path.
	host := s.cfg.PublicHost
	if host == "" {
		host = r.Host
		if hh, _, err := splitHostPort(host); err == nil {
			host = hh
		}
	}
	resp := serverConfigResponse{
		PublicKey:         s.cfg.PublicKey,
		EndpointHost:      host,
		EndpointPort:      s.cfg.ListenPort,
		TLSEndpointHost:   host,
		TLSEndpointPort:   s.cfg.TLSPort,
		DNSTunnelPort:     s.cfg.DNSTunnelPort,
		ICMPUDPPort:       s.cfg.ICMPUDPPort,
		DNSTunnelDomain:   s.cfg.DNSTunnelDomain,
		EndpointHostV6:    publicIPv6(s.cfg.PublicHostV6),
		CDNHost:           s.cfg.CDNHost,
		AllowedIPs:        []string{"0.0.0.0/0", "::/0"},
		ServerVersion:     s.cfg.ServerVersion,
		MinClientVersion:  s.cfg.MinClientVersion,
		Region:            s.cfg.Region,
		CapacityAvailable: s.wg.PeerCount() < s.cfg.Capacity,
	}

	if s.issuer != nil {
		pub := s.issuer.PublicKey()
		keyID := s.issuer.KeyID()
		resp.PrivacyPassKeyN = base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
		resp.PrivacyPassKeyE = pub.E
		resp.PrivacyPassKeyID = base64.RawURLEncoding.EncodeToString(keyID[:])
	}

	writeJSON(w, http.StatusOK, resp)
}

func splitHostPort(addr string) (host, port string, err error) {
	return net.SplitHostPort(addr)
}
