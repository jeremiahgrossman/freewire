package api

import (
	"net"
	"net/http"
)

type serverConfigResponse struct {
	PublicKey         string   `json:"public_key"`
	EndpointHost      string   `json:"endpoint_host"`
	EndpointPort      int      `json:"endpoint_port"`
	TLSEndpointHost   string   `json:"tls_endpoint_host"`
	TLSEndpointPort   int      `json:"tls_endpoint_port"`
	DNSTunnelPort     int      `json:"dns_tunnel_port"`
	ICMPUDPPort       int      `json:"icmp_udp_port"`
	DNSTunnelDomain   string   `json:"dns_tunnel_domain"`
	AllowedIPs        []string `json:"allowed_ips"`
	ServerVersion     string   `json:"server_version"`
	MinClientVersion  string   `json:"min_client_version"`
	Region            string   `json:"region"`
	CapacityAvailable bool     `json:"capacity_available"`
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
	writeJSON(w, http.StatusOK, serverConfigResponse{
		PublicKey:         s.cfg.PublicKey,
		EndpointHost:      host,
		EndpointPort:      s.cfg.ListenPort,
		TLSEndpointHost:   host,
		TLSEndpointPort:   s.cfg.TLSPort,
		DNSTunnelPort:     s.cfg.DNSTunnelPort,
		ICMPUDPPort:       s.cfg.ICMPUDPPort,
		DNSTunnelDomain:   "tunnel.freewire.com",
		AllowedIPs:        []string{"0.0.0.0/0", "::/0"},
		ServerVersion:     s.cfg.ServerVersion,
		MinClientVersion:  s.cfg.MinClientVersion,
		Region:            s.cfg.Region,
		CapacityAvailable: s.wg.PeerCount() < s.cfg.Capacity,
	})
}

func splitHostPort(addr string) (host, port string, err error) {
	return net.SplitHostPort(addr)
}
