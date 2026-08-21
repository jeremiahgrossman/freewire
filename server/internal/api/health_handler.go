package api

import "net/http"

type healthResponse struct {
	Status            string `json:"status"`
	Region            string `json:"region"`
	CurrentPeers      int    `json:"current_peers"`
	Capacity          int    `json:"capacity"`
	CapacityAvailable bool   `json:"capacity_available"`
	ServerVersion     string `json:"server_version"`
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	peers := s.wg.PeerCount()
	writeJSON(w, http.StatusOK, healthResponse{
		Status:            "ok",
		Region:            s.cfg.Region,
		CurrentPeers:      peers,
		Capacity:          s.cfg.Capacity,
		CapacityAvailable: peers < s.cfg.Capacity,
		ServerVersion:     s.cfg.ServerVersion,
	})
}
