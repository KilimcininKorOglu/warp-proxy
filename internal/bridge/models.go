package bridge

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// GET /v1/models serves one shared catalogue for OpenAI and Anthropic
// clients: the upstream list is passed through verbatim except that
// non-free models are dropped (their ids do not end in -free) and the
// fields Anthropic clients expect (type, display_name) are added when the
// upstream does not carry them.
func (s *Server) serveModels(w http.ResponseWriter, r *http.Request) {
	cfg := s.Cfg()
	resp, err := s.roundTrip(r, nil, cfg, newIdentity(cfg))
	if err != nil {
		http.Error(w, "bridge upstream failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close() //nolint:errcheck // read failure surfaces below
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		http.Error(w, "read upstream models failed", http.StatusBadGateway)
		return
	}
	if resp.StatusCode != http.StatusOK {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)
		return
	}
	var list struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		http.Error(w, "upstream models not parsable", http.StatusBadGateway)
		return
	}
	kept := make([]map[string]any, 0, len(list.Data))
	for _, entry := range list.Data {
		id, _ := entry["id"].(string)
		if !strings.HasSuffix(id, "-free") {
			continue
		}
		if _, ok := entry["type"]; !ok {
			entry["type"] = "model"
		}
		if _, ok := entry["display_name"]; !ok {
			entry["display_name"] = id
		}
		kept = append(kept, entry)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": kept})
}
