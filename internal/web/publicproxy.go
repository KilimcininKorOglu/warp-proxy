package web

import (
	"net/http"
)

// showPublicProxy renders the public proxy pool page.
func (s *Server) showPublicProxy(w http.ResponseWriter, r *http.Request) {
	cfg := s.GetConfig()
	running, last, kept, seen := s.PublicPool.ScanState()
	s.render(w, "publicproxy.html", map[string]any{
		"Enabled":  cfg.PublicProxy.Enabled,
		"Running":  running,
		"Count":    s.PublicPool.Len(),
		"LastScan": last,
		"Kept":     kept,
		"Seen":     seen,
		"Interval": cfg.PublicProxy.Interval,
		"Entries":  s.PublicPool.Snapshot(),
	})
}

// doPublicProxyScan triggers an out-of-band scan; the background refresher
// picks it up. The request returns immediately.
func (s *Server) doPublicProxyScan(w http.ResponseWriter, r *http.Request) {
	select {
	case s.PublicScan <- struct{}{}:
	default:
	}
	http.Redirect(w, r, "/publicproxy", http.StatusSeeOther)
}
