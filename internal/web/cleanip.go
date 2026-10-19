package web

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"warp-proxy/internal/cleanip"
	"warp-proxy/internal/config"
)

// scanBudget bounds one scan regardless of the parameter combination.
const scanBudget = 90 * time.Second

// showCleanIP renders the scanner page with the last scan, if any.
func (s *Server) showCleanIP(w http.ResponseWriter, _ *http.Request) {
	cfg := s.GetConfig()
	s.mu.Lock()
	results, scanErr, scanAt := s.scan, s.scanErr, s.scanAt
	s.mu.Unlock()

	s.render(w, "cleanip.html", map[string]any{
		"Cfg":     cfg,
		"Results": results,
		"ScanErr": scanErr,
		"ScanAt":  scanAt,
	})
}

// doCleanIPScan runs a scan with the posted parameters, saves them to the
// config and shows the ranked results.
func (s *Server) doCleanIPScan(w http.ResponseWriter, r *http.Request) {
	cfg := s.GetConfig()
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form parse failed", http.StatusBadRequest)
		return
	}
	applyScanForm(cfg, r)
	if err := s.SaveConfig(cfg); err != nil {
		http.Error(w, "config save failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if s.OnLiveConfigChange != nil {
		s.OnLiveConfigChange(cfg)
	}

	ctx, cancel := context.WithTimeout(r.Context(), scanBudget)
	defer cancel()
	results, err := s.Scanner(ctx, cfg)

	s.mu.Lock()
	s.scan, s.scanErr, s.scanAt = results, "", time.Now()
	if err != nil {
		s.scanErr = err.Error()
		s.scan = nil
	}
	s.mu.Unlock()
	s.Logs.Add("info", "cleanip", "scan finished: %d reachable candidates", len(results))

	http.Redirect(w, r, "/cleanip", http.StatusSeeOther)
}

// applyEndpoint reads the chosen endpoint from the apply form: either a
// combined "host:port" (home-edge scan results) or separate ip and port
// fields. bad reports an unusable value.
func applyEndpoint(r *http.Request) (string, bool) {
	if combined := r.FormValue("ip"); strings.Contains(combined, ":") {
		return applyCombinedEndpoint(combined)
	}
	ip := net.ParseIP(r.FormValue("ip"))
	port, err := strconv.Atoi(r.FormValue("port"))
	if ip == nil || err != nil || port < 1 || port > 65535 {
		return "", true
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(port)), false
}

// applyCombinedEndpoint normalizes a combined "host:port" form value.
func applyCombinedEndpoint(combined string) (string, bool) {
	host, port, err := net.SplitHostPort(combined)
	if err != nil || net.ParseIP(host) == nil {
		return "", true
	}
	p, perr := strconv.Atoi(port)
	if perr != nil || p < 1 || p > 65535 {
		return "", true
	}
	return net.JoinHostPort(host, port), false
}

// doCleanIPApply pins the chosen edge endpoint and reconnects WARP.
func (s *Server) doCleanIPApply(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form parse failed", http.StatusBadRequest)
		return
	}
	endpoint, bad := applyEndpoint(r)
	if bad {
		s.Logs.Add("warn", "cleanip", "apply rejected: bad endpoint form values")
		http.Redirect(w, r, "/cleanip", http.StatusSeeOther)
		return
	}
	if s.EndpointApplier == nil {
		s.Logs.Add("error", "cleanip", "apply unavailable: endpoint applier missing")
		http.Redirect(w, r, "/cleanip", http.StatusSeeOther)
		return
	}
	if err := s.EndpointApplier(r.Context(), endpoint); err != nil {
		s.Logs.Add("warn", "cleanip", "apply %s failed: %v", endpoint, err)
	} else {
		s.Logs.Add("info", "cleanip", "endpoint %s applied, WARP reconnected", endpoint)
	}
	http.Redirect(w, r, "/cleanip", http.StatusSeeOther)
}

// applyScanForm copies scan parameters from the form onto cfg, keeping the
// current value when a field is empty or invalid.
func applyScanForm(cfg *config.Config, r *http.Request) {
	cfg.CleanIP.Port = formIntOr(r, "port", cfg.CleanIP.Port)
	cfg.CleanIP.SamplesPerRange = formIntOr(r, "samples_per_range", cfg.CleanIP.SamplesPerRange)
	cfg.CleanIP.Workers = formIntOr(r, "workers", cfg.CleanIP.Workers)
	cfg.CleanIP.Top = formIntOr(r, "top", cfg.CleanIP.Top)
	cfg.CleanIP.Timeout = formOr(r, "timeout", cfg.CleanIP.Timeout)
	if cfg.CleanIP.Port < 1 || cfg.CleanIP.Port > 65535 {
		cfg.CleanIP.Port = 443
	}
	if cfg.CleanIP.Timeout == "" {
		cfg.CleanIP.Timeout = "2s"
	}
}

// RunScan executes one scan using the configuration's parameters. It is
// the Scanner implementation wired in main.
func RunScan(ctx context.Context, cfg *config.Config) ([]cleanip.Result, error) {
	timeout, err := config.ParseDuration(cfg.CleanIP.Timeout)
	if err != nil {
		return nil, err
	}
	if cfg.CleanIP.Port < 1 || cfg.CleanIP.Port > 65535 {
		return nil, errors.New("cleanip port out of range")
	}
	ranges, err := cleanip.FetchRanges(ctx)
	if err != nil {
		return nil, err
	}
	return cleanip.Scan(ctx, cleanip.Params{
		Port:            cfg.CleanIP.Port,
		SamplesPerRange: cfg.CleanIP.SamplesPerRange,
		Workers:         cfg.CleanIP.Workers,
		Timeout:         timeout,
		Top:             cfg.CleanIP.Top,
	}, ranges), nil
}
