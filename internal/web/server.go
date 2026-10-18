// Package web serves the Turkish admin panel: login, status, settings and
// logs.
package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"warp-proxy/internal/cleanip"
	"warp-proxy/internal/config"
	"warp-proxy/internal/health"
	"warp-proxy/internal/logbuf"
	"warp-proxy/internal/warp"

	"golang.org/x/crypto/bcrypt"
)

// sessionTTL is how long a panel login stays valid.
const sessionTTL = 12 * time.Hour

// Server is the panel HTTP server.
type Server struct {
	ConfigPath string
	GetConfig  func() *config.Config
	SaveConfig func(*config.Config) error
	Checker    *health.Checker
	Manager    *warp.Manager
	Logs       *logbuf.Buffer
	Logger     *slog.Logger
	// OnLiveConfigChange applies settings that must not wait for a
	// restart (upstream address, limiter).
	OnLiveConfigChange func(cfg *config.Config)

	// Scanner runs a clean-IP latency scan and returns ranked results.
	Scanner func(ctx context.Context, cfg *config.Config) ([]cleanip.Result, error)
	// EndpointApplier pins a chosen "ip:port" edge endpoint and
	// reconnects WARP; it returns the rate-limit or command error.
	EndpointApplier func(ctx context.Context, endpoint string) error

	tpl      *template.Template
	mu       sync.Mutex
	sessions map[string]time.Time
	scan     []cleanip.Result
	scanErr  string
	scanAt   time.Time
}

// New builds the Server and parses the embedded templates.
func New() *Server {
	return &Server{
		tpl:      template.Must(template.ParseFS(templates, "templates/*.html")),
		sessions: make(map[string]time.Time),
	}
}

// Handler returns the routed handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", s.showLogin)
	mux.HandleFunc("POST /login", s.doLogin)
	mux.HandleFunc("POST /logout", s.requireAuth(s.doLogout))
	mux.HandleFunc("GET /{$}", s.requireAuth(s.showDashboard))
	mux.HandleFunc("POST /reconnect", s.requireAuth(s.doReconnect))
	mux.HandleFunc("GET /settings", s.requireAuth(s.showSettings))
	mux.HandleFunc("POST /settings", s.requireAuth(s.doSettings))
	mux.HandleFunc("GET /logs", s.requireAuth(s.showLogs))
	mux.HandleFunc("POST /logs/clear", s.requireAuth(s.clearLogs))
	mux.HandleFunc("GET /cleanip", s.requireAuth(s.showCleanIP))
	mux.HandleFunc("POST /cleanip/scan", s.requireAuth(s.doCleanIPScan))
	mux.HandleFunc("POST /cleanip/apply", s.requireAuth(s.doCleanIPApply))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})
	return mux
}

// requireAuth wraps a handler with the session check.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.validSession(r) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func (s *Server) validSession(r *http.Request) bool {
	c, err := r.Cookie("warp_proxy_session")
	if err != nil || c.Value == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.sessions[c.Value]
	if !ok || time.Now().After(exp) {
		delete(s.sessions, c.Value)
		return false
	}
	return true
}

func (s *Server) startSession(w http.ResponseWriter) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		http.Error(w, "session token generation failed", http.StatusInternalServerError)
		return
	}
	token := hex.EncodeToString(buf)
	s.mu.Lock()
	// Drop expired sessions while the map is locked.
	now := time.Now()
	for k, exp := range s.sessions {
		if now.After(exp) {
			delete(s.sessions, k)
		}
	}
	s.sessions[token] = now.Add(sessionTTL)
	s.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "warp_proxy_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
}

func (s *Server) showLogin(w http.ResponseWriter, r *http.Request) {
	if s.validSession(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, "login.html", nil)
}

func (s *Server) doLogin(w http.ResponseWriter, r *http.Request) {
	cfg := s.GetConfig()
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form parse failed", http.StatusBadRequest)
		return
	}
	user := r.FormValue("username")
	pass := r.FormValue("password")
	if user != cfg.Auth.Username ||
		bcrypt.CompareHashAndPassword([]byte(cfg.Auth.PasswordHash), []byte(pass)) != nil {
		s.render(w, "login.html", map[string]any{"Error": "Kullanıcı adı veya şifre hatalı"})
		return
	}
	s.startSession(w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) doLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("warp_proxy_session"); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name: "warp_proxy_session", Value: "", Path: "/",
		MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) showDashboard(w http.ResponseWriter, r *http.Request) {
	cfg := s.GetConfig()
	st := s.Checker.Status()
	warpStatus, warpErr := s.Manager.Status(r.Context())

	s.render(w, "dashboard.html", map[string]any{
		"Health":     st,
		"WarpStatus": strings.TrimSpace(warpStatus),
		"WarpError":  warpErr != nil,
		"Mode":       cfg.Warp.ReconnectMode,
		"Limiter":    st.Limiter,
		"Now":        time.Now(),
	})
}

func (s *Server) doReconnect(w http.ResponseWriter, r *http.Request) {
	if err := s.Checker.ManualReconnect(r.Context()); err != nil {
		s.Logs.Add("warn", "reconnect", "manual reconnect denied or failed: %v", err)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) showSettings(w http.ResponseWriter, _ *http.Request) {
	s.render(w, "settings.html", map[string]any{
		"Cfg":   s.GetConfig(),
		"Saved": false,
	})
}

func (s *Server) doSettings(w http.ResponseWriter, r *http.Request) {
	cfg := s.GetConfig()
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form parse failed", http.StatusBadRequest)
		return
	}
	applyForm(cfg, r)
	if err := s.SaveConfig(cfg); err != nil {
		http.Error(w, "config save failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if s.OnLiveConfigChange != nil {
		s.OnLiveConfigChange(cfg)
	}
	s.Logs.Add("info", "settings", "settings updated from panel")
	s.render(w, "settings.html", map[string]any{
		"Cfg": cfg, "Saved": true,
	})
}

// applyForm copies editable fields from the form onto cfg.
func applyForm(cfg *config.Config, r *http.Request) {
	cfg.Panel.Listen = formOr(r, "panel_listen", cfg.Panel.Listen)
	cfg.HTTPProxy.Listen = formOr(r, "http_listen", cfg.HTTPProxy.Listen)
	cfg.SOCKS.Listen = formOr(r, "socks_listen", cfg.SOCKS.Listen)
	cfg.Warp.Binary = formOr(r, "warp_binary", cfg.Warp.Binary)
	cfg.Warp.ProxyAddr = formOr(r, "warp_proxy_addr", cfg.Warp.ProxyAddr)
	cfg.Warp.ReconnectMode = r.FormValue("reconnect_mode")
	if cfg.Warp.ReconnectMode != warp.ModeReregister {
		cfg.Warp.ReconnectMode = warp.ModeReconnect
	}
	cfg.Health.Enabled = r.FormValue("health_enabled") == "on"
	cfg.Health.Interval = formOr(r, "health_interval", cfg.Health.Interval)
	cfg.Health.Timeout = formOr(r, "health_timeout", cfg.Health.Timeout)
	cfg.Health.URL = formOr(r, "health_url", cfg.Health.URL)
	cfg.Health.TraceURL = r.FormValue("trace_url")
	cfg.Health.BotMarkers = splitLines(r.FormValue("bot_markers"))
	cfg.Reconnect.MinInterval = formOr(r, "min_interval", cfg.Reconnect.MinInterval)
	cfg.Reconnect.CooldownAfterBurst = formOr(r, "cooldown", cfg.Reconnect.CooldownAfterBurst)
	cfg.Reconnect.MaxConsecutive = formIntOr(r, "max_consecutive", cfg.Reconnect.MaxConsecutive)
	cfg.Front.Enabled = r.FormValue("front_enabled") == "on"
	cfg.Front.Domains = splitLines(r.FormValue("front_domains"))
	cfg.Front.ResolveCacheTTL = formOr(r, "front_cache_ttl", cfg.Front.ResolveCacheTTL)
	cfg.Bridge.Enabled = r.FormValue("bridge_enabled") == "on"
	cfg.Bridge.Listen = formOr(r, "bridge_listen", cfg.Bridge.Listen)
	cfg.Bridge.Upstream = formOr(r, "bridge_upstream", cfg.Bridge.Upstream)
	cfg.Bridge.RetryStatuses = parseInts(r.FormValue("bridge_retry_statuses"))
	cfg.Bridge.RetryAttempts = formIntOr(r, "bridge_retry_attempts", cfg.Bridge.RetryAttempts)
	cfg.Bridge.MaxConcurrent = formIntOr(r, "bridge_max_concurrent", cfg.Bridge.MaxConcurrent)
	cfg.Bridge.MinInterval = formOr(r, "bridge_min_interval", cfg.Bridge.MinInterval)
	cfg.Bridge.Timeout = formOr(r, "bridge_timeout", cfg.Bridge.Timeout)
}

// parseInts parses a comma-separated integer list; an empty or invalid
// value yields nil.
func parseInts(v string) []int {
	var out []int
	for part := range strings.SplitSeq(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil
		}
		out = append(out, n)
	}
	return out
}

func formOr(r *http.Request, key, fallback string) string {
	v := strings.TrimSpace(r.FormValue(key))
	if v == "" {
		return fallback
	}
	return v
}

func formIntOr(r *http.Request, key string, fallback int) int {
	v := strings.TrimSpace(r.FormValue(key))
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return fallback
	}
	return n
}

func splitLines(v string) []string {
	var out []string
	for line := range strings.SplitSeq(v, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func (s *Server) showLogs(w http.ResponseWriter, r *http.Request) {
	s.render(w, "logs.html", map[string]any{
		"Entries": s.Logs.Snapshot(500),
	})
}

func (s *Server) clearLogs(w http.ResponseWriter, r *http.Request) {
	s.Logs.Clear()
	http.Redirect(w, r, "/logs", http.StatusSeeOther)
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tpl.ExecuteTemplate(w, name, data); err != nil {
		s.Logger.Error("template render failed", "template", name, "err", err)
	}
}
