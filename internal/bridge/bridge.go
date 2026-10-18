// Package bridge exposes an OpenAI-compatible reverse proxy that forwards
// requests to a configured upstream through WARP and replays a request
// after a WARP IP rotation when the upstream answers with a retryable
// status such as 429. Requests are forwarded unchanged, except for the
// OpenCode free-tier identity (session/request headers, User-Agent and tool
// stubs) which is added when session injection is on and the client did not
// provide it.
package bridge

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"warp-proxy/internal/config"
	"warp-proxy/internal/logbuf"
	"warp-proxy/internal/proxy"
)

// maxBody bounds the buffered request body so a replay is possible.
const maxBody = 10 << 20 // 10 MB

// maxRetryWait caps how long a Retry-After can make the bridge wait.
const maxRetryWait = 60 * time.Second

// Server is the bridge HTTP server.
type Server struct {
	Upstream *proxy.Upstream
	Logs     *logbuf.Buffer
	Logger   *slog.Logger
	// Rotate rotates the WARP exit IP; it is rate-limited by the caller.
	Rotate func(ctx context.Context) error
	// Cfg is read on every request so panel edits apply immediately.
	Cfg func() config.BridgeConfig

	sem  chan struct{}
	mu   sync.Mutex
	last time.Time
}

// New builds a bridge Server.
func New(upstream *proxy.Upstream, logs *logbuf.Buffer, logger *slog.Logger,
	rotate func(ctx context.Context) error, cfg func() config.BridgeConfig) *Server {
	return &Server{
		Upstream: upstream, Logs: logs, Logger: logger,
		Rotate: rotate, Cfg: cfg,
	}
}

// ServeHTTP implements the bridge handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cfg := s.Cfg()

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil {
		http.Error(w, "read request body failed", http.StatusBadRequest)
		return
	}
	if len(body) > maxBody {
		http.Error(w, "request body exceeds bridge limit", http.StatusRequestEntityTooLarge)
		return
	}

	// Add the free-tier tool stubs before the request is (possibly) replayed,
	// so every attempt carries the same body.
	if cfg.InjectSession {
		body = ensureTools(body)
	}
	ids := newIdentity(cfg)

	if err := s.acquire(r.Context(), cfg); err != nil {
		http.Error(w, "bridge busy: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer s.release()

	attempts := max(cfg.RetryAttempts, 0)
	var resp *http.Response
	var replayErr error
	for attempt := 0; attempt <= attempts; attempt++ {
		resp, replayErr = s.roundTrip(r, body, cfg, ids)
		if replayErr != nil {
			break
		}
		if !retryable(cfg, resp.StatusCode) || attempt == attempts {
			break
		}
		s.note("warn", "upstream %d on %s, rotating WARP for replay",
			resp.StatusCode, r.URL.Path)

		// Honor Retry-After when present, then rotate and replay.
		if wait := retryAfter(resp, time.Now()); wait > 0 {
			select {
			case <-r.Context().Done():
				resp.Body.Close()
				http.Error(w, "client canceled while waiting for retry", http.StatusBadGateway)
				return
			case <-time.After(wait):
			}
		}
		resp.Body.Close()
		if err := s.Rotate(r.Context()); err != nil {
			s.note("warn", "rotation before replay failed: %v", err)
			break
		}
	}
	if replayErr != nil {
		http.Error(w, "bridge upstream failed: "+replayErr.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	copyResponse(w, resp)
	s.note("info", "%s %s -> %d", r.Method, r.URL.Path, resp.StatusCode)
}

// roundTrip forwards the buffered request to the upstream once.
func (s *Server) roundTrip(r *http.Request, body []byte, cfg config.BridgeConfig, ids *identity) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(r.Context(), cfg.TimeoutDur())
	defer cancel()

	target := cfg.Upstream + r.URL.Path
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	req, err := http.NewRequestWithContext(ctx, r.Method, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	copyHeaders(req.Header, r.Header)
	ids.apply(req.Header)
	req.Host = req.URL.Host

	transport := &http.Transport{DialContext: s.Upstream.Dial}
	return transport.RoundTrip(req)
}

// acquire takes a concurrency slot and enforces the minimum spacing
// between upstream calls.
func (s *Server) acquire(ctx context.Context, cfg config.BridgeConfig) error {
	if cfg.MaxConcurrent > 0 {
		if s.sem == nil || cap(s.sem) != cfg.MaxConcurrent {
			s.sem = make(chan struct{}, cfg.MaxConcurrent)
		}
		select {
		case s.sem <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	minGap := cfg.MinIntervalDur()
	if minGap <= 0 {
		return nil
	}
	for {
		s.mu.Lock()
		now := time.Now()
		wait := minGap - now.Sub(s.last)
		if wait <= 0 {
			s.last = now
			s.mu.Unlock()
			return nil
		}
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

func (s *Server) release() {
	if s.sem != nil {
		<-s.sem
	}
}

func (s *Server) note(level, format string, args ...any) {
	if s.Logs != nil {
		s.Logs.Add(level, "bridge", format, args...)
	}
	if s.Logger != nil {
		s.Logger.Info("bridge: " + fmt.Sprintf(format, args...))
	}
}

// retryable reports whether the status code is configured for replay.
func retryable(cfg config.BridgeConfig, status int) bool {
	return slices.Contains(cfg.RetryStatuses, status)
}

// retryAfter parses the Retry-After header (seconds or HTTP date), capped
// at maxRetryWait.
func retryAfter(resp *http.Response, now time.Time) time.Duration {
	v := strings.TrimSpace(resp.Header.Get("Retry-After"))
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		return clampWait(time.Duration(secs) * time.Second)
	}
	if t, err := http.ParseTime(v); err == nil {
		return clampWait(t.Sub(now))
	}
	return 0
}

func clampWait(d time.Duration) time.Duration {
	if d < 0 {
		return 0
	}
	if d > maxRetryWait {
		return maxRetryWait
	}
	return d
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		dst[http.CanonicalHeaderKey(k)] = append([]string(nil), vs...)
	}
}

func copyResponse(w http.ResponseWriter, resp *http.Response) {
	dst := w.Header()
	for k, vs := range resp.Header {
		if strings.EqualFold(k, "Retry-After") {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
