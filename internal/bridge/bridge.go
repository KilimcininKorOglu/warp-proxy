// Package bridge exposes an OpenAI-compatible reverse proxy that forwards
// requests to a configured upstream through WARP. A retryable status is
// replayed: a 429 whose body is a FreeUsageLimitError rotates the WARP exit
// IP first, while any other retryable answer is retried on the same IP after
// the Retry-After hint. Requests are forwarded unchanged, except for the
// OpenCode free-tier identity (session/request headers, User-Agent and tool
// stubs) which is added when session injection is on and the client did not
// provide it.
package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

// defaultRetryWait is the wait before a non-rotating replay when the upstream
// sends no parsable Retry-After hint.
const defaultRetryWait = 5 * time.Second

// maxErrorPeek bounds how much of a retryable response body is buffered to
// classify it.
const maxErrorPeek = 64 << 10 // 64 KB

// Server is the bridge HTTP server.
type Server struct {
	Upstream *proxy.Upstream
	Logs     *logbuf.Buffer
	Logger   *slog.Logger
	// Rotate rotates the WARP exit IP; it is rate-limited by the caller.
	Rotate func(ctx context.Context) error
	// Cfg is read on every request so panel edits apply immediately.
	Cfg func() config.BridgeConfig
	// Public, when set, returns a transport bound to the next public
	// proxy in the pool, or nil when the pool is empty. It is the last
	// resort after the WARP retries are exhausted.
	Public func(ctx context.Context) *http.Transport

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
// serveHealth answers the local /health path with 200 ok and reports whether
// it did, so the request never reaches the upstream or spends its quota.
func serveHealth(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/health" {
		return false
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
	return true
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// The local health path is answered here and never proxied, so a
	// health probe does not spend upstream quota.
	if serveHealth(w, r) {
		return
	}

	// The Anthropic-compatible surface runs the same pipeline with its
	// own request/response translation.
	if r.Method == http.MethodPost && r.URL.Path == "/v1/messages" {
		s.serveMessages(w, r)
		return
	}

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

	// Add the free-tier tool stubs and identity before the request is
	// (possibly) replayed, so every attempt carries the same body.
	body, ids := renderInjection(cfg, body)

	// The free tier refuses stream:false: with injection on the upstream
	// always streams, and a caller that asked for JSON gets the SSE
	// reassembled into one chat.completion object.
	clientStream := wantsStream(body)
	if ids != nil {
		body = forceStream(body)
	}

	if err := s.acquire(r.Context(), cfg); err != nil {
		http.Error(w, "bridge busy: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer s.release()

	resp, replayErr := s.replay(r, body, cfg, ids)
	if errors.Is(replayErr, errClientCanceled) {
		http.Error(w, "client canceled while waiting for retry", http.StatusBadGateway)
		return
	}
	if replayErr != nil {
		http.Error(w, "bridge upstream failed: "+replayErr.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if ids != nil && !clientStream && isSSE(resp) {
		agg := aggregateSSE(resp.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(agg.openaiCompletion())
		s.note("info", "%s %s -> 200 (aggregated)", r.Method, r.URL.Path)
		return
	}
	copyResponse(w, resp)
	s.note("info", "%s %s -> %d", r.Method, r.URL.Path, resp.StatusCode)
}

// replay runs the request against the upstream, retrying up to
// cfg.RetryAttempts times: each retryable answer goes through prepareReplay
// (WARP rotation or Retry-After wait) before the next attempt. The final
// response or error is returned; errClientCanceled propagates unchanged.
func (s *Server) replay(r *http.Request, body []byte,
	cfg config.BridgeConfig, ids *identity) (*http.Response, error) {
	attempts := max(cfg.RetryAttempts, 0)
	for attempt := 0; ; attempt++ {
		resp, err := s.roundTrip(r, body, cfg, ids)
		if err != nil || !retryable(cfg, resp.StatusCode) || attempt == attempts {
			if err == nil && retryable(cfg, resp.StatusCode) {
				if fb := s.fallback(r, body, cfg, ids); fb != nil {
					resp.Body.Close()
					return fb, nil
				}
			}
			return resp, err
		}
		if err := s.prepareReplay(r, resp, cfg, ids); err != nil {
			return nil, err
		}
	}
}

// fallback retries the request once through a public proxy after the WARP
// retries are exhausted; nil when the pool is disabled or empty.
func (s *Server) fallback(r *http.Request, body []byte,
	cfg config.BridgeConfig, ids *identity) *http.Response {
	if s.Public == nil {
		return nil
	}
	tr := s.Public(r.Context())
	if tr == nil {
		return nil
	}
	s.note("warn", "WARP retries exhausted on %s, falling back to a public proxy", r.URL.Path)
	resp, err := s.roundTripVia(r, body, cfg, ids, tr)
	if err != nil {
		s.note("warn", "public proxy fallback failed: %v", err)
		return nil
	}
	return resp
}

// errClientCanceled reports that the client went away while the bridge waited
// out a Retry-After before replaying.
var errClientCanceled = errors.New("client canceled while waiting for retry")

// prepareReplay gets resp ready for a replay: a FreeUsageLimitError rotates
// the WARP exit IP, while any other retryable answer is retried on the same IP
// after the Retry-After hint. It returns errClientCanceled if the client went
// away while waiting.
func (s *Server) prepareReplay(r *http.Request, resp *http.Response,
	cfg config.BridgeConfig, ids *identity) error {
	if isUsageLimitError(resp) {
		return s.rotateForReplay(r, resp, cfg, ids)
	}
	wait := retryWait(resp, time.Now())
	s.note("warn", "upstream %d on %s, retrying on the same IP after %s",
		resp.StatusCode, r.URL.Path, wait)
	if wait > 0 {
		select {
		case <-r.Context().Done():
			resp.Body.Close()
			return errClientCanceled
		case <-time.After(wait):
		}
	}
	resp.Body.Close()
	return nil
}

// rotateForReplay rotates the WARP exit IP and, when configured, refreshes the
// OpenCode identity so the replay leaves from a fresh IP with a fresh session.
func (s *Server) rotateForReplay(r *http.Request, resp *http.Response,
	cfg config.BridgeConfig, ids *identity) error {
	s.note("warn", "free-tier quota on %s, rotating WARP for replay", r.URL.Path)
	resp.Body.Close()
	if err := s.Rotate(r.Context()); err != nil {
		s.note("warn", "rotation before replay failed: %v", err)
		return err
	}
	// A rotation can also refresh the OpenCode identity so the replay is not
	// tied to the previous session (see Bridge.RotateSessionOnRetry).
	if cfg.InjectSession && cfg.RotateSessionOnRetry {
		ids.rotate()
	}
	return nil
}

// isUsageLimitError reports whether resp is a 429 whose body marks the
// free-tier quota, {"error":{"type":"FreeUsageLimitError"}}. Only such a
// response rotates the WARP IP. The body is buffered and restored.
func isUsageLimitError(resp *http.Response) bool {
	if resp.StatusCode != http.StatusTooManyRequests {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxErrorPeek))
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		return false
	}
	var payload struct {
		Error struct {
			Type string `json:"type"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return false
	}
	return payload.Error.Type == "FreeUsageLimitError"
}

// roundTrip forwards the buffered request to the upstream once.
func (s *Server) roundTrip(r *http.Request, body []byte, cfg config.BridgeConfig, ids *identity) (*http.Response, error) {
	transport := &http.Transport{DialContext: s.Upstream.Dial}
	return s.roundTripVia(r, body, cfg, ids, transport)
}

// roundTripVia sends the buffered request through the given transport.
func (s *Server) roundTripVia(r *http.Request, body []byte, cfg config.BridgeConfig,
	ids *identity, transport *http.Transport) (*http.Response, error) {
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

// retryAfter parses the Retry-After header (seconds or HTTP date), capped at
// maxRetryWait, and reports whether a value was present and parsable.
func retryAfter(resp *http.Response, now time.Time) (time.Duration, bool) {
	v := strings.TrimSpace(resp.Header.Get("Retry-After"))
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(v); err == nil {
		return clampWait(time.Duration(secs) * time.Second), true
	}
	if t, err := http.ParseTime(v); err == nil {
		return clampWait(t.Sub(now)), true
	}
	return 0, false
}

// retryWait is the delay before a non-rotating replay: the Retry-After hint
// when present and parsable, else defaultRetryWait.
func retryWait(resp *http.Response, now time.Time) time.Duration {
	if d, ok := retryAfter(resp, now); ok {
		return d
	}
	return defaultRetryWait
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
