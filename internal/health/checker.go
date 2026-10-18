package health

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"warp-proxy/internal/logbuf"
	"warp-proxy/internal/proxy"
	"warp-proxy/internal/warp"
)

// Config carries the health-check settings. Rebuilt from the live config on
// every run, so panel edits take effect without a restart.
type Config struct {
	Enabled    bool
	URL        string
	TraceURL   string
	BotMarkers []string
	Timeout    time.Duration
}

// Status is the panel-visible health state.
type Status struct {
	Enabled       bool          `json:"enabled"`
	Healthy       bool          `json:"healthy"`
	ExitIP        string        `json:"exit_ip"`
	WarpOn        bool          `json:"warp_on"`
	LastRun       time.Time     `json:"last_run"`
	LastError     string        `json:"last_error"`
	LastFlagAt    time.Time     `json:"last_flag_at"`
	LastReconnect time.Time     `json:"last_reconnect"`
	Limiter       LimiterState  `json:"limiter"`
}

// Checker runs the periodic health check and triggers rate-limited
// reconnects.
type Checker struct {
	up      *proxy.Upstream
	manager *warp.Manager
	logs    *logbuf.Buffer
	logger  *slog.Logger
	lim     *Limiter

	cfg func() Config

	mu    sync.Mutex
	state Status
}

// NewChecker builds a Checker with default limiter settings. cfg is a getter
// read on every run so config edits apply immediately.
func NewChecker(up *proxy.Upstream, manager *warp.Manager, logs *logbuf.Buffer,
	logger *slog.Logger, cfg func() Config) *Checker {
	return &Checker{
		up: up, manager: manager, logs: logs, logger: logger,
		lim: &Limiter{}, cfg: cfg,
	}
}

// limiter returns the rate limiter. The pointer swap keeps in-flight
// decisions consistent.
func (c *Checker) limiter() *Limiter {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lim
}

// AllowReconnect asks the rate limiter whether a reconnect may run now.
func (c *Checker) AllowReconnect() Decision {
	return c.limiter().Allow(time.Now())
}

// RecordReconnect counts one reconnect attempt and its result.
func (c *Checker) RecordReconnect(succeeded bool) {
	c.limiter().Record(time.Now(), succeeded)
}

// UpdateLimiter replaces the limiter settings while keeping counters when
// the identity stays the same.
func (c *Checker) UpdateLimiter(min time.Duration, maxConsecutive int, cooldown time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lim = &Limiter{MinInterval: min, MaxConsecutive: maxConsecutive, Cooldown: cooldown}
}

// Status returns a copy of the current health state.
func (c *Checker) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.state
	st.Limiter = c.limiterSnapshot()
	return st
}

func (c *Checker) limiterSnapshot() LimiterState {
	if c.lim == nil {
		return LimiterState{}
	}
	return c.lim.snapshot()
}

// Loop runs the check on every interval tick until ctx is done.
func (c *Checker) Loop(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.RunOnce(ctx)
		}
	}
}

// RunOnce performs one check and, when flagged, a rate-limited reconnect
// followed by a re-check.
func (c *Checker) RunOnce(ctx context.Context) {
	cfg := c.cfg()
	if !cfg.Enabled {
		return
	}
	result := c.check(ctx, cfg)

	c.mu.Lock()
	c.state.Enabled = true
	c.state.LastRun = time.Now()
	if result.err != nil {
		c.state.LastError = result.err.Error()
		c.state.Healthy = false
	} else {
		c.state.LastError = ""
		c.state.Healthy = !result.flagged
		c.state.ExitIP = result.exitIP
		c.state.WarpOn = result.warpOn
		if result.flagged {
			c.state.LastFlagAt = time.Now()
		}
	}
	c.mu.Unlock()

	c.logs.Add("info", "health", "check: healthy=%v ip=%s err=%v",
		!result.flagged && result.err == nil, result.exitIP, result.err)
	if !result.flagged && result.err == nil {
		return
	}
	c.maybeReconnect(ctx, cfg)
}

// checkResult is the outcome of a single check pass.
type checkResult struct {
	flagged bool
	err     error
	exitIP  string
	warpOn  bool
}

// check fetches the health URL through WARP and scans it for markers, then
// reads the exit IP from the trace endpoint when configured.
func (c *Checker) check(ctx context.Context, cfg Config) checkResult {
	client := &http.Client{
		Transport: &http.Transport{DialContext: c.up.Dial},
		Timeout:   cfg.Timeout,
	}
	body, err := fetch(ctx, client, cfg.URL)
	if err != nil {
		return checkResult{err: fmt.Errorf("health fetch: %w", err)}
	}
	for _, marker := range cfg.BotMarkers {
		if marker != "" && bytes.Contains(body, []byte(marker)) {
			return checkResult{flagged: true}
		}
	}
	if cfg.TraceURL != "" {
		trace, err := fetch(ctx, client, cfg.TraceURL)
		if err != nil {
			return checkResult{err: fmt.Errorf("trace fetch: %w", err)}
		}
		ip, warpOn := parseTrace(trace)
		return checkResult{exitIP: ip, warpOn: warpOn}
	}
	return checkResult{}
}

// maybeReconnect reconnects when the limiter allows, then re-checks once.
func (c *Checker) maybeReconnect(ctx context.Context, cfg Config) {
	dec := c.limiter().Allow(time.Now())
	if !dec.Allowed {
		c.logs.Add("warn", "reconnect", "reconnect denied: %s", dec)
		return
	}

	c.logs.Add("warn", "reconnect", "reconnecting WARP (%s mode)", c.manager.ReconnectMode())
	err := c.manager.Reconnect(ctx)
	c.limiter().Record(time.Now(), err == nil)
	if err != nil {
		c.logs.Add("error", "reconnect", "reconnect failed: %v", err)
		c.logger.Error("warp reconnect failed", "err", err)
		return
	}
	c.mu.Lock()
	c.state.LastReconnect = time.Now()
	c.mu.Unlock()
	c.logs.Add("info", "reconnect", "WARP reconnect completed")

	// Re-check right away so the panel shows the fresh state.
	after := c.check(ctx, cfg)
	c.mu.Lock()
	if after.err == nil {
		c.state.Healthy = !after.flagged
		c.state.LastError = ""
		c.state.ExitIP = after.exitIP
		c.state.WarpOn = after.warpOn
		if after.flagged {
			c.state.LastFlagAt = time.Now()
			c.logs.Add("warn", "health", "still flagged after reconnect")
		}
	} else {
		c.state.Healthy = false
		c.state.LastError = after.err.Error()
	}
	c.mu.Unlock()
}

// ManualReconnect runs a rate-limited reconnect on panel request.
func (c *Checker) ManualReconnect(ctx context.Context) error {
	dec := c.limiter().Allow(time.Now())
	if !dec.Allowed {
		return fmt.Errorf("reconnect denied: %s", dec)
	}
	err := c.manager.Reconnect(ctx)
	c.limiter().Record(time.Now(), err == nil)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.state.LastReconnect = time.Now()
	c.mu.Unlock()
	c.logs.Add("info", "reconnect", "manual WARP reconnect completed")
	return nil
}

// parseTrace reads ip= and warp= from a Cloudflare cdn-cgi/trace body.
func parseTrace(body []byte) (ip string, warpOn bool) {
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 4096), 64*1024)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "ip="):
			ip = strings.TrimPrefix(line, "ip=")
		case strings.HasPrefix(line, "warp="):
			warpOn = strings.TrimPrefix(line, "warp=") == "on"
		}
	}
	return ip, warpOn
}

// fetch performs a GET and returns the response body.
func fetch(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %s", url, resp.Status)
	}
	return io.ReadAll(resp.Body)
}
