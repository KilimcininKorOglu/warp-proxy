// Command warp-proxy runs the HTTP and SOCKS5 proxies that route every
// connection through Cloudflare WARP, plus the admin web panel.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"warp-proxy/internal/cleanip"
	"warp-proxy/internal/config"
	"warp-proxy/internal/front"
	"warp-proxy/internal/health"
	"warp-proxy/internal/logbuf"
	"warp-proxy/internal/proxy"
	"warp-proxy/internal/warp"
	"warp-proxy/internal/web"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	configPath := flag.String("config", "config.yaml", "configuration file path")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("config load failed", "err", err)
		os.Exit(1)
	}
	if err := ensurePassword(*configPath, cfg); err != nil {
		logger.Error("password setup failed", "err", err)
		os.Exit(1)
	}

	logs := logbuf.New(1000)
	logSink := &logSink{logs: logs}
	slog.SetDefault(logger)

	manager := warp.NewManager(cfg.Warp.Binary, cfg.Warp.CLIArgs, cfg.Warp.ReconnectMode)
	upstream := &proxy.Upstream{Addr: cfg.Warp.ProxyAddr}

	// Front rewriting: pool fed by the Clean-IP scan, decisions read the
	// live config on every request.
	selector := front.NewSelector(func() front.Config {
		ttl, err := config.ParseDuration(cfg.Front.ResolveCacheTTL)
		if err != nil {
			ttl = 10 * time.Minute
		}
		return front.Config{
			Enabled:         cfg.Front.Enabled,
			Domains:         cfg.Front.Domains,
			ResolveCacheTTL: ttl,
		}
	})
	upstream.Front = selector.Pick

	// The health checker must see the tunnel as clients experience WARP,
	// never a front-rewritten edge, so it gets its own plain upstream.
	checkerUpstream := &proxy.Upstream{Addr: cfg.Warp.ProxyAddr}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := manager.EnsureReady(ctx); err != nil {
		logger.Error("warp setup failed", "err", err)
		logs.Add("error", "warp", "warp setup failed: %v", err)
	}

	checker := health.NewChecker(checkerUpstream, manager, logs, logger, func() health.Config {
		return currentHealthConfig(cfg)
	})
	applyLimiter(cfg, checker)

	// Check once at startup so the panel shows real state immediately,
	// then keep the periodic loop.
	go func() {
		waitUpstream(ctx, checkerUpstream.Addr, 30*time.Second)
		checker.RunOnce(ctx)
		checker.Loop(ctx, healthInterval(cfg))
	}()

	httpSrv := &proxy.HTTPServer{Upstream: upstream, Log: logger, OnRequest: logSink.request}
	socksSrv := &proxy.SOCKSServer{Upstream: upstream}

	panel := web.New()
	panel.ConfigPath = *configPath
	panel.GetConfig = func() *config.Config { return cfg }
	panel.SaveConfig = func(c *config.Config) error { return config.Save(*configPath, c) }
	panel.Checker = checker
	panel.Manager = manager
	panel.Logs = logs
	panel.Logger = logger
	panel.OnLiveConfigChange = func(c *config.Config) {
		upstream.Addr = c.Warp.ProxyAddr
		checkerUpstream.Addr = c.Warp.ProxyAddr
		manager.SetMode(c.Warp.ReconnectMode)
		applyLimiter(c, checker)
	}
	panel.Scanner = func(ctx context.Context, c *config.Config) ([]cleanip.Result, error) {
		results, err := web.RunScan(ctx, c)
		if err == nil {
			selector.SetPool(results)
		}
		return results, err
	}
	panel.EndpointApplier = func(ctx context.Context, endpoint string) error {
		if dec := checker.AllowReconnect(); !dec.Allowed {
			return fmt.Errorf("rate limited: %s", dec)
		}
		err := manager.SetEndpoint(ctx, endpoint)
		checker.RecordReconnect(err == nil)
		return err
	}

	// Listeners: each failure is fatal and logged.
	lnPanel, err := net.Listen("tcp", cfg.Panel.Listen)
	if err != nil {
		logger.Error("panel listen failed", "addr", cfg.Panel.Listen, "err", err)
		os.Exit(1)
	}
	lnHTTP, err := net.Listen("tcp", cfg.HTTPProxy.Listen)
	if err != nil {
		logger.Error("http proxy listen failed", "addr", cfg.HTTPProxy.Listen, "err", err)
		os.Exit(1)
	}
	lnSOCKS, err := net.Listen("tcp", cfg.SOCKS.Listen)
	if err != nil {
		logger.Error("socks listen failed", "addr", cfg.SOCKS.Listen, "err", err)
		os.Exit(1)
	}
	logger.Info("warp-proxy started",
		"panel", cfg.Panel.Listen,
		"http_proxy", cfg.HTTPProxy.Listen,
		"socks", cfg.SOCKS.Listen,
		"upstream", cfg.Warp.ProxyAddr)

	errCh := make(chan error, 3)
	go func() { errCh <- http.Serve(lnPanel, panel.Handler()) }()
	go func() { errCh <- httpSrv.Serve(lnHTTP) }()
	go func() { errCh <- socksSrv.Serve(lnSOCKS) }()

	select {
	case <-ctx.Done():
		logger.Info("shutting down")
	case err := <-errCh:
		logger.Error("server failed", "err", err)
	}
}

// ensurePassword sets the panel password from WARP_PROXY_PASSWORD on first
// run, storing only the bcrypt hash in the config.
func ensurePassword(path string, cfg *config.Config) error {
	if cfg.Auth.PasswordHash != "" {
		return nil
	}
	plain := os.Getenv("WARP_PROXY_PASSWORD")
	if plain == "" {
		return errNoPassword
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	cfg.Auth.PasswordHash = string(hash)
	return config.Save(path, cfg)
}

type errString string

func (e errString) Error() string { return string(e) }

const errNoPassword = errString(
	"panel password not set: define WARP_PROXY_PASSWORD on first run")

// currentHealthConfig converts the YAML config into checker settings.
func currentHealthConfig(cfg *config.Config) health.Config {
	timeout := 30 * time.Second
	if d, err := config.ParseDuration(cfg.Health.Timeout); err == nil {
		timeout = d
	}
	return health.Config{
		Enabled:    cfg.Health.Enabled,
		URL:        cfg.Health.URL,
		TraceURL:   cfg.Health.TraceURL,
		BotMarkers: cfg.Health.BotMarkers,
		Timeout:    timeout,
	}
}

// applyLimiter pushes the configured rate limits into the checker.
func applyLimiter(cfg *config.Config, checker *health.Checker) {
	minI := time.Minute
	if d, err := config.ParseDuration(cfg.Reconnect.MinInterval); err == nil {
		minI = d
	}
	cool := 10 * time.Minute
	if d, err := config.ParseDuration(cfg.Reconnect.CooldownAfterBurst); err == nil {
		cool = d
	}
	checker.UpdateLimiter(minI, cfg.Reconnect.MaxConsecutive, cool)
}

func healthInterval(cfg *config.Config) time.Duration {
	d, err := config.ParseDuration(cfg.Health.Interval)
	if err != nil {
		return 5 * time.Minute
	}
	return d
}

// waitUpstream blocks until the upstream proxy accepts TCP connections or
// the budget runs out, so the first health check does not race warp-cli's
// listener startup.
func waitUpstream(ctx context.Context, addr string, budget time.Duration) {
	deadline := time.Now().Add(budget)
	for {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			conn.Close()
			return
		}
		if ctx.Err() != nil || time.Now().After(deadline) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

// logSink adapts proxy requests into the panel ring buffer.
type logSink struct {
	logs *logbuf.Buffer
}

func (s *logSink) request(kind, client, target string) {
	s.logs.Add("info", "request", "%s %s -> %s", kind, client, target)
}
