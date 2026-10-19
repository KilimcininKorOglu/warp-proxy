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

	"warp-proxy/internal/bridge"
	"warp-proxy/internal/cleanip"
	"warp-proxy/internal/config"
	"warp-proxy/internal/front"
	"warp-proxy/internal/health"
	"warp-proxy/internal/logbuf"
	"warp-proxy/internal/proxy"
	"warp-proxy/internal/publicproxy"
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

	manager := warp.NewManager(cfg.Warp.StateDir, cfg.Warp.ReconnectMode,
		cfg.Warp.Accounts, cfg.Warp.Distribution)
	manager.SetIPv6Preference(cfg.Warp.IPv6Preference)
	upstream := &proxy.Upstream{DialFunc: manager.Dial, Resolve: manager.ResolveIP}

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
	checkerUpstream := &proxy.Upstream{DialFunc: manager.Dial}

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
	// then keep the periodic loop. EnsureReady has already run, so the
	// tunnel is up (or its failure was logged) by the time this starts.
	go func() {
		checker.RunOnce(ctx)
		checker.Loop(ctx, healthInterval(cfg))
	}()

	// In round-robin mode the fresh sessions often land on one shared
	// egress; run a bounded dedupe pass in the background so the pool
	// spreads across exit IPs. Every rotation goes through the limiter.
	go runStartupDedupe(ctx, manager, checker, logs)

	httpSrv := &proxy.HTTPServer{Upstream: upstream, Log: logger, OnRequest: logSink.request}
	socksSrv := &proxy.SOCKSServer{Upstream: upstream}

	// The public proxy pool: scraped lists, verified with real requests,
	// used by the bridge as the last-resort exit after WARP retries.
	pool := &publicproxy.Pool{}
	panelScan := make(chan struct{}, 1)
	go runPublicProxyPool(ctx, pool, panelScan, cfg, logs)

	panel := web.New()
	panel.PublicPool = pool
	panel.PublicScan = panelScan
	panel.ConfigPath = *configPath
	panel.GetConfig = func() *config.Config { return cfg }
	panel.SaveConfig = func(c *config.Config) error { return config.Save(*configPath, c) }
	panel.Checker = checker
	panel.Manager = manager
	panel.Logs = logs
	panel.Logger = logger
	panel.OnLiveConfigChange = func(c *config.Config) {
		manager.SetMode(c.Warp.ReconnectMode)
		manager.SetIPv6Preference(c.Warp.IPv6Preference)
		applyLimiter(c, checker)
	}
	panel.Scanner = func(ctx context.Context, c *config.Config) ([]cleanip.Result, error) {
		// MASQUE binds a registration to its home edge: scan the home
		// edge's service ports instead of random Cloudflare addresses.
		var results []cleanip.Result
		var err error
		if host, ports, ok := manager.HomeEdge(); ok {
			timeout := 2 * time.Second
			if d, perr := config.ParseDuration(c.CleanIP.Timeout); perr == nil {
				timeout = d
			}
			results = cleanip.ScanHostPorts(ctx, host, ports, timeout, c.CleanIP.Top)
		} else {
			results, err = web.RunScan(ctx, c)
		}
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

	errCh := make(chan error, 4)
	go func() { errCh <- http.Serve(lnPanel, panel.Handler()) }()
	go func() { errCh <- httpSrv.Serve(lnHTTP) }()
	go func() { errCh <- socksSrv.Serve(lnSOCKS) }()

	if cfg.Bridge.Enabled {
		startBridge(errCh, cfg, checker, checkerUpstream, pool, logs, logger)
	}

	logger.Info("warp-proxy started",
		"panel", cfg.Panel.Listen,
		"http_proxy", cfg.HTTPProxy.Listen,
		"socks", cfg.SOCKS.Listen,
		"bridge", cfg.Bridge.Listen,
		"state_dir", cfg.Warp.StateDir)

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

// startBridge runs the OpenAI-compatible bridge listener with the public
// proxy fallback attached; a listener failure is fatal.
func startBridge(errCh chan error, cfg *config.Config, checker *health.Checker,
	upstream *proxy.Upstream, pool *publicproxy.Pool, logs *logbuf.Buffer,
	logger *slog.Logger) {
	srv := bridge.New(upstream, logs, logger,
		checker.ManualReconnect, func() config.BridgeConfig { return cfg.Bridge })
	srv.Public = func(_ context.Context) *http.Transport {
		if !cfg.PublicProxy.Enabled {
			return nil
		}
		return pool.Transport()
	}
	ln, err := net.Listen("tcp", cfg.Bridge.Listen)
	if err != nil {
		logger.Error("bridge listen failed", "addr", cfg.Bridge.Listen, "err", err)
		os.Exit(1)
	}
	go func() { errCh <- http.Serve(ln, srv) }()
}

// runPublicProxyPool refreshes the scraped public proxy pool on its
// configured interval and on panel scan requests, until ctx ends.
func runPublicProxyPool(ctx context.Context, pool *publicproxy.Pool,
	panelScan <-chan struct{}, cfg *config.Config, logs *logbuf.Buffer) {
	if !cfg.PublicProxy.Enabled {
		return
	}
	scan := func() {
		c := cfg.PublicProxy
		seen, kept := pool.Refresh(ctx, c.Sources, c.CheckURL, c.TimeoutDur(),
			c.Max, c.Workers, func(f string, a ...any) {
				logs.Add("info", "publicproxy", f, a...)
			})
		if kept > 0 {
			logs.Add("info", "publicproxy", "pool refreshed: %d/%d proxies verified", kept, seen)
		} else {
			logs.Add("warn", "publicproxy", "pool empty after scan (%d candidates)", seen)
		}
	}
	scan()
	ticker := time.NewTicker(cfg.PublicProxy.IntervalDur())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			scan()
		case <-panelScan:
			scan()
		}
	}
}

// runStartupDedupe evens out the round-robin pool's exit IPs once after
// startup, rotating through the shared rate limiter. It is a no-op in the
// other distribution modes.
func runStartupDedupe(ctx context.Context, manager *warp.Manager,
	checker *health.Checker, logs *logbuf.Buffer) {
	if manager.Distribution() != warp.DistributionRoundRobin {
		return
	}
	gate := &warp.RotationGate{
		Allow:  func() bool { return checker.AllowReconnect().Allowed },
		Record: checker.RecordReconnect,
	}
	n, err := manager.DedupeEgress(ctx, 2, gate)
	if err != nil {
		logs.Add("warn", "warp", "startup egress dedupe failed: %v", err)
	} else if n > 0 {
		logs.Add("info", "warp", "startup egress dedupe rotated %d tunnels", n)
	}
}

// logSink adapts proxy requests into the panel ring buffer.
type logSink struct {
	logs *logbuf.Buffer
}

func (s *logSink) request(kind, client, target string) {
	s.logs.Add("info", "request", "%s %s -> %s", kind, client, target)
}
