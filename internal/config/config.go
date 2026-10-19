// Package config loads and saves the warp-proxy YAML configuration.
// Every save is atomic: write to a temp file, fsync, rename over the target.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the full application configuration. All durations are stored as
// strings so the YAML stays human friendly (for example "60s").
type Config struct {
	Panel       PanelConfig       `yaml:"panel"`
	HTTPProxy   ListenerConfig    `yaml:"http_proxy"`
	SOCKS       ListenerConfig    `yaml:"socks_proxy"`
	Warp        WarpConfig        `yaml:"warp"`
	Health      HealthConfig      `yaml:"health"`
	Reconnect   ReconnectConfig   `yaml:"reconnect"`
	CleanIP     CleanIPConfig     `yaml:"cleanip"`
	Front       FrontConfig       `yaml:"front"`
	Bridge      BridgeConfig      `yaml:"bridge"`
	PublicProxy PublicProxyConfig `yaml:"public_proxy"`
	Auth        AuthConfig        `yaml:"auth"`
}

// BridgeConfig configures the OpenAI-compatible AI bridge listener. A
// configured retry status is replayed: a 429 whose body is a
// FreeUsageLimitError rotates the WARP exit IP first, while any other
// retryable status is retried on the same IP after Retry-After.
type BridgeConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Listen   string `yaml:"listen"`
	Upstream string `yaml:"upstream"`
	// RetryStatuses lists the upstream status codes eligible for a replay.
	RetryStatuses []int  `yaml:"retry_statuses"`
	RetryAttempts int    `yaml:"retry_attempts"`
	MaxConcurrent int    `yaml:"max_concurrent"`
	MinInterval   string `yaml:"min_interval"`
	Timeout       string `yaml:"timeout"`
	// InjectSession adds the OpenCode free-tier identity to upstream
	// requests that do not already carry it: the X-Opencode-Session and
	// X-Opencode-Request headers, an opencode User-Agent, and stub tool
	// entries. Values sent by the client are respected.
	InjectSession bool `yaml:"inject_session"`
	// RotateSessionOnRetry refreshes the OpenCode session and request ids
	// after a WARP rotation, overriding values the client sent, so a
	// replayed request carries a fresh identity. It trades prompt-cache
	// affinity on the replayed request for a new session bucket.
	RotateSessionOnRetry bool `yaml:"rotate_session_on_retry"`
}

// TimeoutDur parses the configured upstream timeout.
func (b BridgeConfig) TimeoutDur() time.Duration {
	d, err := time.ParseDuration(b.Timeout)
	if err != nil || d <= 0 {
		return 120 * time.Second
	}
	return d
}

// MinIntervalDur parses the configured minimum spacing between upstream
// calls.
func (b BridgeConfig) MinIntervalDur() time.Duration {
	d, err := time.ParseDuration(b.MinInterval)
	if err != nil || d < 0 {
		return 0
	}
	return d
}

// FrontConfig configures Cloudflare front-IP rewriting for proxied
// traffic.
type FrontConfig struct {
	Enabled         bool     `yaml:"enabled"`
	Domains         []string `yaml:"domains"`
	ResolveCacheTTL string   `yaml:"resolve_cache_ttl"`
}

// CleanIPConfig configures the Cloudflare edge latency scanner.
type CleanIPConfig struct {
	Port            int    `yaml:"port"`
	SamplesPerRange int    `yaml:"samples_per_range"`
	Workers         int    `yaml:"workers"`
	Timeout         string `yaml:"timeout"`
	Top             int    `yaml:"top"`
}

// PanelConfig configures the web panel listener.
type PanelConfig struct {
	Listen string `yaml:"listen"`
}

// ListenerConfig configures one proxy listener.
type ListenerConfig struct {
	Listen string `yaml:"listen"`
}

// WarpConfig describes the built-in MASQUE tunnel.
type WarpConfig struct {
	// StateDir holds the device identities. Persisted across restarts.
	StateDir string `yaml:"state_dir"`
	// Accounts is the multi-account pool size. 1 means a single tunnel;
	// more enables round-robin egress rotation across accounts.
	Accounts int `yaml:"accounts"`
	// ReconnectMode is "reconnect" (close and reopen the tunnel) or
	// "reregister" (delete registration, register again, connect).
	ReconnectMode string `yaml:"reconnect_mode"`
	// Distribution is "off" (one active tunnel, rotation on reconnect) or
	// "round-robin" (every account keeps a live tunnel and requests
	// spread across them per request). Needs a restart to change.
	Distribution string `yaml:"distribution"`
	// IPv6Preference is "off" (resolve A only), "prefer" (AAAA first,
	// fallback A) or "only" (AAAA only) for hostname resolution inside
	// the tunnel. Applies live.
	IPv6Preference string `yaml:"ipv6_preference"`
}

// HealthConfig configures the periodic health check through the WARP proxy.
type HealthConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Interval string `yaml:"interval"`
	Timeout  string `yaml:"timeout"`
	URL      string `yaml:"url"`
	// TraceURL is fetched through the proxy to read the exit IP and the
	// warp=on flag. Empty disables the IP readout.
	TraceURL   string   `yaml:"trace_url"`
	BotMarkers []string `yaml:"bot_markers"`
}

// PublicProxyConfig configures the scraped public proxy fallback pool.
type PublicProxyConfig struct {
	// Enabled turns the pool and the bridge fallback on.
	Enabled bool `yaml:"enabled"`
	// Interval is how often the sources are rescanned.
	Interval string `yaml:"interval"`
	// Max caps the verified pool size (fastest kept).
	Max int `yaml:"max"`
	// Workers bounds the concurrent check goroutines.
	Workers int `yaml:"workers"`
	// Timeout bounds each fetch and each check request.
	Timeout string `yaml:"timeout"`
	// CheckURL is fetched through every candidate; its ip= line names the
	// exit address.
	CheckURL string `yaml:"check_url"`
	// Sources are the list URLs to scrape.
	Sources []string `yaml:"sources"`
}

// IntervalDur parses Interval with a 30m default.
func (c PublicProxyConfig) IntervalDur() time.Duration {
	d, err := ParseDuration(c.Interval)
	if err != nil || d <= 0 {
		return 30 * time.Minute
	}
	return d
}

// TimeoutDur parses Timeout with a 10s default.
func (c PublicProxyConfig) TimeoutDur() time.Duration {
	d, err := ParseDuration(c.Timeout)
	if err != nil || d <= 0 {
		return 10 * time.Second
	}
	return d
}

// ReconnectConfig rate-limits automatic and manual reconnects.
type ReconnectConfig struct {
	MinInterval        string `yaml:"min_interval"`
	MaxConsecutive     int    `yaml:"max_consecutive"`
	CooldownAfterBurst string `yaml:"cooldown_after_burst"`
}

// AuthConfig holds the panel credentials.
type AuthConfig struct {
	Username     string `yaml:"username"`
	PasswordHash string `yaml:"password_hash"`
}

// Defaults returns the built-in configuration with generic health-check
// targets. The deployment defaults for listeners match the assigned port
// block 8590-8599.
func Defaults() *Config {
	return &Config{
		Panel:     PanelConfig{Listen: ":8590"},
		HTTPProxy: ListenerConfig{Listen: ":8591"},
		SOCKS:     ListenerConfig{Listen: ":8592"},
		Warp: WarpConfig{
			StateDir:       "state",
			Accounts:       1,
			ReconnectMode:  "reconnect",
			Distribution:   "off",
			IPv6Preference: "off",
		},
		Health: HealthConfig{
			Enabled:  true,
			Interval: "5m",
			Timeout:  "30s",
			URL:      "https://www.cloudflare.com/cdn-cgi/trace",
			TraceURL: "https://www.cloudflare.com/cdn-cgi/trace",
			BotMarkers: []string{
				"Sign in to confirm you're not a bot",
			},
		},
		Reconnect: ReconnectConfig{
			MinInterval:        "60s",
			MaxConsecutive:     5,
			CooldownAfterBurst: "10m",
		},
		CleanIP: CleanIPConfig{
			Port:            443,
			SamplesPerRange: 4,
			Workers:         50,
			Timeout:         "2s",
			Top:             20,
		},
		Front: FrontConfig{
			Enabled:         false,
			ResolveCacheTTL: "10m",
		},
		Bridge: BridgeConfig{
			Enabled:              true,
			Listen:               ":8593",
			Upstream:             "https://opencode.ai/zen",
			RetryStatuses:        []int{429},
			RetryAttempts:        1,
			MaxConcurrent:        3,
			MinInterval:          "0.5s",
			Timeout:              "120s",
			InjectSession:        true,
			RotateSessionOnRetry: true,
		},
		PublicProxy: PublicProxyConfig{
			Enabled:  true,
			Interval: "30m",
			Max:      100,
			Workers:  100,
			Timeout:  "10s",
			CheckURL: "http://www.cloudflare.com/cdn-cgi/trace",
			Sources: []string{
				"https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
				"https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
				"https://sunny9577.github.io/proxy-scraper/generated/socks5_proxies.txt",
				"https://sunny9577.github.io/proxy-scraper/generated/http_proxies.txt",
				"https://raw.githubusercontent.com/berkay-digital/Proxy-Scraper/main/proxies.txt",
			},
		},
		Auth: AuthConfig{Username: "admin"},
	}
}

// Load reads the configuration from path. A missing file yields Defaults.
func Load(path string) (*Config, error) {
	// The path comes from the -config flag, not from request input.
	data, err := os.ReadFile(path) // #nosec G304
	if errors.Is(err, os.ErrNotExist) {
		return Defaults(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg := Defaults()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}

// Save writes the configuration to path atomically: temp file in the same
// directory, fsync, rename over the target.
func Save(path string, cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".warp-proxy-config-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) //nolint:errcheck // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("fsync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename config: %w", err)
	}
	return nil
}

// ParseDuration parses one of the configured duration strings.
func ParseDuration(v string) (time.Duration, error) {
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("parse duration %q: %w", v, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("duration %q must be positive", v)
	}
	return d, nil
}
