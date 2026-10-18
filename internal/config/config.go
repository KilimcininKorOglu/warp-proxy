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
	Panel     PanelConfig     `yaml:"panel"`
	HTTPProxy ListenerConfig  `yaml:"http_proxy"`
	SOCKS     ListenerConfig  `yaml:"socks_proxy"`
	Warp      WarpConfig      `yaml:"warp"`
	Health    HealthConfig    `yaml:"health"`
	Reconnect ReconnectConfig `yaml:"reconnect"`
	Auth      AuthConfig      `yaml:"auth"`
}

// PanelConfig configures the web panel listener.
type PanelConfig struct {
	Listen string `yaml:"listen"`
}

// ListenerConfig configures one proxy listener.
type ListenerConfig struct {
	Listen string `yaml:"listen"`
}

// WarpConfig describes how to drive the warp-cli binary and where its
// local proxy listens.
type WarpConfig struct {
	// Binary is the warp-cli executable path or name.
	Binary string `yaml:"binary"`
	// CLIArgs is an optional prefix applied to every warp-cli call,
	// for example ["--accept-tos"] on older client versions.
	CLIArgs []string `yaml:"cli_args"`
	// ProxyAddr is the local proxy warp-cli opens in proxy mode.
	ProxyAddr string `yaml:"proxy_addr"`
	// ReconnectMode is "reconnect" (disconnect+connect) or
	// "reregister" (delete registration, register again, connect).
	ReconnectMode string `yaml:"reconnect_mode"`
}

// HealthConfig configures the periodic health check through the WARP proxy.
type HealthConfig struct {
	Enabled  bool     `yaml:"enabled"`
	Interval string   `yaml:"interval"`
	Timeout  string   `yaml:"timeout"`
	URL      string   `yaml:"url"`
	// TraceURL is fetched through the proxy to read the exit IP and the
	// warp=on flag. Empty disables the IP readout.
	TraceURL   string   `yaml:"trace_url"`
	BotMarkers []string `yaml:"bot_markers"`
}

// ReconnectConfig rate-limits automatic and manual reconnects.
type ReconnectConfig struct {
	MinInterval         string `yaml:"min_interval"`
	MaxConsecutive      int    `yaml:"max_consecutive"`
	CooldownAfterBurst  string `yaml:"cooldown_after_burst"`
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
			Binary: "warp-cli",
			// Non-interactive environments must accept the ToS flag.
			CLIArgs:       []string{"--accept-tos"},
			ProxyAddr:     "127.0.0.1:40000",
			ReconnectMode: "reconnect",
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
		Auth: AuthConfig{Username: "admin"},
	}
}

// Load reads the configuration from path. A missing file yields Defaults.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
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
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
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
