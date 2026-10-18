package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMissingFileYieldsDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	def := Defaults()
	if cfg.HTTPProxy.Listen != def.HTTPProxy.Listen {
		t.Errorf("http listen = %q, want %q", cfg.HTTPProxy.Listen, def.HTTPProxy.Listen)
	}
	if cfg.Warp.StateDir != def.Warp.StateDir {
		t.Errorf("warp state dir = %q, want %q", cfg.Warp.StateDir, def.Warp.StateDir)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	cfg := Defaults()
	cfg.HTTPProxy.Listen = ":9999"
	cfg.Auth.Username = "kerem"

	if err := Save(path, cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.HTTPProxy.Listen != ":9999" || got.Auth.Username != "kerem" {
		t.Errorf("round trip lost values: %+v", got.HTTPProxy)
	}
}

func TestSaveIsAtomicAndLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	if err := Save(path, Defaults()); err != nil {
		t.Fatalf("Save: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("temp files left behind: %d entries", len(entries))
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("config perm = %o, want 600", perm)
	}
}

func TestParseDurationRejectsZeroAndNegative(t *testing.T) {
	if _, err := ParseDuration("0s"); err == nil {
		t.Error("zero duration accepted")
	}
	if _, err := ParseDuration("-5m"); err == nil {
		t.Error("negative duration accepted")
	}
	if d, err := ParseDuration("90s"); err != nil || d.Seconds() != 90 {
		t.Errorf("ParseDuration(90s) = %v, %v", d, err)
	}
}
