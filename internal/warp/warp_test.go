package warp

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeMockCLI installs a shell script that records every invocation into
// calls.log and answers from the given status text.
func writeMockCLI(t *testing.T, statusText string) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "warp-cli")
	body := "#!/bin/sh\necho \"$@\" >> " + dir + "/calls.log\n" +
		"if [ \"$1\" = \"status\" ]; then echo " + statusText + "; exit 0; fi\n" +
		"exit 0\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatalf("write mock cli: %v", err)
	}
	return dir
}

func calls(t *testing.T, dir string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "calls.log"))
	if err != nil {
		t.Fatalf("read calls: %v", err)
	}
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

func TestEnsureReadyRegistersOnceAndConnects(t *testing.T) {
	dir := writeMockCLI(t, "Status: Connected")
	m := NewManager(filepath.Join(dir, "warp-cli"), nil, ModeReconnect)

	ctx := context.Background()
	if err := m.EnsureReady(ctx); err != nil {
		t.Fatalf("EnsureReady: %v", err)
	}
	if ok, err := m.Connected(ctx); err != nil || !ok {
		t.Errorf("Connected = %v, %v; want true", ok, err)
	}
	got := calls(t, dir)
	want := []string{
		"registration new", "mode proxy", "connect", "status",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("calls = %v, want %v", got, want)
	}
}

func TestEnsureReadyToleratesAlreadyRegistered(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "warp-cli")
	body := "#!/bin/sh\n" +
		"if [ \"$1\" = \"registration\" ] && [ \"$2\" = \"new\" ]; then\n" +
		"  echo 'Error: Already registered' >&2; exit 1; fi\n" +
		"exit 0\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}
	m := NewManager(script, nil, ModeReconnect)
	if err := m.EnsureReady(context.Background()); err != nil {
		t.Errorf("EnsureReady with already-registered: %v", err)
	}
}

func TestReconnectModeDisconnectConnect(t *testing.T) {
	dir := writeMockCLI(t, "Status: Connected")
	m := NewManager(filepath.Join(dir, "warp-cli"), nil, ModeReconnect)

	if err := m.Reconnect(context.Background()); err != nil {
		t.Fatalf("Reconnect: %v", err)
	}
	got := calls(t, dir)
	if strings.Join(got, "|") != "disconnect|connect" {
		t.Errorf("calls = %v, want [disconnect connect]", got)
	}
	if m.LastReconnect().IsZero() {
		t.Error("LastReconnect not recorded")
	}
}

func TestReconnectModeReregister(t *testing.T) {
	dir := writeMockCLI(t, "Status: Connected")
	m := NewManager(filepath.Join(dir, "warp-cli"), nil, ModeReregister)

	if err := m.Reconnect(context.Background()); err != nil {
		t.Fatalf("Reconnect: %v", err)
	}
	got := calls(t, dir)
	want := "registration delete|registration new|mode proxy|connect"
	if strings.Join(got, "|") != want {
		t.Errorf("calls = %v, want %v", got, want)
	}
}

func TestCLIArgsPrefix(t *testing.T) {
	dir := writeMockCLI(t, "Status: Disconnected")
	m := NewManager(filepath.Join(dir, "warp-cli"), []string{"--accept-tos"}, ModeReconnect)

	if _, err := m.Status(context.Background()); err != nil {
		t.Fatalf("Status: %v", err)
	}
	got := calls(t, dir)
	if got[0] != "--accept-tos status" {
		t.Errorf("call = %q, want %q", got[0], "--accept-tos status")
	}
}

func TestInvalidModeFallsBackToReconnect(t *testing.T) {
	m := NewManager("warp-cli", nil, "bogus")
	if m.ReconnectMode() != ModeReconnect {
		t.Errorf("mode = %q, want %q", m.ReconnectMode(), ModeReconnect)
	}
}

func TestLastReconnectConcurrency(t *testing.T) {
	dir := writeMockCLI(t, "Status: Connected")
	m := NewManager(filepath.Join(dir, "warp-cli"), nil, ModeReconnect)
	done := make(chan struct{})
	go func() {
		_ = m.LastReconnect()
		close(done)
	}()
	_ = m.Reconnect(context.Background())
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("LastReconnect deadlocked against Reconnect")
	}
}
