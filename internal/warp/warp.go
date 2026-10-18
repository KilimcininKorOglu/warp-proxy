// Package warp drives the official Cloudflare warp-cli binary:
// registration, proxy mode, connect, disconnect and reconnect.
package warp

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Reconnect modes.
const (
	ModeReconnect  = "reconnect"
	ModeReregister = "reregister"
)

// Manager runs warp-cli commands. Calls are serialized: warp-cli does not
// tolerate concurrent invocations well.
type Manager struct {
	binary    string
	prefix    []string
	reconnect string // ModeReconnect or ModeReregister

	mu   sync.Mutex
	last time.Time // last successful reconnect, zero if none
}

// NewManager builds a Manager. reconnectMode is one of the Mode constants;
// anything else falls back to ModeReconnect.
func NewManager(binary string, cliArgs []string, reconnectMode string) *Manager {
	mode := reconnectMode
	if mode != ModeReregister {
		mode = ModeReconnect
	}
	return &Manager{
		binary:    binary,
		prefix:    append([]string(nil), cliArgs...),
		reconnect: mode,
	}
}

// ReconnectMode reports the configured reconnect mode.
func (m *Manager) ReconnectMode() string { return m.reconnect }

// SetMode switches the reconnect mode at runtime; anything other than
// ModeReregister falls back to ModeReconnect.
func (m *Manager) SetMode(mode string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if mode != ModeReregister {
		mode = ModeReconnect
	}
	m.reconnect = mode
}

// LastReconnect reports the time of the last successful reconnect.
func (m *Manager) LastReconnect() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.last
}

// run executes warp-cli with the configured prefix plus args.
func (m *Manager) run(ctx context.Context, args ...string) (string, error) {
	full := append(append([]string(nil), m.prefix...), args...)
	cmd := exec.CommandContext(ctx, m.binary, full...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("warp-cli %s: %w: %s",
			strings.Join(full, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// Status returns the raw warp-cli status text.
func (m *Manager) Status(ctx context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.run(ctx, "status")
}

// Connected reports whether warp-cli reports a connected tunnel.
func (m *Manager) Connected(ctx context.Context) (bool, error) {
	out, err := m.Status(ctx)
	if err != nil {
		return false, err
	}
	return strings.Contains(strings.ToLower(out), "connected"), nil
}

// EnsureReady makes the tunnel usable: register if needed, switch to proxy
// mode and connect. An already registered client keeps its registration.
func (m *Manager) EnsureReady(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, err := m.run(ctx, "registration", "new"); err != nil {
		// Already registered (or the org blocks registration) is fine;
		// anything else stops startup.
		if !isAlreadyRegistered(err) {
			return fmt.Errorf("registration: %w", err)
		}
	}
	if _, err := m.run(ctx, "mode", "proxy"); err != nil {
		return fmt.Errorf("mode proxy: %w", err)
	}
	if _, err := m.run(ctx, "connect"); err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	return nil
}

// Reconnect obtains a fresh WARP address using the configured mode.
func (m *Manager) Reconnect(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var err error
	if m.reconnect == ModeReregister {
		err = m.reregister(ctx)
	} else {
		err = m.simpleReconnect(ctx)
	}
	if err != nil {
		return err
	}
	m.last = time.Now()
	return nil
}

func (m *Manager) simpleReconnect(ctx context.Context) error {
	// Best effort: disconnect may fail when the tunnel is already down,
	// which must not block the reconnect.
	_, _ = m.run(ctx, "disconnect")
	if _, err := m.run(ctx, "connect"); err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	return nil
}

func (m *Manager) reregister(ctx context.Context) error {
	// Best effort delete; a missing registration must not block.
	_, _ = m.run(ctx, "registration", "delete")
	if _, err := m.run(ctx, "registration", "new"); err != nil {
		if !isAlreadyRegistered(err) {
			return fmt.Errorf("registration new: %w", err)
		}
	}
	if _, err := m.run(ctx, "mode", "proxy"); err != nil {
		return fmt.Errorf("mode proxy: %w", err)
	}
	if _, err := m.run(ctx, "connect"); err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	return nil
}

// isAlreadyRegistered reports whether err is warp-cli telling us the client
// already has a registration.
func isAlreadyRegistered(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "already registered") ||
		strings.Contains(msg, "already exists")
}

// ErrNotConnected is returned when the tunnel should be up but is not.
var ErrNotConnected = errors.New("warp tunnel is not connected")
