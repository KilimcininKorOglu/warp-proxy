// Package warp owns the WARP tunnel lifecycle: identity registration, the
// MASQUE tunnel and the netstack dialer the proxies route through. It
// replaces the warp-cli driver; the external API is unchanged.
package warp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"warp-proxy/internal/masque"
)

// Reconnect modes.
const (
	ModeReconnect  = "reconnect"
	ModeReregister = "reregister"
)

// Manager keeps one WARP identity and its live tunnel. Dials are served by
// the current netstack dialer; reconnects swap the tunnel under a lock.
type Manager struct {
	stateDir string
	mode     string // ModeReconnect or ModeReregister

	// hook points for tests; nil means the real implementations.
	register IdentityFunc
	connect  ConnectFunc

	mu       sync.RWMutex
	tun      Tunnel
	dialer   Dialer
	endpoint string // pin override applied at the next (re)connect
	last     time.Time
}

// Tunnel is the piece of the MASQUE tunnel the manager needs: teardown.
type Tunnel interface {
	Close() error
}

// Dialer is the piece of the netstack the proxies need: the dial contract.
type Dialer interface {
	Dial(ctx context.Context, network, addr string) (net.Conn, error)
}

// IdentityFunc registers a fresh device identity (test hook).
type IdentityFunc = func(ctx context.Context) (*masque.Identity, error)

// ConnectFunc opens a tunnel for the identity (test hook).
type ConnectFunc = func(ctx context.Context, id *masque.Identity,
	endpoint string) (Tunnel, Dialer, error)

// NewManager builds a Manager persisting identity state under stateDir.
func NewManager(stateDir string, reconnectMode string) *Manager {
	m := &Manager{stateDir: stateDir}
	m.SetMode(reconnectMode)
	return m
}

// ReconnectMode reports the configured reconnect mode.
func (m *Manager) ReconnectMode() string { return m.mode }

// SetMode switches the reconnect mode at runtime; anything other than
// ModeReregister falls back to ModeReconnect.
func (m *Manager) SetMode(mode string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if mode != ModeReregister {
		mode = ModeReconnect
	}
	m.mode = mode
}

// LastReconnect reports the time of the last successful reconnect.
func (m *Manager) LastReconnect() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.last
}

// Dial routes a connection through the tunnel's netstack. It implements the
// proxy.Upstream dial contract.
func (m *Manager) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	m.mu.RLock()
	d := m.dialer
	m.mu.RUnlock()
	if d == nil {
		return nil, ErrNotConnected
	}
	return d.Dial(ctx, network, addr)
}

// EnsureReady makes the tunnel usable: load or register the identity, open
// the tunnel and start the netstack. An existing registration is kept.
func (m *Manager) EnsureReady(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.connectLocked(ctx, "")
}

// Reconnect obtains a fresh WARP tunnel using the configured mode.
func (m *Manager) Reconnect(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.mode == ModeReregister {
		if err := m.reregisterLocked(ctx); err != nil {
			return err
		}
	} else {
		if err := m.connectLocked(ctx, m.endpoint); err != nil {
			return err
		}
	}
	m.last = time.Now()
	return nil
}

// SetEndpoint pins the WARP tunnel to a custom edge endpoint ("host:port")
// and reconnects so the change takes effect.
func (m *Manager) SetEndpoint(ctx context.Context, endpoint string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.endpoint = endpoint
	if err := m.connectLocked(ctx, endpoint); err != nil {
		return err
	}
	m.last = time.Now()
	return nil
}

// Connected reports whether a tunnel is up.
func (m *Manager) Connected(_ context.Context) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.tun != nil, nil
}

// Status returns a one-line tunnel state for the panel dashboard.
func (m *Manager) Status(_ context.Context) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.tun == nil {
		return "disconnected", nil
	}
	ep := m.endpoint
	if ep == "" {
		ep = "default edge"
	}
	return fmt.Sprintf("connected (MASQUE, endpoint %s)", ep), nil
}

// connectLocked swaps in a fresh tunnel for the stored identity (registering
// first when none exists). The old tunnel, if any, is torn down.
func (m *Manager) connectLocked(ctx context.Context, endpoint string) error {
	id, err := m.identity(ctx)
	if err != nil {
		return err
	}
	tun, dialer, err := m.connectTunnel(ctx, id, endpoint)
	if err != nil {
		return err
	}
	m.swap(tun, dialer)
	return nil
}

// reregisterLocked deletes the old registration and starts over with a fresh
// identity.
func (m *Manager) reregisterLocked(ctx context.Context) error {
	if old, err := masque.LoadIdentity(m.stateDir); err == nil {
		// The fresh registration must not depend on the delete succeeding:
		// a failed delete only leaves the old device in the account list.
		delCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		_ = masque.NewClient().Delete(delCtx, old)
		cancel()
	}
	if err := os.Remove(m.stateDir + "/identity.json"); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove old identity: %w", err)
	}
	return m.connectLocked(ctx, m.endpoint)
}

// identity loads the stored identity or registers a fresh one, persisting it.
func (m *Manager) identity(ctx context.Context) (*masque.Identity, error) {
	if id, err := masque.LoadIdentity(m.stateDir); err == nil {
		return id, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("load identity: %w", err)
	}
	id, err := m.registerIdentity(ctx)
	if err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}
	if err := id.Save(m.stateDir); err != nil {
		return nil, fmt.Errorf("save identity: %w", err)
	}
	return id, nil
}

// registerIdentity registers through the real API, or through the test hook.
func (m *Manager) registerIdentity(ctx context.Context) (*masque.Identity, error) {
	if m.register != nil {
		return m.register(ctx)
	}
	return masque.RegisterAuto(ctx, masque.Options{Name: "warp-proxy"})
}

// swap installs the new tunnel and dialer, dropping the old ones.
func (m *Manager) swap(tun Tunnel, d Dialer) {
	if m.tun != nil {
		m.tun.Close()
	}
	m.tun = tun
	m.dialer = d
}

// connectTunnel is the real connect path, split out for test injection.
func (m *Manager) connectTunnel(ctx context.Context, id *masque.Identity,
	endpoint string) (Tunnel, Dialer, error) {
	if m.connect != nil {
		return m.connect(ctx, id, endpoint)
	}
	tun, err := masque.Dial(ctx, id, endpoint)
	if err != nil {
		return nil, nil, err
	}
	nd, err := masque.NewNetstackDialer(tun, id)
	if err != nil {
		tun.Close()
		return nil, nil, err
	}
	return tun, nd, nil
}

// SetHooks installs test doubles for registration and connecting. Nil hooks
// mean the real implementations; production code never calls this.
func (m *Manager) SetHooks(register IdentityFunc, connect ConnectFunc) {
	m.register = register
	m.connect = connect
}

// ErrNotConnected is returned when the tunnel should be up but is not.
var ErrNotConnected = errors.New("warp tunnel is not connected")
