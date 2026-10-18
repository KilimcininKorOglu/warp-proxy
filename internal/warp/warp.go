// Package warp owns the WARP tunnel lifecycle: identity registration, the
// MASQUE tunnels and the netstack dialers the proxies route through. It
// replaces the warp-cli driver and supports a multi-account pool.
package warp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"warp-proxy/internal/masque"
)

// Reconnect modes.
const (
	ModeReconnect  = "reconnect"
	ModeReregister = "reregister"
)

// Tunnel is the piece of the MASQUE tunnel the manager needs: teardown.
type Tunnel interface {
	Close() error
}

// Dialer is the piece of the netstack the proxies need: the dial contract
// plus remote resolution.
type Dialer interface {
	Dial(ctx context.Context, network, addr string) (net.Conn, error)
	Resolve(ctx context.Context, host string) (net.IP, error)
}

// IdentityFunc registers a fresh device identity (test hook).
type IdentityFunc = func(ctx context.Context) (*masque.Identity, error)

// ConnectFunc opens a tunnel for the identity (test hook).
type ConnectFunc = func(ctx context.Context, id *masque.Identity,
	endpoint string) (Tunnel, Dialer, error)

// worker is one account's live tunnel.
type worker struct {
	index int
	id    *masque.Identity
	tun   Tunnel
	d     Dialer
}

// Manager keeps a pool of WARP identities and their live tunnels. With one
// account it behaves exactly like a single tunnel; with more, dials rotate
// round-robin across the healthy workers and Reconnect rotates to the next
// worker instead of bouncing the active one.
type Manager struct {
	stateDir string
	accounts int
	mode     string // ModeReconnect or ModeReregister

	// hook points for tests; nil means the real implementations.
	register IdentityFunc
	connect  ConnectFunc

	mu       sync.RWMutex
	workers  []*worker
	rr       atomic.Uint64
	endpoint string // pin override applied at the next (re)connect
	last     time.Time
}

// NewManager builds a Manager persisting identity state under stateDir and
// maintaining accounts tunnels.
func NewManager(stateDir string, reconnectMode string, accounts int) *Manager {
	if accounts < 1 {
		accounts = 1
	}
	m := &Manager{stateDir: stateDir, accounts: accounts}
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

// Dial routes a connection through a healthy tunnel's netstack,
// round-robin across the pool. It implements the proxy.Upstream contract.
func (m *Manager) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	d, err := m.pickDialer()
	if err != nil {
		return nil, err
	}
	return d.Dial(ctx, network, addr)
}

// ResolveIP resolves a hostname through the tunnel's remote DNS.
func (m *Manager) ResolveIP(ctx context.Context, host string) (net.IP, error) {
	m.mu.RLock()
	var d Dialer
	if len(m.workers) > 0 {
		d = m.workers[0].d
	}
	m.mu.RUnlock()
	if d == nil {
		return nil, ErrNotConnected
	}
	ip, rerr := d.Resolve(ctx, host)
	if rerr != nil {
		return nil, fmt.Errorf("dns: %w", rerr)
	}
	return ip, nil
}

// pickDialer returns the dialer of the next healthy worker, scanning the
// pool once from the round-robin position.
func (m *Manager) pickDialer() (Dialer, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := len(m.workers)
	if n == 0 {
		return nil, ErrNotConnected
	}
	start := int(m.rr.Add(1)) % n
	for i := 0; i < n; i++ {
		w := m.workers[(start+i)%n]
		if w != nil && w.d != nil {
			return w.d, nil
		}
	}
	return nil, ErrNotConnected
}

// EnsureReady brings the pool up: one tunnel per configured account, keeping
// existing registrations. Failure of some workers is tolerated as long as
// at least one comes up.
func (m *Manager) EnsureReady(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.bringUpLocked(ctx, m.endpoint)
}

// Reconnect refreshes the pool. With a single account it re-establishes the
// tunnel (reregister mode deletes the registration first). With a pool it
// rotates the round-robin to the next worker for instant egress change and
// heals the abandoned worker in the background.
func (m *Manager) Reconnect(ctx context.Context) error {
	if m.poolSize() > 1 {
		return m.rotate(ctx)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mode == ModeReregister {
		if err := m.reregisterLocked(ctx, 0); err != nil {
			return err
		}
	} else {
		if err := m.connectLocked(ctx, 0, m.endpoint); err != nil {
			return err
		}
	}
	m.last = time.Now()
	return nil
}

// SetEndpoint pins the tunnels to a custom edge endpoint ("host:port") and
// reconnects every worker so the change takes effect.
func (m *Manager) SetEndpoint(ctx context.Context, endpoint string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.endpoint = endpoint
	for i := range m.workers {
		if err := m.connectLocked(ctx, i, endpoint); err != nil {
			return err
		}
	}
	m.last = time.Now()
	return nil
}

// rotate advances the round-robin pointer and refreshes the abandoned
// worker in the background, so the next dial lands on a ready tunnel while
// the old one regains a fresh IP.
func (m *Manager) rotate(ctx context.Context) error {
	m.mu.RLock()
	n := len(m.workers)
	m.mu.RUnlock()
	if n == 0 {
		return ErrNotConnected
	}
	abandoned := int(m.rr.Add(1)) % n
	m.last = time.Now()

	go func() {
		hctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.mode == ModeReregister {
			_ = m.reregisterLocked(hctx, abandoned)
		} else {
			_ = m.connectLocked(hctx, abandoned, m.endpoint)
		}
	}()
	return nil
}

// Connected reports whether at least one tunnel is up.
func (m *Manager) Connected(_ context.Context) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, w := range m.workers {
		if w != nil && w.d != nil {
			return true, nil
		}
	}
	return false, nil
}

// Status returns a one-line tunnel state for the panel dashboard.
func (m *Manager) Status(_ context.Context) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	up := 0
	for _, w := range m.workers {
		if w != nil && w.d != nil {
			up++
		}
	}
	if up == 0 {
		return "disconnected", nil
	}
	ep := m.endpoint
	if ep == "" {
		ep = "default edge"
	}
	if len(m.workers) == 1 {
		return fmt.Sprintf("connected (MASQUE, endpoint %s)", ep), nil
	}
	return fmt.Sprintf("connected (MASQUE, %d/%d workers round-robin, endpoint %s)",
		up, len(m.workers), ep), nil
}

// bringUpLocked ensures every configured account has a tunnel, keeping the
// workers that are already up. It fails only when none could be started.
func (m *Manager) bringUpLocked(ctx context.Context, endpoint string) error {
	if len(m.workers) == 0 {
		m.workers = make([]*worker, m.accounts)
		for i := range m.workers {
			m.workers[i] = &worker{index: i}
		}
	}
	var firstErr error
	raised := 0
	for i, w := range m.workers {
		if w.d != nil {
			raised++
			continue
		}
		if err := m.connectLocked(ctx, i, endpoint); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		raised++
		// Space fresh registrations out; the API rate-limits bursts.
		if i+1 < len(m.workers) {
			time.Sleep(time.Second)
		}
	}
	if raised == 0 {
		return firstErr
	}
	return nil
}

// connectLocked (re)establishes worker i's tunnel for its stored identity.
func (m *Manager) connectLocked(ctx context.Context, i int, endpoint string) error {
	m.ensureWorkersLocked()
	id, err := m.identity(ctx, i)
	if err != nil {
		return err
	}
	tun, d, err := m.connectTunnel(ctx, id, endpoint)
	if err != nil {
		return err
	}
	m.swap(i, tun, d)
	return nil
}

// ensureWorkersLocked allocates the worker slots when missing, so a
// Reconnect before EnsureReady cannot index an empty pool.
func (m *Manager) ensureWorkersLocked() {
	if len(m.workers) == 0 {
		m.workers = make([]*worker, m.accounts)
		for i := range m.workers {
			m.workers[i] = &worker{index: i}
		}
	}
}

// reregisterLocked deletes worker i's registration and starts over with a
// fresh identity.
func (m *Manager) reregisterLocked(ctx context.Context, i int) error {
	if old, err := masque.LoadIdentityAt(m.identityPath(i)); err == nil {
		// The fresh registration must not depend on the delete succeeding:
		// a failed delete only leaves the old device in the account list.
		delCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		_ = masque.NewClient().Delete(delCtx, old)
		cancel()
	}
	if err := os.Remove(m.identityPath(i)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove old identity: %w", err)
	}
	return m.connectLocked(ctx, i, m.endpoint)
}

// identityPath is worker i's state file. Worker 0 keeps the historical
// identity.json name so single-account state survives the upgrade.
func (m *Manager) identityPath(i int) string {
	if i == 0 {
		return m.stateDir + "/identity.json"
	}
	return m.stateDir + "/acc-" + strconv.Itoa(i) + ".json"
}

// identity loads worker i's stored identity or registers a fresh one.
func (m *Manager) identity(ctx context.Context, i int) (*masque.Identity, error) {
	path := m.identityPath(i)
	if id, err := masque.LoadIdentityAt(path); err == nil {
		return id, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("load identity: %w", err)
	}
	id, err := m.registerIdentity(ctx)
	if err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}
	if err := id.SaveAt(path); err != nil {
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

// swap installs worker i's new tunnel and dialer, dropping the old ones.
func (m *Manager) swap(i int, tun Tunnel, d Dialer) {
	w := m.workers[i]
	if w.tun != nil {
		w.tun.Close()
	}
	w.tun = tun
	w.d = d
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

// poolSize reports the configured account count.
func (m *Manager) poolSize() int {
	if m.accounts < 1 {
		return 1
	}
	return m.accounts
}

// ErrNotConnected is returned when the tunnel should be up but is not.
var ErrNotConnected = errors.New("warp tunnel is not connected")
