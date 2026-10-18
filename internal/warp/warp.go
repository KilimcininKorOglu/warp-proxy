// Package warp owns the WARP tunnel lifecycle: identity registration, the
// MASQUE tunnels and the netstack dialers the proxies route through. It
// replaces the warp-cli driver and supports a multi-account pool.
package warp

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
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

// worker is one account: a stored identity plus, when active, its tunnel.
type worker struct {
	index int
	id    *masque.Identity
	tun   Tunnel
	d     Dialer
}

// Manager keeps a pool of WARP identities. Exactly one identity's tunnel is
// active at a time: Cloudflare keys the WARP egress IP on the client host
// and hands each NEW tunnel session the next egress, so simultaneous
// tunnels would all share one IP. Rotation therefore means opening the next
// identity's fresh session and closing the old tunnel afterwards — a new
// egress without re-registration. With one account it behaves like a single
// tunnel.
type Manager struct {
	stateDir string
	accounts int
	mode     string // ModeReconnect or ModeReregister

	// hook points for tests; nil means the real implementations.
	register IdentityFunc
	connect  ConnectFunc

	mu       sync.RWMutex
	workers  []*worker
	active   int    // the worker owning the live tunnel
	endpoint string // pin override applied at the next (re)connect
	last     time.Time
}

// NewManager builds a Manager persisting identity state under stateDir and
// rotating across accounts accounts.
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

// Dial routes a connection through the active tunnel's netstack. It
// implements the proxy.Upstream contract.
func (m *Manager) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	w, err := m.activeWorker()
	if err != nil {
		return nil, err
	}
	return w.d.Dial(ctx, network, addr)
}

// ResolveIP resolves a hostname through the active tunnel's remote DNS.
func (m *Manager) ResolveIP(ctx context.Context, host string) (net.IP, error) {
	w, werr := m.activeWorker()
	if w == nil || werr != nil {
		return nil, ErrNotConnected
	}
	ip, rerr := w.d.Resolve(ctx, host)
	return ip, wrapResolve(host, ip, rerr)
}

// wrapResolve annotates a resolver failure with the queried host.
func wrapResolve(host string, ip net.IP, err error) error {
	if err == nil && ip == nil {
		return fmt.Errorf("dns: no address for %s", host)
	}
	if err != nil {
		return fmt.Errorf("dns: %w", err)
	}
	return nil
}

// EnsureReady brings the active account's tunnel up, keeping existing
// registrations and a tunnel that is already live.
func (m *Manager) EnsureReady(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensureWorkersLocked()
	if m.activeWorkerLocked() != nil {
		return nil
	}
	return m.connectLocked(ctx, m.active, m.endpoint)
}

// Reconnect refreshes the egress. With a single account it re-establishes
// the tunnel (reregister mode deletes the registration first). With a pool
// it opens the next identity's fresh session — which Cloudflare answers
// with the next egress IP — and closes the previous tunnel only after the
// new one is up, so a failed rotation keeps the old egress working.
func (m *Manager) Reconnect(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	next := m.active
	if m.poolSize() > 1 {
		next = (m.active + 1) % m.poolSize()
	}
	if err := m.connectLocked(ctx, next, m.endpoint); err != nil {
		return err
	}
	if next != m.active {
		// nils tear the old tunnel down; the identity file stays.
		m.swap(m.active, nil, nil)
		m.active = next
	}
	m.last = time.Now()
	return nil
}

// SetEndpoint pins the tunnel to a custom edge endpoint ("host:port") and
// reconnects the active account so the change takes effect.
func (m *Manager) SetEndpoint(ctx context.Context, endpoint string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.endpoint = endpoint
	if err := m.connectLocked(ctx, m.active, endpoint); err != nil {
		return err
	}
	m.last = time.Now()
	return nil
}

// Connected reports whether the active tunnel is up.
func (m *Manager) Connected(_ context.Context) (bool, error) {
	_, err := m.activeWorker()
	return err == nil, nil
}

// Status returns a one-line tunnel state for the panel dashboard.
func (m *Manager) Status(_ context.Context) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.activeWorkerLocked() == nil {
		return "disconnected", nil
	}
	ep := m.endpoint
	if ep == "" {
		ep = "default edge"
	}
	if m.poolSize() == 1 {
		return fmt.Sprintf("connected (MASQUE, endpoint %s)", ep), nil
	}
	return fmt.Sprintf("connected (MASQUE, account %d/%d, endpoint %s)",
		m.active+1, m.poolSize(), ep), nil
}

// activeWorker returns the worker that owns the live tunnel.
func (m *Manager) activeWorker() (*worker, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if w := m.activeWorkerLocked(); w != nil {
		return w, nil
	}
	return nil, ErrNotConnected
}

// activeWorkerLocked is activeWorker without locking.
func (m *Manager) activeWorkerLocked() *worker {
	if m.active < len(m.workers) {
		if w := m.workers[m.active]; w != nil && w.d != nil {
			return w
		}
	}
	// Any live tunnel counts: the active index can lag a failed rotation.
	for _, w := range m.workers {
		if w != nil && w.d != nil {
			return w
		}
	}
	return nil
}

// bringUpLocked ensures the active account has a tunnel. Other accounts
// keep only their identity files; their tunnels open on rotation.
func (m *Manager) bringUpLocked(ctx context.Context, endpoint string) error {
	m.ensureWorkersLocked()
	return m.connectLocked(ctx, m.active, endpoint)
}

// ensureWorkersLocked allocates the worker slots when missing, so a
// Reconnect before EnsureReady cannot index an empty pool.
func (m *Manager) ensureWorkersLocked() {
	if len(m.workers) == 0 {
		m.workers = make([]*worker, m.poolSize())
		for i := range m.workers {
			m.workers[i] = &worker{index: i}
		}
	}
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

// h2Debug logs pool decisions when MASQUE_DEBUG=1.
func h2Debug(format string, args ...any) {
	if os.Getenv("MASQUE_DEBUG") == "1" {
		log.Printf("warp: "+format, args...)
	}
}

// ErrNotConnected is returned when the tunnel should be up but is not.
var ErrNotConnected = errors.New("warp tunnel is not connected")
