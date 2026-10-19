// Package warp owns the WARP tunnel lifecycle: identity registration, the
// MASQUE tunnels and the netstack dialers the proxies route through. It
// replaces the warp-cli driver and supports a multi-account pool.
package warp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
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

// Request distribution modes.
const (
	// DistributionOff keeps a single active tunnel; rotation happens only
	// on Reconnect.
	DistributionOff = "off"
	// DistributionRoundRobin keeps every account's tunnel open and
	// spreads requests across them one by one.
	DistributionRoundRobin = "round-robin"
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

	mu           sync.RWMutex
	workers      []*worker
	active       int    // the worker owning the live tunnel (off mode)
	endpoint     string // pin override applied at the next (re)connect
	last         time.Time
	distribution string // DistributionOff or DistributionRoundRobin
	rrCounter    atomic.Uint64
	egress       map[int]string // worker index -> last measured egress IP

	// measure is the egress measurement hook (test override); nil means
	// the real HTTP-over-tunnel measurement.
	measure func(ctx context.Context, i int) string
}

// RotationGate routes each dedupe rotation through the caller's rate
// limiter, so the manager itself stays limiter-free.
type RotationGate struct {
	Allow  func() bool
	Record func(succeeded bool)
}

// NewManager builds a Manager persisting identity state under stateDir and
// rotating across accounts accounts. distribution selects DistributionOff
// (default) or DistributionRoundRobin; anything else falls back to off.
func NewManager(stateDir string, reconnectMode string, accounts int,
	distribution string) *Manager {
	if accounts < 1 {
		accounts = 1
	}
	m := &Manager{stateDir: stateDir, accounts: accounts}
	m.SetMode(reconnectMode)
	m.SetDistribution(distribution)
	return m
}

// SetDistribution switches the request distribution mode; anything other
// than DistributionRoundRobin falls back to DistributionOff.
func (m *Manager) SetDistribution(mode string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if mode != DistributionRoundRobin {
		mode = DistributionOff
	}
	m.distribution = mode
}

// Distribution reports the request distribution mode.
func (m *Manager) Distribution() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.distribution
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

// Dial routes a connection through the tunnel pool. Off mode uses the
// active tunnel; round-robin advances one worker per call. It implements
// the proxy.Upstream contract.
func (m *Manager) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	d, err := m.requestDialer()
	if err != nil {
		return nil, err
	}
	return d.Dial(ctx, network, addr)
}

// ResolveIP resolves a hostname through the pool's remote DNS, picked by
// the same distribution rule as Dial.
func (m *Manager) ResolveIP(ctx context.Context, host string) (net.IP, error) {
	d, err := m.requestDialer()
	if err != nil {
		return nil, ErrNotConnected
	}
	ip, rerr := d.Resolve(ctx, host)
	return ip, wrapResolve(host, ip, rerr)
}

// requestDialer picks the dialer for one request according to the
// distribution mode.
func (m *Manager) requestDialer() (Dialer, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.distribution == DistributionRoundRobin {
		if d := m.rrDialerLocked(); d != nil {
			return d, nil
		}
		return nil, ErrNotConnected
	}
	w, err := m.activeWorker()
	if err != nil {
		return nil, err
	}
	return w.d, nil
}

// rrDialerLocked returns the next live worker's dialer, skipping dead
// workers so a failed tunnel does not break the round-robin.
func (m *Manager) rrDialerLocked() Dialer {
	n := len(m.workers)
	if n == 0 {
		return nil
	}
	start := int(m.rrCounter.Add(1)) - 1
	for i := 0; i < n; i++ {
		if w := m.workers[(start+i)%n]; w != nil && w.d != nil {
			return w.d
		}
	}
	return nil
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

// EnsureReady brings the pool up, keeping existing registrations and any
// tunnel that is already live. Off mode connects only the active account;
// round-robin connects every account.
func (m *Manager) EnsureReady(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensureWorkersLocked()
	if m.distribution == DistributionRoundRobin {
		return m.forWorkersLocked(ctx, true)
	}
	if m.activeWorkerLocked() != nil {
		return nil
	}
	return m.connectLocked(ctx, m.active, m.endpoint)
}

// Reconnect refreshes the egress. With a single account it re-establishes
// the tunnel (reregister mode deletes the registration first). With a pool
// it opens the next identity's fresh session — which Cloudflare answers
// with the next egress IP — and closes the previous tunnel only after the
// new one is up, so a failed rotation keeps the old egress working. In
// round-robin mode it refreshes every live tunnel's session instead.
func (m *Manager) Reconnect(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.distribution == DistributionRoundRobin {
		if err := m.forWorkersLocked(ctx, false); err != nil {
			return err
		}
		m.last = time.Now()
		return nil
	}
	next := m.active
	if m.poolSize() > 1 {
		next = (m.active + 1) % m.poolSize()
	}
	if err := m.connectLocked(ctx, next, m.endpoint); err != nil {
		return err
	}
	if next != m.active {
		// nils tear the old tunnel down; the identity file stays.
		m.swap(m.active, nil, nil, nil)
		m.active = next
	}
	m.last = time.Now()
	return nil
}

// SetEndpoint pins the tunnels to a custom edge endpoint ("host:port") and
// reconnects so the change takes effect: the active account in off mode,
// every account in round-robin mode.
func (m *Manager) SetEndpoint(ctx context.Context, endpoint string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.endpoint = endpoint
	if m.distribution == DistributionRoundRobin {
		if err := m.forWorkersLocked(ctx, false); err != nil {
			return err
		}
		m.last = time.Now()
		return nil
	}
	if err := m.connectLocked(ctx, m.active, endpoint); err != nil {
		return err
	}
	m.last = time.Now()
	return nil
}

// forWorkersLocked connects every worker's tunnel. With skipLive it keeps
// tunnels that are already up (EnsureReady); without it every worker gets
// a fresh session (Reconnect, SetEndpoint). It fails only when no tunnel
// comes up at all, so a single bad account cannot take the pool down.
func (m *Manager) forWorkersLocked(ctx context.Context, skipLive bool) error {
	var firstErr error
	up := 0
	for i := range m.workers {
		if w := m.workers[i]; skipLive && w != nil && w.d != nil {
			up++
			continue
		}
		if err := m.connectLocked(ctx, i, m.endpoint); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			h2Debug("worker %d connect failed: %v", i, err)
			continue
		}
		up++
	}
	if up == 0 && firstErr != nil {
		return firstErr
	}
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
	ep := m.endpoint
	if ep == "" {
		ep = "default edge"
	}
	if m.distribution == DistributionRoundRobin {
		live := m.liveCountLocked()
		if live == 0 {
			return "disconnected", nil
		}
		return fmt.Sprintf("connected (MASQUE, round-robin %d/%d tunnels, endpoint %s)",
			live, m.poolSize(), ep), nil
	}
	if m.activeWorkerLocked() == nil {
		return "disconnected", nil
	}
	if m.poolSize() == 1 {
		return fmt.Sprintf("connected (MASQUE, endpoint %s)", ep), nil
	}
	return fmt.Sprintf("connected (MASQUE, account %d/%d, endpoint %s)",
		m.active+1, m.poolSize(), ep), nil
}

// liveCountLocked counts the workers holding a live tunnel.
func (m *Manager) liveCountLocked() int {
	n := 0
	for _, w := range m.workers {
		if w != nil && w.d != nil {
			n++
		}
	}
	return n
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
	m.swap(i, id, tun, d)
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
func (m *Manager) swap(i int, id *masque.Identity, tun Tunnel, d Dialer) {
	w := m.workers[i]
	if w.tun != nil {
		w.tun.Close()
	}
	w.id = id
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

// egressTraceURL is fetched through each tunnel to read its exit IP.
const egressTraceURL = "http://www.cloudflare.com/cdn-cgi/trace"

// ReconnectWorker refreshes worker i's tunnel session, dropping the old
// tunnel only after the new one is up. The caller owns rate limiting.
func (m *Manager) ReconnectWorker(ctx context.Context, i int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if i < 0 || i >= len(m.workers) {
		return fmt.Errorf("worker %d out of range", i)
	}
	return m.connectLocked(ctx, i, m.endpoint)
}

// Egresses measures every live worker's exit IP through its own tunnel,
// caches the result for the dashboard and returns a copy. Failed
// measurements leave the worker out of the map.
func (m *Manager) Egresses(ctx context.Context) map[int]string {
	ips := map[int]string{}
	for i := range m.workers {
		if ip := m.measureEgress(ctx, i); ip != "" {
			ips[i] = ip
		}
	}
	m.mu.Lock()
	m.egress = ips
	m.mu.Unlock()
	out := make(map[int]string, len(ips))
	for i, ip := range ips {
		out[i] = ip
	}
	return out
}

// CachedEgresses returns the last measured per-worker egress IPs.
func (m *Manager) CachedEgresses() map[int]string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[int]string, len(m.egress))
	for i, ip := range m.egress {
		out[i] = ip
	}
	return out
}

// measureEgress reads the exit IP through worker i's tunnel; empty on any
// failure. The real implementation runs HTTP over the worker's dialer.
func (m *Manager) measureEgress(ctx context.Context, i int) string {
	if m.measure != nil {
		return m.measure(ctx, i)
	}
	m.mu.RLock()
	var d Dialer
	if i < len(m.workers) && m.workers[i] != nil {
		d = m.workers[i].d
	}
	m.mu.RUnlock()
	if d == nil {
		return ""
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return d.Dial(ctx, network, addr)
		},
	}
	client := &http.Client{Transport: tr, Timeout: 20 * time.Second}
	resp, err := client.Get(egressTraceURL)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil || resp.StatusCode != http.StatusOK {
		return ""
	}
	for _, line := range strings.Split(string(body), "\n") {
		if ip, ok := strings.CutPrefix(line, "ip="); ok {
			return strings.TrimSpace(ip)
		}
	}
	return ""
}

// DedupeEgress evens out the round-robin pool's exit IPs: it measures
// every live tunnel, refreshes the colliding workers' sessions (all but
// the first worker on each shared IP) and re-measures, at most passes
// times. Each rotation goes through the gate, so a rate-limited pass
// stops early and keeps sharing. It is a no-op error outside round-robin
// mode. It returns the number of rotated tunnels.
func (m *Manager) DedupeEgress(ctx context.Context, passes int, gate *RotationGate) (int, error) {
	m.mu.RLock()
	mode := m.distribution
	m.mu.RUnlock()
	if mode != DistributionRoundRobin {
		return 0, fmt.Errorf("egress dedupe requires distribution=%s", DistributionRoundRobin)
	}
	rotated := 0
	for p := 0; p < passes; p++ {
		colliders := egressColliders(m.Egresses(ctx))
		if len(colliders) == 0 {
			break
		}
		n, progress, stopped := m.rotateColliders(ctx, colliders, gate)
		rotated += n
		if stopped || !progress {
			break
		}
	}
	m.Egresses(ctx)
	return rotated, nil
}

// rotateColliders refreshes the colliding workers' sessions one by one. It
// reports whether any rotation succeeded (progress) and whether the gate
// cut the pass short (stopped).
func (m *Manager) rotateColliders(ctx context.Context, colliders []int,
	gate *RotationGate) (rotated int, progress, stopped bool) {
	for _, i := range colliders {
		if gate != nil && gate.Allow != nil && !gate.Allow() {
			return rotated, progress, true
		}
		err := m.ReconnectWorker(ctx, i)
		if gate != nil && gate.Record != nil {
			gate.Record(err == nil)
		}
		if err != nil {
			h2Debug("dedupe: worker %d refresh failed: %v", i, err)
			continue
		}
		rotated++
		progress = true
	}
	return rotated, progress, false
}

// egressColliders lists the workers that share an exit IP with an earlier
// worker, ascending.
func egressColliders(ips map[int]string) []int {
	seen := map[string]bool{}
	var out []int
	for _, i := range slices.Sorted(maps.Keys(ips)) {
		ip := ips[i]
		if seen[ip] {
			out = append(out, i)
			continue
		}
		seen[ip] = true
	}
	return out
}

// HomeEdge returns the active identity's registration edge host and its
// CONNECT-IP service ports. MASQUE binds a registration to this edge, so
// endpoint scans must stay on it; ok is false without a loaded identity.
func (m *Manager) HomeEdge() (host string, ports []int, ok bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, w := range m.workers {
		if w != nil && w.id != nil && w.id.EndpointV4 != "" {
			ports := w.id.EndpointPorts
			if len(ports) == 0 {
				ports = []int{443}
			}
			return w.id.EndpointV4, ports, true
		}
	}
	return "", nil, false
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
