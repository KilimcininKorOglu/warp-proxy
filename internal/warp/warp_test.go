package warp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"warp-proxy/internal/masque"
)

func TestEnsureReadyRegistersOnceAndConnects(t *testing.T) {
	dir := t.TempDir()
	var registers atomic.Int32
	var attempts atomic.Int32
	m := NewManager(dir, ModeReconnect, 1, DistributionOff)
	m.register = func(context.Context) (*masque.Identity, error) {
		registers.Add(1)
		return testIdentity(), nil
	}
	m.connect = func(context.Context, *masque.Identity,
		string) (Tunnel, Dialer, error) {
		attempts.Add(1)
		return &countingTunnel{}, &fakeDialer{}, nil
	}

	ctx := context.Background()
	if err := m.EnsureReady(ctx); err != nil {
		t.Fatalf("EnsureReady: %v", err)
	}
	if ok, err := m.Connected(ctx); err != nil || !ok {
		t.Errorf("Connected = %v, %v; want true", ok, err)
	}
	// A second EnsureReady keeps the stored registration and the live tunnel.
	if err := m.EnsureReady(ctx); err != nil {
		t.Fatalf("EnsureReady 2: %v", err)
	}
	if registers.Load() != 1 {
		t.Errorf("registers = %d, want 1", registers.Load())
	}
	if attempts.Load() != 1 {
		t.Errorf("connects = %d, want 1 (live worker untouched)", attempts.Load())
	}
	if _, err := os.Stat(filepath.Join(dir, "identity.json")); err != nil {
		t.Errorf("identity not persisted: %v", err)
	}
}

func TestReconnectModesSwapTunnel(t *testing.T) {
	dir := t.TempDir()
	var attempts, oldClosed atomic.Int32
	m := NewManager(dir, ModeReconnect, 1, DistributionOff)
	m.connect = func(context.Context, *masque.Identity,
		string) (Tunnel, Dialer, error) {
		attempts.Add(1)
		return &countingTunnel{onClose: func() { oldClosed.Add(1) }}, &fakeDialer{}, nil
	}

	ctx := context.Background()
	if err := m.EnsureReady(ctx); err != nil {
		t.Fatalf("EnsureReady: %v", err)
	}
	if err := m.Reconnect(ctx); err != nil {
		t.Fatalf("Reconnect: %v", err)
	}
	if attempts.Load() != 2 || oldClosed.Load() != 1 {
		t.Errorf("attempts=%d closed=%d, want 2/1", attempts.Load(), oldClosed.Load())
	}
	if m.LastReconnect().IsZero() {
		t.Error("LastReconnect not stamped")
	}

	// Reregister mode deletes the stored identity before reconnecting.
	m.SetMode(ModeReregister)
	if m.ReconnectMode() != ModeReregister {
		t.Fatal("mode not switched")
	}
}

func TestSetEndpointPinsOverride(t *testing.T) {
	dir := t.TempDir()
	var endpoints []string
	var attempts atomic.Int32
	m := NewManager(dir, ModeReconnect, 1, DistributionOff)
	m.connect = func(_ context.Context, _ *masque.Identity,
		endpoint string) (Tunnel, Dialer, error) {
		attempts.Add(1)
		endpoints = append(endpoints, endpoint)
		return &countingTunnel{}, &fakeDialer{}, nil
	}
	if err := m.EnsureReady(context.Background()); err != nil {
		t.Fatalf("EnsureReady: %v", err)
	}
	if err := m.SetEndpoint(context.Background(), "162.159.198.1:443"); err != nil {
		t.Fatalf("SetEndpoint: %v", err)
	}
	if endpoints[len(endpoints)-1] != "162.159.198.1:443" {
		t.Errorf("endpoint = %q, want the pinned override", endpoints[len(endpoints)-1])
	}
	if attempts.Load() != 2 {
		t.Errorf("connects = %d, want 2", attempts.Load())
	}
}

func TestDialWithoutTunnelFails(t *testing.T) {
	m := NewManager(t.TempDir(), ModeReconnect, 1, DistributionOff)
	if _, err := m.Dial(context.Background(), "tcp", "example.com:80"); !errors.Is(err, ErrNotConnected) {
		t.Errorf("Dial err = %v, want ErrNotConnected", err)
	}
}

func TestModeFallback(t *testing.T) {
	m := NewManager(t.TempDir(), "bogus", 1, DistributionOff)
	if m.ReconnectMode() != ModeReconnect {
		t.Errorf("mode = %q, want reconnect fallback", m.ReconnectMode())
	}
	m.SetMode(ModeReregister)
	m.SetMode("also-bogus")
	if m.ReconnectMode() != ModeReconnect {
		t.Errorf("mode = %q, want reconnect fallback", m.ReconnectMode())
	}
}

// countingTunnel records close calls.
type countingTunnel struct {
	onClose func()
	closed  bool
}

func (c *countingTunnel) Close() error {
	if !c.closed {
		c.closed = true
		if c.onClose != nil {
			c.onClose()
		}
	}
	return nil
}

// testIdentity returns a syntactically complete identity for state files.
func testIdentity() *masque.Identity {
	return &masque.Identity{
		PrivateKey:  "test",
		AccessToken: "test",
		ID:          "test-device",
		IPv4:        "172.16.0.2/32",
	}
}

// fakeDialer stands in for the netstack dialer.
type fakeDialer struct{}

func (fakeDialer) Dial(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("fake dialer")
}

func (fakeDialer) Resolve(context.Context, string) (net.IP, error) {
	return nil, errors.New("fake dialer")
}

func TestPoolRotationUsesFreshSession(t *testing.T) {
	dir := t.TempDir()
	var attempts, oldClosed atomic.Int32
	m := NewManager(dir, ModeReconnect, 3, DistributionOff)
	m.register = func(context.Context) (*masque.Identity, error) {
		return testIdentity(), nil
	}
	m.connect = func(context.Context, *masque.Identity,
		string) (Tunnel, Dialer, error) {
		attempts.Add(1)
		return &countingTunnel{onClose: func() { oldClosed.Add(1) }}, &fakeDialer{}, nil
	}

	if err := m.EnsureReady(context.Background()); err != nil {
		t.Fatalf("EnsureReady: %v", err)
	}
	if attempts.Load() != 1 {
		t.Fatalf("connects = %d, want 1 (only the active account)", attempts.Load())
	}

	// Rotation opens the next identity's fresh session and drops the old
	// tunnel only afterwards.
	if err := m.Reconnect(context.Background()); err != nil {
		t.Fatalf("Reconnect: %v", err)
	}
	if attempts.Load() != 2 || oldClosed.Load() != 1 {
		t.Errorf("attempts=%d closed=%d, want 2/1", attempts.Load(), oldClosed.Load())
	}
	st, err := m.Status(context.Background())
	if err != nil || !strings.Contains(st, "account 2/3") {
		t.Errorf("status = %q, %v; want account 2/3", st, err)
	}

	// A second rotation wraps around to the first identity.
	if err := m.Reconnect(context.Background()); err != nil {
		t.Fatalf("Reconnect 2: %v", err)
	}
	if attempts.Load() != 3 {
		t.Errorf("connects = %d, want 3", attempts.Load())
	}
}

func TestPoolKeepsOldTunnelOnFailedRotation(t *testing.T) {
	dir := t.TempDir()
	var attempts, oldClosed atomic.Int32
	m := NewManager(dir, ModeReconnect, 2, DistributionOff)
	m.register = func(context.Context) (*masque.Identity, error) {
		return testIdentity(), nil
	}
	m.connect = func(context.Context, *masque.Identity,
		string) (Tunnel, Dialer, error) {
		if attempts.Add(1) == 2 {
			return nil, nil, errors.New("next identity's tunnel fails")
		}
		return &countingTunnel{onClose: func() { oldClosed.Add(1) }}, &fakeDialer{}, nil
	}
	if err := m.EnsureReady(context.Background()); err != nil {
		t.Fatalf("EnsureReady: %v", err)
	}
	if err := m.Reconnect(context.Background()); err == nil {
		t.Fatal("rotation succeeded although the next tunnel failed")
	}
	// The old tunnel must stay up.
	if ok, _ := m.Connected(context.Background()); !ok {
		t.Error("failed rotation tore down the working tunnel")
	}
	if oldClosed.Load() != 0 {
		t.Error("failed rotation closed the old tunnel")
	}
}

// taggedDialer marks every dial with its worker index so tests can see
// which tunnel served a request.
type taggedDialer struct{ tag string }

func (d taggedDialer) Dial(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New(d.tag)
}

func (d taggedDialer) Resolve(context.Context, string) (net.IP, error) {
	return nil, errors.New(d.tag)
}

func TestRoundRobinDialCyclesWorkers(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir, ModeReconnect, 3, DistributionRoundRobin)
	m.register = func(context.Context) (*masque.Identity, error) {
		return testIdentity(), nil
	}
	m.connect = func(_ context.Context, _ *masque.Identity,
		_ string) (Tunnel, Dialer, error) {
		return &countingTunnel{}, nil, nil
	}
	if err := m.EnsureReady(context.Background()); err != nil {
		t.Fatalf("EnsureReady: %v", err)
	}
	// Install tagged dialers after connect so each worker is identifiable.
	for i, w := range m.workers {
		w.d = taggedDialer{tag: fmt.Sprintf("worker-%d", i)}
	}

	var got []string
	for range 3 {
		_, err := m.Dial(context.Background(), "tcp", "example.com:80")
		if err == nil {
			t.Fatal("dial unexpectedly succeeded on a fake dialer")
		}
		got = append(got, err.Error())
	}
	want := []string{"worker-0", "worker-1", "worker-2"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("dials = %v, want %v", got, want)
		}
	}
}

func TestRoundRobinSkipsDeadWorkers(t *testing.T) {
	dir := t.TempDir()
	var attempts atomic.Int32
	m := NewManager(dir, ModeReconnect, 3, DistributionRoundRobin)
	m.register = func(context.Context) (*masque.Identity, error) {
		return testIdentity(), nil
	}
	m.connect = func(_ context.Context, _ *masque.Identity,
		_ string) (Tunnel, Dialer, error) {
		// Worker 1's tunnel never comes up.
		if attempts.Add(1) == 2 {
			return nil, nil, errors.New("worker 1 fails")
		}
		return &countingTunnel{}, nil, nil
	}
	if err := m.EnsureReady(context.Background()); err != nil {
		t.Fatalf("EnsureReady: %v (one dead worker must not fail the pool)", err)
	}
	m.workers[0].d = taggedDialer{tag: "worker-0"}
	m.workers[2].d = taggedDialer{tag: "worker-2"}

	// The dead worker is skipped (never served) but consumes its tick, so
	// the served sequence is 0, 2, 2, ...
	for i, want := range []string{"worker-0", "worker-2", "worker-2"} {
		_, err := m.Dial(context.Background(), "tcp", "example.com:80")
		if err == nil || err.Error() != want {
			t.Fatalf("dial %d = %v, want %s", i, err, want)
		}
	}
}

func TestRoundRobinReconnectRefreshesAll(t *testing.T) {
	dir := t.TempDir()
	var attempts atomic.Int32
	m := NewManager(dir, ModeReconnect, 3, DistributionRoundRobin)
	m.register = func(context.Context) (*masque.Identity, error) {
		return testIdentity(), nil
	}
	m.connect = func(context.Context, *masque.Identity,
		string) (Tunnel, Dialer, error) {
		attempts.Add(1)
		return &countingTunnel{}, &fakeDialer{}, nil
	}
	if err := m.EnsureReady(context.Background()); err != nil {
		t.Fatalf("EnsureReady: %v", err)
	}
	if attempts.Load() != 3 {
		t.Fatalf("EnsureReady connects = %d, want 3", attempts.Load())
	}
	if err := m.Reconnect(context.Background()); err != nil {
		t.Fatalf("Reconnect: %v", err)
	}
	if attempts.Load() != 6 {
		t.Errorf("connects after Reconnect = %d, want 6 (every tunnel refreshed)", attempts.Load())
	}
	st, err := m.Status(context.Background())
	if err != nil || !strings.Contains(st, "round-robin 3/3") {
		t.Errorf("status = %q, %v; want round-robin 3/3", st, err)
	}
}

func TestDistributionFallback(t *testing.T) {
	m := NewManager(t.TempDir(), ModeReconnect, 1, "bogus")
	if m.Distribution() != DistributionOff {
		t.Errorf("distribution = %q, want off fallback", m.Distribution())
	}
}

// egressDialer dials a fixed listener (an httptest server), so the real
// measureEgress implementation runs end to end over a fake tunnel.
type egressDialer struct{ addr string }

func (d egressDialer) Dial(_ context.Context, _, _ string) (net.Conn, error) {
	return net.Dial("tcp", d.addr)
}

func (d egressDialer) Resolve(context.Context, string) (net.IP, error) {
	return nil, errors.New("fake dialer")
}

// traceServer serves a cdn-cgi/trace-style body whose ip= line is read
// from the atomic pointer, so tests can change the exit IP over time.
func traceServer(t *testing.T, ip *atomic.Pointer[string]) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, "fl=x\nip=%s\nwarp=on\n", *ip.Load())
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestMeasureEgressParsesTraceIP(t *testing.T) {
	ip := atomic.Pointer[string]{}
	ip.Store(new("203.0.113.9"))
	srv := traceServer(t, &ip)
	m := NewManager(t.TempDir(), ModeReconnect, 1, DistributionOff)
	m.register = func(context.Context) (*masque.Identity, error) {
		return testIdentity(), nil
	}
	m.connect = func(_ context.Context, _ *masque.Identity,
		_ string) (Tunnel, Dialer, error) {
		return &countingTunnel{}, egressDialer{addr: srv.Listener.Addr().String()}, nil
	}
	if err := m.EnsureReady(context.Background()); err != nil {
		t.Fatalf("EnsureReady: %v", err)
	}
	if got := m.measureEgress(context.Background(), 0); got != "203.0.113.9" {
		t.Errorf("measureEgress = %q, want 203.0.113.9", got)
	}
	// A dead worker measures empty and stays out of the map.
	if got := m.measureEgress(context.Background(), 5); got != "" {
		t.Errorf("measureEgress(dead) = %q, want empty", got)
	}
}

func TestDedupeRotatesCollidingWorker(t *testing.T) {
	dir := t.TempDir()
	var rotated atomic.Int32
	m := NewManager(dir, ModeReconnect, 2, DistributionRoundRobin)
	m.register = func(context.Context) (*masque.Identity, error) {
		return testIdentity(), nil
	}
	m.connect = func(context.Context, *masque.Identity,
		string) (Tunnel, Dialer, error) {
		return &countingTunnel{}, &fakeDialer{}, nil
	}
	if err := m.EnsureReady(context.Background()); err != nil {
		t.Fatalf("EnsureReady: %v", err)
	}
	// Both workers sit on the same egress; the first rotation of worker 1
	// moves it off.
	ips := atomic.Pointer[string]{}
	ips.Store(new("104.28.192.58"))
	m.measure = func(_ context.Context, i int) string {
		if i == 1 && rotated.Load() > 0 {
			return "104.28.224.60"
		}
		return "104.28.192.58"
	}
	n, err := m.DedupeEgress(context.Background(), 2, &RotationGate{
		Allow:  func() bool { return true },
		Record: func(bool) { rotated.Add(1) },
	})
	if err != nil {
		t.Fatalf("DedupeEgress: %v", err)
	}
	if n != 1 {
		t.Errorf("rotated = %d, want 1", n)
	}
	if got := m.CachedEgresses(); got[0] != "104.28.192.58" || got[1] != "104.28.224.60" {
		t.Errorf("cached egresses = %v, want distinct", got)
	}
}

func TestDedupeAcceptsUnresolvableCollision(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir, ModeReconnect, 2, DistributionRoundRobin)
	m.register = func(context.Context) (*masque.Identity, error) {
		return testIdentity(), nil
	}
	m.connect = func(context.Context, *masque.Identity,
		string) (Tunnel, Dialer, error) {
		return &countingTunnel{}, &fakeDialer{}, nil
	}
	if err := m.EnsureReady(context.Background()); err != nil {
		t.Fatalf("EnsureReady: %v", err)
	}
	// Cloudflare keeps answering the same IP: the pass must stop at the
	// bound (one rotation per pass) and keep both tunnels alive.
	m.measure = func(context.Context, int) string { return "104.28.192.58" }
	var records atomic.Int32
	n, err := m.DedupeEgress(context.Background(), 2, &RotationGate{
		Allow:  func() bool { return true },
		Record: func(bool) { records.Add(1) },
	})
	if err != nil {
		t.Fatalf("DedupeEgress: %v", err)
	}
	if n != 2 || records.Load() != 2 {
		t.Errorf("rotated = %d, records = %d; want 2/2 (pass bound)", n, records.Load())
	}
	if ok, _ := m.Connected(context.Background()); !ok {
		t.Error("dedupe tore down the pool")
	}
}

func TestDedupeStopsAtRateLimit(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir, ModeReconnect, 3, DistributionRoundRobin)
	m.register = func(context.Context) (*masque.Identity, error) {
		return testIdentity(), nil
	}
	m.connect = func(context.Context, *masque.Identity,
		string) (Tunnel, Dialer, error) {
		return &countingTunnel{}, &fakeDialer{}, nil
	}
	if err := m.EnsureReady(context.Background()); err != nil {
		t.Fatalf("EnsureReady: %v", err)
	}
	m.measure = func(context.Context, int) string { return "104.28.192.58" }
	n, err := m.DedupeEgress(context.Background(), 2, &RotationGate{
		Allow:  func() bool { return false },
		Record: func(bool) {},
	})
	if err != nil {
		t.Fatalf("DedupeEgress: %v", err)
	}
	if n != 0 {
		t.Errorf("rotated = %d, want 0 (limiter denied every rotation)", n)
	}
}

func TestDedupeOutsideRoundRobinFails(t *testing.T) {
	m := NewManager(t.TempDir(), ModeReconnect, 1, DistributionOff)
	if _, err := m.DedupeEgress(context.Background(), 2, nil); err == nil {
		t.Error("dedupe ran outside round-robin mode")
	}
}

func TestEgressCollidersPicksLaterWorkers(t *testing.T) {
	got := egressColliders(map[int]string{0: "a", 1: "a", 2: "b", 3: "a"})
	want := []int{1, 3}
	if !slices.Equal(got, want) {
		t.Errorf("colliders = %v, want %v", got, want)
	}
}

// prefDialer records the IPv6 preference applied to it.
type prefDialer struct {
	pref atomic.Pointer[string]
}

func (p *prefDialer) SetIPv6Pref(pref string) { p.pref.Store(&pref) }

func (p *prefDialer) Dial(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("fake dialer")
}

func (p *prefDialer) Resolve(context.Context, string) (net.IP, error) {
	return nil, errors.New("fake dialer")
}

func TestIPv6PreferenceAppliesToLiveDialers(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir, ModeReconnect, 2, DistributionRoundRobin)
	m.register = func(context.Context) (*masque.Identity, error) {
		return testIdentity(), nil
	}
	dialers := []*prefDialer{{}, {}}
	next := 0
	m.connect = func(context.Context, *masque.Identity,
		string) (Tunnel, Dialer, error) {
		d := dialers[next]
		next++
		return &countingTunnel{}, d, nil
	}
	// The preference set before connecting must reach new dialers too.
	m.SetIPv6Preference("prefer")
	if err := m.EnsureReady(context.Background()); err != nil {
		t.Fatalf("EnsureReady: %v", err)
	}
	for i, d := range dialers {
		if got := d.pref.Load(); got == nil || *got != "prefer" {
			t.Errorf("dialer %d pref = %v, want prefer", i, got)
		}
	}
	// A live change must reach the already-connected dialers.
	m.SetIPv6Preference("only")
	for i, d := range dialers {
		if got := d.pref.Load(); got == nil || *got != "only" {
			t.Errorf("dialer %d pref after change = %v, want only", i, got)
		}
	}
	if m.IPv6Preference() != "only" {
		t.Errorf("manager pref = %q, want only", m.IPv6Preference())
	}
	m.SetIPv6Preference("bogus")
	if m.IPv6Preference() != "off" {
		t.Errorf("bogus pref = %q, want off fallback", m.IPv6Preference())
	}
}

func TestHomeEdgeFromActiveIdentity(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir, ModeReconnect, 1, DistributionOff)
	m.register = func(context.Context) (*masque.Identity, error) {
		id := testIdentity()
		id.EndpointV4 = "162.159.198.2"
		id.EndpointPorts = []int{443, 500}
		return id, nil
	}
	m.connect = func(_ context.Context, _ *masque.Identity,
		_ string) (Tunnel, Dialer, error) {
		return &countingTunnel{}, &fakeDialer{}, nil
	}
	if err := m.EnsureReady(context.Background()); err != nil {
		t.Fatalf("EnsureReady: %v", err)
	}
	host, ports, ok := m.HomeEdge()
	if !ok || host != "162.159.198.2" || len(ports) != 2 {
		t.Errorf("HomeEdge = %q, %v, %v", host, ports, ok)
	}
}
