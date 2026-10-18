package warp

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"warp-proxy/internal/masque"
)

func TestEnsureReadyRegistersOnceAndConnects(t *testing.T) {
	dir := t.TempDir()
	var registers atomic.Int32
	var attempts atomic.Int32
	m := NewManager(dir, ModeReconnect, 1)
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
	m := NewManager(dir, ModeReconnect, 1)
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
	m := NewManager(dir, ModeReconnect, 1)
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
	m := NewManager(t.TempDir(), ModeReconnect, 1)
	if _, err := m.Dial(context.Background(), "tcp", "example.com:80"); !errors.Is(err, ErrNotConnected) {
		t.Errorf("Dial err = %v, want ErrNotConnected", err)
	}
}

func TestModeFallback(t *testing.T) {
	m := NewManager(t.TempDir(), "bogus", 1)
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
	m := NewManager(dir, ModeReconnect, 3)
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
	m := NewManager(dir, ModeReconnect, 2)
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
