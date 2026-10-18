package masque

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// liveGuard skips unless MASQUE_LIVE=1; the test talks to real Cloudflare
// endpoints and registers nothing.
func liveGuard(t *testing.T) {
	t.Helper()
	if os.Getenv("MASQUE_LIVE") != "1" {
		t.Skip("set MASQUE_LIVE=1 to run the live network probe")
	}
}

// loadLiveIdentity reads the identity named by MASQUE_STATE.
func loadLiveIdentity(t *testing.T) *Identity {
	t.Helper()
	dir := os.Getenv("MASQUE_STATE")
	if dir == "" {
		t.Fatal("set MASQUE_STATE to the identity state directory")
	}
	id, err := LoadIdentity(dir)
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	return id
}

func liveTLSConf(t *testing.T, id *Identity) *tls.Config {
	t.Helper()
	kp, err := id.Keypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	cert, err := selfSignedCert(kp.Key())
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	pinned, err := parsePEMPubKey(id.PeerPubKeyPEM)
	if err != nil {
		t.Fatalf("pinned key: %v", err)
	}
	return &tls.Config{
		Certificates:          []tls.Certificate{cert},
		ServerName:            ConnectSNI,
		NextProtos:            []string{"h3"},
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: pinVerifier(pinned),
		MinVersion:            tls.VersionTLS13,
	}
}

// TestLiveQuicHandshake dials the stored identity's endpoint with the full
// mTLS + pinning TLS config and reports where the handshake dies.
func TestLiveQuicHandshake(t *testing.T) {
	liveGuard(t)
	id := loadLiveIdentity(t)
	endpoint, err := id.TunnelEndpoint()
	if err != nil {
		t.Fatalf("endpoint: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, endpoint, liveTLSConf(t, id),
		&quic.Config{EnableDatagrams: true, MaxIdleTimeout: 30 * time.Second})
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	defer conn.CloseWithError(0, "")
	t.Logf("handshake OK: tls=0x%x", conn.ConnectionState().TLS.Version)
}

// TestLiveEndpointScan dials the H2 fallback endpoint over TCP+TLS with the
// full mTLS config, the documented QUIC-blocked path.
func TestLiveEndpointScan(t *testing.T) {
	liveGuard(t)
	id := loadLiveIdentity(t)
	conf := liveTLSConf(t, id)
	conf.NextProtos = []string{"h2"}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 8 * time.Second}, Config: conf}
	nc, err := d.DialContext(ctx, "tcp", "162.159.198.2:443")
	if err != nil {
		t.Fatalf("tcp tls dial failed: %v", err)
	}
	defer nc.Close()
	tc := nc.(*tls.Conn)
	st := tc.ConnectionState()
	t.Logf("tcp+tls handshake OK: tls=0x%x alpn=%q", st.Version, st.NegotiatedProtocol)
}

// TestLiveNetstack dials real TCP through tunnel + netstack: remote DNS
// resolution and an HTTP GET must return data.
func TestLiveNetstack(t *testing.T) {
	liveGuard(t)
	id := loadLiveIdentity(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	tun, err := Dial(ctx, id, "")
	if err != nil {
		t.Fatalf("tunnel: %v", err)
	}
	defer tun.Close()
	d, err := NewNetstackDialer(tun, id)
	if err != nil {
		t.Fatalf("netstack: %v", err)
	}
	ip, err := d.Resolve(ctx, "cloudflare.com")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	t.Logf("resolved cloudflare.com -> %s", ip)
	conn, err := d.Dial(ctx, "tcp", "cloudflare.com:80")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	req := "GET / HTTP/1.1\r\nHost: cloudflare.com\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		t.Fatalf("read: %v", err)
	}
	t.Logf("read %d bytes: %q", n, buf[:min(n, 60)])
	if !bytes.HasPrefix(buf[:n], []byte("HTTP/1.1")) {
		t.Errorf("answer %q is not HTTP", buf[:min(n, 60)])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestLiveIdleSurvival keeps the tunnel idle past the negotiated idle
// timeout and then dials again: keep-alive must keep it usable.
func TestLiveIdleSurvival(t *testing.T) {
	liveGuard(t)
	id := loadLiveIdentity(t)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	tun, err := Dial(ctx, id, "")
	if err != nil {
		t.Fatalf("tunnel: %v", err)
	}
	defer tun.Close()
	d, err := NewNetstackDialer(tun, id)
	if err != nil {
		t.Fatalf("netstack: %v", err)
	}
	conn, err := d.Dial(ctx, "tcp", "cloudflare.com:80")
	if err != nil {
		t.Fatalf("dial before idle: %v", err)
	}
	conn.Close()
	t.Log("idle 60s starting")
	time.Sleep(60 * time.Second)
	conn2, err := d.Dial(ctx, "tcp", "cloudflare.com:80")
	if err != nil {
		t.Fatalf("dial after idle: %v", err)
	}
	conn2.Close()
	t.Log("tunnel survived idle and dialed again")
}

// TestLiveAppFlow mimics the app: open a tunnel, wait ~15s, then carry an
// HTTPS request through the netstack. Repeat to see whether later tunnels
// degrade the way the daemon's did.
func TestLiveAppFlow(t *testing.T) {
	liveGuard(t)
	id := loadLiveIdentity(t)
	for round := 1; round <= 3; round++ {
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		tun, err := Dial(ctx, id, "")
		if err != nil {
			cancel()
			t.Fatalf("round %d: tunnel: %v", round, err)
		}
		d, err := NewNetstackDialer(tun, id)
		if err != nil {
			tun.Close()
			cancel()
			t.Fatalf("round %d: netstack: %v", round, err)
		}
		time.Sleep(15 * time.Second)
		conn, err := d.Dial(ctx, "tcp", "www.cloudflare.com:443")
		if err != nil {
			tun.Close()
			cancel()
			t.Fatalf("round %d: dial: %v", round, err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, 64)
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write([]byte("GET /cdn-cgi/trace HTTP/1.1\r\nHost: www.cloudflare.com\r\nConnection: close\r\n\r\n")); err != nil {
			tun.Close()
			cancel()
			t.Fatalf("round %d: write: %v", round, err)
		}
		n, err := conn.Read(buf)
		tun.Close()
		cancel()
		if err != nil && n == 0 {
			t.Fatalf("round %d: read: %v", round, err)
		}
		t.Logf("round %d: %q", round, buf[:min(n, 40)])
		time.Sleep(2 * time.Second)
	}
}

// TestLiveEgressPerEndpoint reports the WARP egress for two different edge
// endpoints with the same identity: same IP means the egress keys on the
// client, different IPs mean the pool can spread across edges.
func TestLiveEgressPerEndpoint(t *testing.T) {
	liveGuard(t)
	id := loadLiveIdentity(t)
	for _, ep := range []string{"", "162.159.198.1:443", "162.159.192.1:443"} {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		tun, err := Dial(ctx, id, ep)
		if err != nil {
			cancel()
			t.Logf("endpoint %q: dial: %v", ep, err)
			continue
		}
		d, derr := NewNetstackDialer(tun, id)
		if derr != nil {
			tun.Close()
			cancel()
			continue
		}
		conn, cerr := d.Dial(ctx, "tcp", "1.1.1.1:53")
		if cerr != nil {
			tun.Close()
			cancel()
			t.Logf("endpoint %q: dial: %v", ep, cerr)
			continue
		}
		conn.Close()
		// UDP DNS via netstack for whoami TXT.
		resp, rerr := d.dnsExchange(ctx, BuildTXTQuery("whoami.cloudflare"))
		if rerr != nil {
			t.Logf("endpoint %q: dns: %v", ep, rerr)
			tun.Close()
			cancel()
			continue
		}
		txt, terr := parseTXTFromMessage(resp)
		if terr != nil {
			t.Logf("endpoint %q: parse: %v", ep, terr)
			tun.Close()
			cancel()
			continue
		}
		tun.Close()
		cancel()
		t.Logf("endpoint %q -> egress %q", ep, txt)
	}
}

// TestLiveEgressPerAccount reports the WARP egress of every stored
// identity: distinct IPs make the pool useful, identical ones mean
// Cloudflare keys the egress on the client host.
func TestLiveEgressPerAccount(t *testing.T) {
	liveGuard(t)
	dir := os.Getenv("MASQUE_STATE")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		id, err := LoadIdentityAt(filepath.Join(dir, name))
		if err != nil {
			t.Logf("%s: load: %v", name, err)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		tun, err := Dial(ctx, id, "")
		if err != nil {
			cancel()
			t.Logf("%s: tunnel: %v", name, err)
			continue
		}
		d, derr := NewNetstackDialer(tun, id)
		if derr != nil {
			tun.Close()
			cancel()
			continue
		}
		resp, rerr := d.dnsExchange(ctx, BuildTXTQuery("whoami.cloudflare"))
		if rerr != nil {
			t.Logf("%s: dns: %v", name, rerr)
			tun.Close()
			cancel()
			continue
		}
		txt, _ := parseTXTFromMessage(resp)
		t.Logf("%s -> egress %q", name, txt)
		tun.Close()
		cancel()
	}
}
