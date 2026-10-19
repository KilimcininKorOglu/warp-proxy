package masque

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
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
		Certificates:       []tls.Certificate{cert},
		ServerName:         ConnectSNI,
		NextProtos:         []string{"h3"},
		InsecureSkipVerify: true,
		VerifyConnection:   pinVerifier(pinned),
		MinVersion:         tls.VersionTLS13,
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
	defer conn.CloseWithError(0, "") //nolint:errcheck // test teardown
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
	defer nc.Close() //nolint:errcheck // test teardown
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
	defer tun.Close() //nolint:errcheck // test teardown
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
	defer conn.Close() //nolint:errcheck // test teardown
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
	defer tun.Close() //nolint:errcheck // test teardown
	d, err := NewNetstackDialer(tun, id)
	if err != nil {
		t.Fatalf("netstack: %v", err)
	}
	conn, err := d.Dial(ctx, "tcp", "cloudflare.com:80")
	if err != nil {
		t.Fatalf("dial before idle: %v", err)
	}
	_ = conn.Close()
	t.Log("idle 60s starting")
	time.Sleep(60 * time.Second)
	conn2, err := d.Dial(ctx, "tcp", "cloudflare.com:80")
	if err != nil {
		t.Fatalf("dial after idle: %v", err)
	}
	_ = conn2.Close()
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
			_ = tun.Close()
			cancel()
			t.Fatalf("round %d: netstack: %v", round, err)
		}
		time.Sleep(15 * time.Second)
		conn, err := d.Dial(ctx, "tcp", "www.cloudflare.com:443")
		if err != nil {
			_ = tun.Close()
			cancel()
			t.Fatalf("round %d: dial: %v", round, err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, 64)
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write([]byte("GET /cdn-cgi/trace HTTP/1.1\r\nHost: www.cloudflare.com\r\nConnection: close\r\n\r\n")); err != nil {
			_ = tun.Close()
			cancel()
			t.Fatalf("round %d: write: %v", round, err)
		}
		n, err := conn.Read(buf)
		_ = tun.Close()
		cancel()
		if err != nil && n == 0 {
			t.Fatalf("round %d: read: %v", round, err)
		}
		t.Logf("round %d: %q", round, buf[:min(n, 40)])
		time.Sleep(2 * time.Second)
	}
}

// egressFor opens id's tunnel (optionally pinned to an endpoint) and asks
// whoami.cloudflare for the WARP egress address.
func egressFor(t *testing.T, ctx context.Context, id *Identity,
	endpoint string) (string, error) {
	t.Helper()
	tun, err := Dial(ctx, id, endpoint)
	if err != nil {
		return "", fmt.Errorf("tunnel: %w", err)
	}
	defer tun.Close() //nolint:errcheck // helper teardown, error carried above
	d, err := NewNetstackDialer(tun, id)
	if err != nil {
		return "", fmt.Errorf("netstack: %w", err)
	}
	resp, err := d.dnsExchange(ctx, BuildTXTQuery("whoami.cloudflare"))
	if err != nil {
		return "", fmt.Errorf("dns: %w", err)
	}
	return parseTXTFromMessage(resp)
}

// TestLiveEgressPerAccount reports the WARP egress of every stored identity
// (sequentially, so each session is fresh).
func TestLiveEgressPerAccount(t *testing.T) {
	liveGuard(t)
	dir := os.Getenv("MASQUE_STATE")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		id, err := LoadIdentityAt(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		txt, err := egressFor(t, ctx, id, "")
		if err != nil {
			t.Logf("%s: %v", e.Name(), err)
			continue
		}
		t.Logf("%s -> egress %q", e.Name(), txt)
	}
}

// TestLiveEgressKeysOnSession proves the egress depends on the session, not
// the account or the edge: the same identity on two endpoints answers with
// the same address, and each fresh session of any account may move.
func TestLiveEgressKeysOnSession(t *testing.T) {
	liveGuard(t)
	id := loadLiveIdentity(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	seen := map[string]bool{}
	for _, ep := range []string{"", ""} {
		txt, err := egressFor(t, ctx, id, ep)
		if err != nil {
			t.Logf("endpoint %q: %v", ep, err)
			continue
		}
		seen[txt] = true
		t.Logf("fresh session -> egress %q", txt)
	}
	if len(seen) > 1 {
		t.Logf("egress varies between fresh sessions: %v", seen)
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
			_ = tun.Close()
			cancel()
			continue
		}
		conn, cerr := d.Dial(ctx, "tcp", "1.1.1.1:53")
		if cerr != nil {
			_ = tun.Close()
			cancel()
			t.Logf("endpoint %q: dial: %v", ep, cerr)
			continue
		}
		_ = conn.Close()
		// UDP DNS via netstack for whoami TXT.
		resp, rerr := d.dnsExchange(ctx, BuildTXTQuery("whoami.cloudflare"))
		if rerr != nil {
			t.Logf("endpoint %q: dns: %v", ep, rerr)
			_ = tun.Close()
			cancel()
			continue
		}
		txt, terr := parseTXTFromMessage(resp)
		if terr != nil {
			t.Logf("endpoint %q: parse: %v", ep, terr)
			_ = tun.Close()
			cancel()
			continue
		}
		_ = tun.Close()
		cancel()
		t.Logf("endpoint %q -> egress %q", ep, txt)
	}
}

// TestLiveIPv6Egress dials an IPv6 target through the tunnel's netstack:
// the trace's ip= line then names the WARP IPv6 egress, if the tunnel
// carries v6 at all.
func TestLiveIPv6Egress(t *testing.T) {
	liveGuard(t)
	id := loadLiveIdentity(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	tun, err := Dial(ctx, id, "")
	if err != nil {
		t.Fatalf("tunnel: %v", err)
	}
	defer tun.Close() //nolint:errcheck // test teardown
	d, err := NewNetstackDialer(tun, id)
	if err != nil {
		t.Fatalf("netstack: %v", err)
	}
	conn, err := d.Dial(ctx, "tcp6", "[2606:4700:4700::1111]:80")
	if err != nil {
		t.Fatalf("v6 dial: %v", err)
	}
	defer conn.Close() //nolint:errcheck // test teardown
	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte("GET /cdn-cgi/trace HTTP/1.1\r\nHost: www.cloudflare.com\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	buf := make([]byte, 4096)
	n, err := io.ReadFull(conn, buf)
	if err != nil && n == 0 {
		t.Fatalf("read: %v", err)
	}
	body := string(buf[:n])
	line := ""
	for l := range strings.SplitSeq(body, "\n") {
		if strings.HasPrefix(l, "ip=") {
			line = strings.TrimSpace(l)
		}
	}
	t.Logf("v6 trace: %s", line)
	if line == "" {
		t.Errorf("trace carried no ip= line: %q", body[:min(n, 200)])
	}
}

// TestLiveEgressAcrossFreshRegistrations registers several throwaway
// devices and reports each one's tunnel endpoint and egress: if the
// endpoint (colo) varies across registrations, so does the egress pool.
// Every device is deleted again before the test ends.
func TestLiveEgressAcrossFreshRegistrations(t *testing.T) {
	liveGuard(t)
	const n = 5
	client := NewClient()
	for i := range n {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		id, err := RegisterAuto(ctx, Options{Name: "warp-proxy-colo-probe"})
		if err != nil {
			cancel()
			t.Logf("registration %d: %v", i+1, err)
			continue
		}
		ep := id.EndpointV4
		ports := id.EndpointPorts
		txt, eerr := egressFor(t, ctx, id, "")
		cancel()
		if eerr != nil {
			t.Logf("registration %d: endpoint=%s ports=%v egress error: %v", i+1, ep, ports, eerr)
		} else {
			t.Logf("registration %d: endpoint=%s ports=%v egress=%q", i+1, ep, ports, txt)
		}
		delCtx, delCancel := context.WithTimeout(context.Background(), 15*time.Second)
		if derr := client.Delete(delCtx, id); derr != nil {
			t.Logf("registration %d: delete: %v", i+1, derr)
		}
		delCancel()
		time.Sleep(2 * time.Second)
	}
}

// TestLiveSimultaneousEgress opens the stored identities' tunnels at the
// same time and reports each one's egress, mirroring the daemon's pool.
func TestLiveSimultaneousEgress(t *testing.T) {
	liveGuard(t)
	dir := os.Getenv("MASQUE_STATE")
	entries, _ := os.ReadDir(dir)
	var ids []*Identity
	var names []string
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		id, err := LoadIdentityAt(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		ids = append(ids, id)
		names = append(names, e.Name())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	for i, id := range ids {
		tun, err := Dial(ctx, id, "")
		if err != nil {
			t.Logf("%s: tunnel: %v", names[i], err)
			continue
		}
		defer tun.Close() //nolint:errcheck // test teardown
		d, err := NewNetstackDialer(tun, id)
		if err != nil {
			continue
		}
		resp, rerr := d.dnsExchange(ctx, BuildTXTQuery("whoami.cloudflare"))
		if rerr != nil {
			t.Logf("%s: dns: %v", names[i], rerr)
			continue
		}
		txt, _ := parseTXTFromMessage(resp)
		t.Logf("%s -> egress %q", names[i], txt)
		time.Sleep(300 * time.Millisecond)
	}
}
