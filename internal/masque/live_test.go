package masque

import (
	"context"
	"crypto/tls"
	"net"
	"os"
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
