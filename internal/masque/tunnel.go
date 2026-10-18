package masque

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

// Protocol values from the clean-room reference (DESIGN.md); Cloudflare's
// CONNECT-IP is deliberately not RFC-9484-clean.
const (
	// ConnectSNI is the TLS SNI of the tunnel handshake; it intentionally
	// does not match the endpoint IP, hence the key pinning.
	ConnectSNI = "consumer-masque.cloudflareclient.com"
	// ConnectProtocol is Cloudflare's non-standard extended-CONNECT :protocol.
	ConnectProtocol = "cf-connect-ip"
	// ConnectURI is the fixed request target of the CONNECT-IP session.
	ConnectURI = "https://cloudflareaccess.com"
	// quicCIDLength is the source connection-ID length the backend expects;
	// shorter IDs intermittently draw PROTOCOL_VIOLATION.
	quicCIDLength = 20
	// h3SettingDatagram00 is the legacy H3 datagram setting id the official
	// client still advertises.
	h3SettingDatagram00 = 0x276
	// MaxIPPacket bounds the packet we hand to sendIP; QUIC datagram budget
	// (~1222) minus the context-id varint, rounded down for safety.
	MaxIPPacket = 1200
)

// Tunnel is an established MASQUE CONNECT-IP session. IP packets are
// exchanged as HTTP/3 datagrams framed `varint(context_id=0) || packet`
// (quic-go adds the quarter-stream-id prefix itself).
type Tunnel struct {
	conn       *quic.Conn
	client     *http3.ClientConn
	stream     *http3.RequestStream
	transport  *http3.Transport
	qTransport *quic.Transport
	udpConn    *net.UDPConn
	cancel     context.CancelFunc
	status     int
}

// Dial establishes the tunnel against id's endpoint (or endpointOverride
// "host:port" when non-empty): QUIC dial with mTLS + pubkey pinning, then the
// extended CONNECT. A 200 response opens the session.
func Dial(ctx context.Context, id *Identity, endpointOverride string) (*Tunnel, error) {
	endpoint := endpointOverride
	if endpoint == "" {
		var err error
		if endpoint, err = id.TunnelEndpoint(); err != nil {
			return nil, err
		}
	}
	kp, err := id.Keypair()
	if err != nil {
		return nil, err
	}
	pinned, err := parsePEMPubKey(id.PeerPubKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("endpoint_pub_key: %w", err)
	}
	cert, err := selfSignedCert(kp.Key())
	if err != nil {
		return nil, err
	}
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   ConnectSNI,
		NextProtos:   []string{"h3"},
		// The endpoint is trusted by key pinning, not PKI: the SNI does not
		// match the endpoint IP.
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: pinVerifier(pinned),
		MinVersion:            tls.VersionTLS13,
	}
	quicConf := &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 15 * time.Second,
		MaxIdleTimeout:  30 * time.Second,
	}
	// The backend intermittently emits PROTOCOL_VIOLATION unless the client
	// uses 20-byte source connection IDs, so pin the generator length.
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		return nil, fmt.Errorf("udp socket: %w", err)
	}
	qTransport := &quic.Transport{
		Conn:               udpConn,
		ConnectionIDLength: quicCIDLength,
	}
	addr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		udpConn.Close()
		return nil, fmt.Errorf("resolve endpoint %s: %w", endpoint, err)
	}
	conn, err := qTransport.Dial(ctx, addr, tlsConf, quicConf)
	if err != nil {
		qTransport.Close()
		udpConn.Close()
		return nil, fmt.Errorf("quic dial %s: %w", endpoint, err)
	}
	transport := &http3.Transport{
		TLSClientConfig:    tlsConf,
		QUICConfig:         quicConf,
		EnableDatagrams:    true,
		AdditionalSettings: map[uint64]uint64{h3SettingDatagram00: 1},
	}
	client := transport.NewClientConn(conn)

	// The CONNECT stream is the tunnel's lifetime; cancel is released when
	// the tunnel closes (Close cancels the stream, ending the request).
	reqCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	t := &Tunnel{cancel: cancel}
	req, err := http.NewRequestWithContext(reqCtx, http.MethodConnect, ConnectURI, nil)
	if err != nil {
		conn.CloseWithError(quic.ApplicationErrorCode(0), "setup failed")
		cancel()
		return nil, err
	}
	req.Proto = ConnectProtocol
	req.Header.Set("Capsule-Protocol", "?1")
	req.Header.Set("User-Agent", "")

	stream, err := client.OpenRequestStream(reqCtx)
	if err != nil {
		conn.CloseWithError(quic.ApplicationErrorCode(0), "setup failed")
		cancel()
		return nil, fmt.Errorf("open request stream: %w", err)
	}
	if err := stream.SendRequestHeader(req); err != nil {
		conn.CloseWithError(quic.ApplicationErrorCode(0), "setup failed")
		cancel()
		return nil, fmt.Errorf("send extended CONNECT: %w", err)
	}
	resp, err := stream.ReadResponse()
	if err != nil {
		conn.CloseWithError(quic.ApplicationErrorCode(0), "setup failed")
		cancel()
		return nil, fmt.Errorf("read CONNECT response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		conn.CloseWithError(quic.ApplicationErrorCode(0), "connect rejected")
		cancel()
		return nil, fmt.Errorf("MASQUE CONNECT rejected: %d", resp.StatusCode)
	}
	t.conn = conn
	t.client = client
	t.stream = stream
	t.transport = transport
	t.qTransport = qTransport
	t.udpConn = udpConn
	t.status = resp.StatusCode
	return t, nil
}

// Status reports the HTTP status of the extended CONNECT.
func (t *Tunnel) Status() int { return t.status }

// SendIP sends one IP packet through the tunnel, framed with context id 0.
func (t *Tunnel) SendIP(packet []byte) error {
	if len(packet) > MaxIPPacket {
		return fmt.Errorf("ip packet %d bytes exceeds tunnel budget %d",
			len(packet), MaxIPPacket)
	}
	buf := quicvarint.Append(nil, 0) // context id 0: full, uncompressed packet
	buf = append(buf, packet...)
	return t.stream.SendDatagram(buf)
}

// RecvIP receives one IP packet from the tunnel, skipping datagrams with a
// non-zero context id. SendIP prepends the context-id varint (quic-go
// already stripped the quarter-stream-id prefix).
func (t *Tunnel) RecvIP(ctx context.Context) ([]byte, error) {
	for {
		b, err := t.stream.ReceiveDatagram(ctx)
		if err != nil {
			return nil, err
		}
		ctxID, n, err := quicvarint.Parse(b)
		if err != nil || ctxID != 0 {
			continue
		}
		return b[n:], nil
	}
}

// Close tears the tunnel down.
func (t *Tunnel) Close() error {
	if t.cancel != nil {
		t.cancel()
	}
	if t.stream != nil {
		t.stream.CancelRead(0)
		t.stream.CancelWrite(0)
	}
	if t.client != nil {
		_ = t.client.CloseWithError(0, "closed")
	}
	if t.conn != nil {
		_ = t.conn.CloseWithError(0, "closed")
	}
	if t.transport != nil {
		_ = t.transport.Close()
	}
	if t.qTransport != nil {
		_ = t.qTransport.Close()
	}
	if t.udpConn != nil {
		_ = t.udpConn.Close()
	}
	return nil
}

// selfSignedCert builds the short-lived self-signed certificate that wraps
// the device key; the server issues no client cert.
func selfSignedCert(key *ecdsa.PrivateKey) (tls.Certificate, error) {
	serialBytes := make([]byte, 16)
	if _, err := rand.Read(serialBytes); err != nil {
		return tls.Certificate{}, fmt.Errorf("serial: %w", err)
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber: new(big.Int).SetBytes(serialBytes),
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("self-sign certificate: %w", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}, nil
}

// pinVerifier returns the VerifyPeerCertificate callback that accepts the
// endpoint only when its certificate carries the pinned public key. The
// handshake signature is still verified by the TLS stack, so a MITM without
// the pinned private key cannot complete it.
func pinVerifier(pinned *ecdsa.PublicKey) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("endpoint sent no certificate")
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("parse server certificate: %w", err)
		}
		got, ok := leaf.PublicKey.(*ecdsa.PublicKey)
		if !ok || !got.Equal(pinned) {
			return errors.New("endpoint public key mismatch (pin failed)")
		}
		return nil
	}
}

// parsePEMPubKey parses the PEM "PUBLIC KEY" block from the enroll response.
func parsePEMPubKey(pemStr string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is %T, want *ecdsa.PublicKey", pub)
	}
	return ec, nil
}
