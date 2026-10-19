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
	// MaxIPPacket bounds the packet handed to a tunnel's SendIP: the QUIC
	// datagram budget at InitialPacketSize 1350 (the official client's
	// value) minus headers and the context-id varint, matching mihomo's
	// 1280 MTU.
	MaxIPPacket = 1280
	// initialPacketSize is the QUIC initial packet size the official
	// client uses.
	initialPacketSize = 1350
)

// Tunnel is an established MASQUE CONNECT-IP session over either transport.
type Tunnel struct {
	send   func([]byte) error
	recv   func(context.Context) ([]byte, error)
	closer func() error
	status int
}

// Dial establishes the tunnel: H3 (QUIC) first, H2 fallback when the QUIC
// path cannot complete (QUIC-blocked networks, or edges that silently drop
// foreign QUIC fingerprints). endpointOverride is "host:port" for the H3
// endpoint when non-empty.
func Dial(ctx context.Context, id *Identity, endpointOverride string) (*Tunnel, error) {
	conf, err := tunnelTLSConf(id)
	if err != nil {
		return nil, err
	}
	var h3Err, h2Err error
	t, err := dialH3(ctx, id, conf, endpointOverride)
	if err == nil {
		return t, nil
	}
	h3Err = err
	t, err = dialH2(ctx, id, conf)
	if err == nil {
		return t, nil
	}
	h2Err = err
	return nil, fmt.Errorf("h3: %v; h2: %v", h3Err, h2Err)
}

// tunnelTLSConf builds the mTLS + pinning TLS config shared by both paths.
func tunnelTLSConf(id *Identity) (*tls.Config, error) {
	kp, err := id.Keypair()
	if err != nil {
		return nil, err
	}
	cert, err := selfSignedCert(kp.Key())
	if err != nil {
		return nil, err
	}
	pinned, err := parsePEMPubKey(id.PeerPubKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("endpoint_pub_key: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   ConnectSNI,
		// The endpoint is trusted by key pinning, not PKI: the SNI does not
		// match the endpoint IP. VerifyConnection (not VerifyPeerCertificate)
		// keeps the pin active on resumed sessions too.
		InsecureSkipVerify: true, // #nosec G402 -- self-signed endpoint, pubkey pin below
		VerifyConnection:   pinVerifier(pinned),
		MinVersion:         tls.VersionTLS13,
	}, nil
}

// Status reports the HTTP status of the extended CONNECT.
func (t *Tunnel) Status() int { return t.status }

// SendIP sends one IP packet through the tunnel.
func (t *Tunnel) SendIP(packet []byte) error {
	if len(packet) > MaxIPPacket {
		return fmt.Errorf("ip packet %d bytes exceeds tunnel budget %d",
			len(packet), MaxIPPacket)
	}
	return t.send(packet)
}

// RecvIP receives one IP packet from the tunnel.
func (t *Tunnel) RecvIP(ctx context.Context) ([]byte, error) {
	return t.recv(ctx)
}

// Close tears the tunnel down.
func (t *Tunnel) Close() error {
	if t.closer != nil {
		return t.closer()
	}
	return nil
}

// dialH3 establishes the MASQUE session over HTTP/3 datagrams: QUIC dial
// with mTLS + pubkey pinning, then the extended CONNECT. IP packets are
// exchanged as HTTP/3 datagrams framed `varint(context_id=0) || packet`
// (quic-go adds the quarter-stream-id prefix itself).
func dialH3(ctx context.Context, id *Identity, conf *tls.Config,
	endpointOverride string) (*Tunnel, error) {
	endpoint := endpointOverride
	if endpoint == "" {
		var err error
		if endpoint, err = id.TunnelEndpoint(); err != nil {
			return nil, err
		}
	}
	tlsConf := conf.Clone()
	tlsConf.NextProtos = []string{"h3"}
	quicConf := &quic.Config{
		EnableDatagrams:   true,
		InitialPacketSize: initialPacketSize,
		KeepAlivePeriod:   15 * time.Second,
		MaxIdleTimeout:    30 * time.Second,
	}
	session, teardown, err := dialH3QUIC(ctx, endpoint, tlsConf, quicConf)
	if err != nil {
		return nil, err
	}
	return newH3Tunnel(ctx, session, teardown)
}

// h3Session carries the live HTTP/3 connection plus everything its tunnel
// needs to close.
type h3Session struct {
	conn      *quic.Conn
	transport *http3.Transport
	teardown  func()
}

// dialH3QUIC dials the QUIC connection under the endpoint: a pinned UDP
// socket, a 20-byte connection-ID generator and the http3 client on top.
// The returned teardown releases every resource it opened.
func dialH3QUIC(ctx context.Context, endpoint string,
	tlsConf *tls.Config, quicConf *quic.Config) (*h3Session, func(), error) {
	// The backend intermittently emits PROTOCOL_VIOLATION unless the client
	// uses 20-byte source connection IDs, so pin the generator length.
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		return nil, nil, fmt.Errorf("udp socket: %w", err)
	}
	qTransport := &quic.Transport{
		Conn:               udpConn,
		ConnectionIDLength: quicCIDLength,
	}
	fail := func(e error) (*h3Session, func(), error) {
		_ = qTransport.Close() //nolint:errcheck // best-effort teardown
		_ = udpConn.Close()    //nolint:errcheck // best-effort teardown
		return nil, nil, e
	}
	addr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return fail(fmt.Errorf("resolve endpoint %s: %w", endpoint, err))
	}
	conn, err := qTransport.Dial(ctx, addr, tlsConf, quicConf)
	if err != nil {
		return fail(fmt.Errorf("quic dial %s: %w", endpoint, err))
	}
	transport := &http3.Transport{
		TLSClientConfig:    tlsConf,
		QUICConfig:         quicConf,
		EnableDatagrams:    true,
		AdditionalSettings: map[uint64]uint64{h3SettingDatagram00: 1},
	}
	teardown := func() {
		_ = transport.Close()
		_ = qTransport.Close()
		_ = udpConn.Close()
	}
	return &h3Session{conn: conn, transport: transport, teardown: teardown}, teardown, nil
}

// newH3Tunnel opens the extended CONNECT on the live session and returns the
// datagram tunnel over it.
func newH3Tunnel(ctx context.Context, s *h3Session,
	teardown func()) (*Tunnel, error) {
	client := s.transport.NewClientConn(s.conn)

	// The CONNECT stream is the tunnel's lifetime; its context is decoupled
	// from the dial context and released by Tunnel.Close.
	stream, status, cancel, err := openH3Connect(ctx, client, s.conn)
	if err != nil {
		teardown()
		return nil, err
	}
	return &Tunnel{
		send: func(packet []byte) error {
			buf := quicvarint.Append(nil, 0) // context id 0: full packet
			buf = append(buf, packet...)
			return stream.SendDatagram(buf)
		},
		recv: func(rctx context.Context) ([]byte, error) {
			for {
				b, err := stream.ReceiveDatagram(rctx)
				if err != nil {
					return nil, err
				}
				h2Debug("recv datagram: %d bytes %x", len(b), b[:min(len(b), 48)])
				ctxID, n, err := quicvarint.Parse(b)
				if err != nil || ctxID != 0 {
					h2Debug("skip datagram: ctx parse err=%v", err)
					continue
				}
				return b[n:], nil
			}
		},
		closer: func() error {
			cancel()
			stream.CancelRead(0)
			stream.CancelWrite(0)
			_ = client.CloseWithError(0, "closed")
			_ = s.conn.CloseWithError(0, "closed")
			teardown()
			return nil
		},
		status: status,
	}, nil
}

// openH3Connect opens the extended CONNECT stream and waits for the
// response. The returned cancel belongs to the tunnel's lifetime context
// and must be kept until the stream closes.
func openH3Connect(ctx context.Context, client *http3.ClientConn,
	conn *quic.Conn) (stream *http3.RequestStream, status int, cancel context.CancelFunc, err error) {
	reqCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	bad := func(e error) (*http3.RequestStream, int, context.CancelFunc, error) {
		_ = conn.CloseWithError(quic.ApplicationErrorCode(0), "setup failed") //nolint:errcheck // best-effort teardown
		cancel()
		return nil, 0, nil, e
	}
	req, err := http.NewRequestWithContext(reqCtx, http.MethodConnect, ConnectURI, nil)
	if err != nil {
		return bad(err)
	}
	req.Proto = ConnectProtocol
	req.Header.Set("Capsule-Protocol", "?1")
	req.Header.Set("User-Agent", "")
	stream, err = client.OpenRequestStream(reqCtx)
	if err != nil {
		return bad(fmt.Errorf("open request stream: %w", err))
	}
	if err := stream.SendRequestHeader(req); err != nil {
		return bad(fmt.Errorf("send extended CONNECT: %w", err))
	}
	resp, err := stream.ReadResponse()
	if err != nil {
		return bad(fmt.Errorf("read CONNECT response: %w", err))
	}
	if resp.StatusCode != http.StatusOK {
		return bad(fmt.Errorf("MASQUE CONNECT rejected: %d", resp.StatusCode))
	}
	return stream, resp.StatusCode, cancel, nil
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

// pinVerifier returns the VerifyConnection callback that accepts the
// endpoint only when its certificate carries the pinned public key. The
// handshake signature is still verified by the TLS stack, so a MITM without
// the pinned private key cannot complete it. VerifyConnection runs on
// resumed sessions too, unlike VerifyPeerCertificate.
func pinVerifier(pinned *ecdsa.PublicKey) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("endpoint sent no certificate")
		}
		leaf := cs.PeerCertificates[0]
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
