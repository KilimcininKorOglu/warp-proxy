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
	// datagram budget at InitialPacketSize 1350 (the warp-svc value) minus
	// headers and the context-id varint, matching mihomo's 1280 MTU.
	MaxIPPacket = 1280
	// initialPacketSize is the QUIC initial packet size warp-svc uses.
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
		// match the endpoint IP.
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: pinVerifier(pinned),
		MinVersion:            tls.VersionTLS13,
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
	fail := func(e error) (*Tunnel, error) {
		qTransport.Close()
		udpConn.Close()
		return nil, e
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
	client := transport.NewClientConn(conn)

	// The CONNECT stream is the tunnel's lifetime; its context is decoupled
	// from the dial context and released by Tunnel.Close.
	reqCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	req, err := http.NewRequestWithContext(reqCtx, http.MethodConnect, ConnectURI, nil)
	if err != nil {
		conn.CloseWithError(quic.ApplicationErrorCode(0), "setup failed")
		cancel()
		return fail(err)
	}
	req.Proto = ConnectProtocol
	req.Header.Set("Capsule-Protocol", "?1")
	req.Header.Set("User-Agent", "")

	stream, err := client.OpenRequestStream(reqCtx)
	if err != nil {
		conn.CloseWithError(quic.ApplicationErrorCode(0), "setup failed")
		cancel()
		return fail(fmt.Errorf("open request stream: %w", err))
	}
	if err := stream.SendRequestHeader(req); err != nil {
		conn.CloseWithError(quic.ApplicationErrorCode(0), "setup failed")
		cancel()
		return fail(fmt.Errorf("send extended CONNECT: %w", err))
	}
	resp, err := stream.ReadResponse()
	if err != nil {
		conn.CloseWithError(quic.ApplicationErrorCode(0), "setup failed")
		cancel()
		return fail(fmt.Errorf("read CONNECT response: %w", err))
	}
	if resp.StatusCode != http.StatusOK {
		conn.CloseWithError(quic.ApplicationErrorCode(0), "connect rejected")
		cancel()
		return fail(fmt.Errorf("MASQUE CONNECT rejected: %d", resp.StatusCode))
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
			_ = conn.CloseWithError(0, "closed")
			_ = transport.Close()
			_ = qTransport.Close()
			_ = udpConn.Close()
			return nil
		},
		status: resp.StatusCode,
	}, nil
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
