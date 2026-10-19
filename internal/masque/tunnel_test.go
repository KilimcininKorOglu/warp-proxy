package masque

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/quic-go/quic-go/quicvarint"
)

func TestSelfSignedCertWrapsDeviceKey(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	cert, err := selfSignedCert(kp.Key())
	if err != nil {
		t.Fatalf("self-sign: %v", err)
	}
	if len(cert.Certificate) != 1 {
		t.Fatalf("cert chain = %d entries, want 1", len(cert.Certificate))
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !got.Equal(&kp.Key().PublicKey) {
		t.Error("certificate does not carry the device public key")
	}
	if span := leaf.NotAfter.Sub(leaf.NotBefore); span < 23*time.Hour || span > 25*time.Hour {
		t.Errorf("validity = %v, want about 24h", span)
	}
}

func TestPinVerifierAcceptsAndRejects(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	cert, err := selfSignedCert(kp.Key())
	if err != nil {
		t.Fatalf("self-sign: %v", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	other, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	verify := pinVerifier(&kp.Key().PublicKey)
	if err := verify(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}); err != nil {
		t.Errorf("pinned certificate rejected: %v", err)
	}
	// A certificate for a different key must fail the pin.
	otherCert, err := selfSignedCert(other.Key())
	if err != nil {
		t.Fatalf("self-sign: %v", err)
	}
	otherLeaf, err := x509.ParseCertificate(otherCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := verify(tls.ConnectionState{PeerCertificates: []*x509.Certificate{otherLeaf}}); err == nil {
		t.Error("verifier accepted a certificate with a different key")
	}
	if err := verify(tls.ConnectionState{}); err == nil {
		t.Error("verifier accepted an empty chain")
	}
}

func TestParsePEMPubKey(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&kp.Key().PublicKey)
	if err != nil {
		t.Fatalf("spki: %v", err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	got, err := parsePEMPubKey(pemStr)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !got.Equal(&kp.Key().PublicKey) {
		t.Error("parsed key differs from source")
	}
	if _, err := parsePEMPubKey("not a pem"); err == nil {
		t.Error("parsed garbage input")
	}
}

func TestContextIDParsing(t *testing.T) {
	// RecvIP's framing: SendIP prepends a single-byte context-id varint 0.
	b := []byte{0x00, 0x45, 0x00}
	ctxID, n, err := quicvarint.Parse(b)
	if err != nil || ctxID != 0 || n != 1 {
		t.Fatalf("parse = %d/%d/%v, want 0/1/nil", ctxID, n, err)
	}
	if _, _, err := quicvarint.Parse(nil); err == nil {
		t.Error("parsed an empty datagram")
	}
}

func TestProtocolConstants(t *testing.T) {
	if quicCIDLength != 20 {
		t.Errorf("quicCIDLength = %d, want 20", quicCIDLength)
	}
	if h3SettingDatagram00 != 0x276 {
		t.Errorf("h3SettingDatagram00 = %#x, want 0x276", h3SettingDatagram00)
	}
	if ConnectProtocol != "cf-connect-ip" {
		t.Errorf("ConnectProtocol = %q, want cf-connect-ip", ConnectProtocol)
	}
	if ConnectSNI != "consumer-masque.cloudflareclient.com" {
		t.Errorf("ConnectSNI = %q", ConnectSNI)
	}
	if ConnectURI != "https://cloudflareaccess.com" {
		t.Errorf("ConnectURI = %q", ConnectURI)
	}
	// 1280 matches mihomo's tunnel MTU at InitialPacketSize 1350.
	if MaxIPPacket != 1280 {
		t.Errorf("MaxIPPacket = %d, want 1280", MaxIPPacket)
	}
	if initialPacketSize != 1350 {
		t.Errorf("initialPacketSize = %d, want 1350", initialPacketSize)
	}
}
