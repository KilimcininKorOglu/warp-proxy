// Package masque implements the Cloudflare WARP MASQUE client: device
// registration, the CONNECT-IP tunnel, and the identity state store. It is
// the Go port of the protocol documented in the clean-room reference
// (github.com/akumaginkou/warp-proxy, DESIGN.md).
package masque

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

// DeviceKeypair is a device's P-256 identity. Registration enrolls the
// public key; the tunnel authenticates with a self-signed certificate
// wrapping the same private key.
type DeviceKeypair struct {
	key *ecdsa.PrivateKey
}

// GenerateKeypair creates a fresh random P-256 keypair.
func GenerateKeypair() (*DeviceKeypair, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate P-256 key: %w", err)
	}
	return &DeviceKeypair{key: key}, nil
}

// KeypairFromPrivateB64 restores a keypair from its base64(SEC1 DER)
// private-key encoding, the format persisted in the identity state.
func KeypairFromPrivateB64(b64 string) (*DeviceKeypair, error) {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("base64 private key: %w", err)
	}
	key, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse SEC1 private key: %w", err)
	}
	return &DeviceKeypair{key: key}, nil
}

// PrivateB64 returns base64(SEC1 DER) of the private key, the value stored
// as private_key in the identity state.
func (k *DeviceKeypair) PrivateB64() (string, error) {
	der, err := x509.MarshalECPrivateKey(k.key)
	if err != nil {
		return "", fmt.Errorf("encode SEC1 private key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

// PublicSPKIB64 returns base64(SPKI DER) of the public key, the value sent
// in the enroll "key" field.
func (k *DeviceKeypair) PublicSPKIB64() (string, error) {
	der, err := x509.MarshalPKIXPublicKey(&k.key.PublicKey)
	if err != nil {
		return "", fmt.Errorf("encode SPKI public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

// Key exposes the private key for the tunnel's mTLS certificate.
func (k *DeviceKeypair) Key() *ecdsa.PrivateKey { return k.key }

// randomWGPubkeyB64 returns a random 32-byte value, base64-encoded. It is
// the throwaway WireGuard-style key the account creation step expects; it is
// never used for the tunnel.
func randomWGPubkeyB64() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

// randomAndroidSerial mimics an Android device serial: 16 lowercase hex
// characters.
func randomAndroidSerial() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 0, len(buf)*2)
	for _, b := range buf {
		out = append(out, hexDigits[b>>4], hexDigits[b&0x0f])
	}
	return string(out), nil
}
