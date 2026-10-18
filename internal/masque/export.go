package masque

import (
	"crypto/ecdsa"
	"crypto/tls"
)

// SelfSignedCert is the exported form of selfSignedCert for tools that need
// the tunnel's client identity without opening a tunnel.
func SelfSignedCert(key *ecdsa.PrivateKey) (tls.Certificate, error) {
	return selfSignedCert(key)
}

// ParsePEMPubKey is the exported form of parsePEMPubKey.
func ParsePEMPubKey(pemStr string) (*ecdsa.PublicKey, error) {
	return parsePEMPubKey(pemStr)
}
