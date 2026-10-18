package masque

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Identity is one registered WARP device: the enrolled key, the API token and
// everything the tunnel needs. It is persisted as JSON in the state directory.
type Identity struct {
	PrivateKey    string `json:"private_key"`
	AccessToken   string `json:"access_token"`
	ID            string `json:"id"`
	EndpointV4    string `json:"endpoint_v4"`
	EndpointV6    string `json:"endpoint_v6"`
	EndpointH2V4  string `json:"endpoint_h2_v4"`
	EndpointV6H2  string `json:"endpoint_h2_v6"`
	PeerPubKeyPEM string `json:"endpoint_pub_key"`
	IPv4          string `json:"ipv4"`
	IPv6          string `json:"ipv6"`
}

// H2FallbackEndpoint is the fixed MASQUE H2 fallback endpoint
// (QUIC-blocked networks; stage 2 feature).
const H2FallbackEndpoint = "162.159.198.2"

// Save writes the identity to <dir>/identity.json atomically: temp file,
// fsync, rename. The directory is created when missing.
func (id *Identity) Save(dir string) error {
	return id.SaveAt(filepath.Join(dir, "identity.json"))
}

// SaveAt writes the identity to the given file path atomically: temp file
// in the same directory, fsync, rename over the target.
func (id *Identity) SaveAt(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	b, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "identity-*.tmp")
	if err != nil {
		return fmt.Errorf("temp state file: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("write state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// LoadIdentity reads the identity from <dir>/identity.json. Returns
// os.ErrNotExist when no identity is stored yet.
func LoadIdentity(dir string) (*Identity, error) {
	return LoadIdentityAt(filepath.Join(dir, "identity.json"))
}

// LoadIdentityAt reads the identity from the given file path.
func LoadIdentityAt(path string) (*Identity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var id Identity
	if err := json.NewDecoder(f).Decode(&id); err != nil {
		return nil, fmt.Errorf("parse identity state: %w", err)
	}
	return &id, nil
}

// Keypair returns the device keypair of the identity.
func (id *Identity) Keypair() (*DeviceKeypair, error) {
	return KeypairFromPrivateB64(id.PrivateKey)
}

// TunnelEndpoint returns the MASQUE endpoint host:port (IPv4 preferred).
func (id *Identity) TunnelEndpoint() (string, error) {
	if ip := net.ParseIP(id.EndpointV4); ip != nil && ip.To4() != nil {
		return net.JoinHostPort(id.EndpointV4, "443"), nil
	}
	if ip := net.ParseIP(id.EndpointV6); ip != nil {
		return net.JoinHostPort(id.EndpointV6, "443"), nil
	}
	return "", fmt.Errorf("no usable MASQUE endpoint (v4=%q, v6=%q)",
		id.EndpointV4, id.EndpointV6)
}

// cfTimestamp formats now the way the registration API's tos field expects:
// YYYY-MM-DDTHH:MM:SS.mmm±HH:MM.
func cfTimestamp(t time.Time) string {
	return t.Format("2006-01-02T15:04:05.000-07:00")
}
