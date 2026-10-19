package masque

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Cloudflare-internal registration API values tracked from the public WARP
// Android app; they bump with app releases.
const (
	APIURL           = "https://api.cloudflareclient.com"
	APIVersion       = "v0a4471"
	APIUserAgent     = "WARP for Android"
	APIClientVersion = "a-6.35-4471"
	// DefaultEndpointH2 is the fixed H2 fallback endpoint from the reference.
	DefaultEndpointH2 = "162.159.198.2"

	// DoHResolver is the resolver used to bypass a poisoned API hostname.
	DoHResolver = "1.1.1.1"
	apiHost     = "api.cloudflareclient.com"
)

// Options controls a registration.
type Options struct {
	// Model is the device model string (default "PC").
	Model string
	// Locale is the device locale (default "en_US").
	Locale string
	// Name optionally labels the device in the WARP device list.
	Name string
}

func (o Options) model() string {
	if o.Model == "" {
		return "PC"
	}
	return o.Model
}

func (o Options) locale() string {
	if o.Locale == "" {
		return "en_US"
	}
	return o.Locale
}

// Client talks to the WARP registration API. baseURL overrides APIURL for
// tests; pinAddr, when set, connects to that IP while keeping the real TLS
// SNI (the DoH-bypass mode).
type Client struct {
	baseURL string
	pinAddr string
	http    *http.Client
}

// NewClient builds a registration client that resolves the API host normally.
func NewClient() *Client {
	return &Client{baseURL: APIURL, http: &http.Client{Timeout: 30 * time.Second}}
}

// NewDoHClient builds a registration client that resolves api.cloudflareclient.com
// through DoH over 1.1.1.1 and pins the connection to the answer, keeping the
// real TLS SNI. For networks that poison the API hostname.
func NewDoHClient(ctx context.Context) (*Client, error) {
	addrs, err := resolveViaDoH(ctx, apiHost)
	if err != nil {
		return nil, err
	}
	return &Client{
		baseURL: APIURL,
		pinAddr: addrs[0],
		http:    &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// Register runs the full flow: create the account, enroll the P-256 MASQUE
// key and fold the response into an Identity.
func (c *Client) Register(ctx context.Context, opts Options) (*Identity, error) {
	kp, err := GenerateKeypair()
	if err != nil {
		return nil, err
	}
	acc, err := c.createAccount(ctx, opts)
	if err != nil {
		return nil, err
	}
	if acc.Token == "" {
		return nil, fmt.Errorf("register response had no token")
	}
	enrolled, err := c.enrollKey(ctx, acc.ID, acc.Token, kp, opts.Name)
	if err != nil {
		return nil, err
	}
	return buildIdentity(kp, acc.Token, enrolled)
}

// createAccount is step 1: POST /reg with a throwaway WG-style key.
func (c *Client) createAccount(ctx context.Context, opts Options) (*apiAccount, error) {
	wgKey, err := randomWGPubkeyB64()
	if err != nil {
		return nil, err
	}
	serial, err := randomAndroidSerial()
	if err != nil {
		return nil, err
	}
	body := map[string]string{
		"key":           wgKey,
		"install_id":    "",
		"fcm_token":     "",
		"tos":           cfTimestamp(time.Now()),
		"model":         opts.model(),
		"serial_number": serial,
		"os_version":    "",
		"key_type":      "curve25519",
		"tunnel_type":   "wireguard",
		"locale":        opts.locale(),
	}
	var acc apiAccount
	if err := c.doJSON(ctx, http.MethodPost, "/reg", "", body, &acc); err != nil {
		return nil, err
	}
	return &acc, nil
}

// enrollKey is step 2: PATCH /reg/{id} with the real P-256 public key.
func (c *Client) enrollKey(ctx context.Context, deviceID, token string,
	kp *DeviceKeypair, name string) (*apiAccount, error) {
	spki, err := kp.PublicSPKIB64()
	if err != nil {
		return nil, err
	}
	body := map[string]string{
		"key":         spki,
		"key_type":    "secp256r1",
		"tunnel_type": "masque",
	}
	if name != "" {
		body["name"] = name
	}
	var acc apiAccount
	if err := c.doJSON(ctx, http.MethodPatch, "/reg/"+deviceID, token, body, &acc); err != nil {
		return nil, err
	}
	return &acc, nil
}

// doJSON sends one API request with the WARP headers and decodes the JSON
// answer, surfacing non-2xx bodies as errors.
func (c *Client) doJSON(ctx context.Context, method, path, token string,
	body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method,
		strings.TrimRight(c.baseURL, "/")+"/"+APIVersion+path,
		bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", APIUserAgent)
	req.Header.Set("CF-Client-Version", APIClientVersion)
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("Connection", "Keep-Alive")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if c.pinAddr != "" {
		// Keep the real SNI and Host, but connect to the DoH-pinned IP.
		req.Host = req.URL.Host
		req.URL.Host = net.JoinHostPort(c.pinAddr, "443")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	text, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("warp api %s %s: %d: %s",
			method, path, resp.StatusCode, strings.TrimSpace(string(text)))
	}
	if err := json.Unmarshal(text, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// buildIdentity folds the enroll response and the keypair into an Identity.
func buildIdentity(kp *DeviceKeypair, token string, acc *apiAccount) (*Identity, error) {
	if len(acc.Config.Peers) == 0 {
		return nil, fmt.Errorf("enroll response had no peers")
	}
	priv, err := kp.PrivateB64()
	if err != nil {
		return nil, err
	}
	peer := acc.Config.Peers[0]
	ports := peer.Endpoint.Ports
	if len(ports) == 0 {
		ports = []int{443}
	}
	return &Identity{
		PrivateKey:    priv,
		AccessToken:   token,
		ID:            acc.ID,
		EndpointV4:    stripPort(peer.Endpoint.V4),
		EndpointV6:    stripPort(peer.Endpoint.V6),
		EndpointH2V4:  DefaultEndpointH2,
		EndpointPorts: ports,
		PeerPubKeyPEM: peer.PublicKey,
		IPv4:          acc.Config.Interface.Addresses.V4,
		IPv6:          acc.Config.Interface.Addresses.V6,
	}, nil
}

// stripPort removes ":port" from an endpoint string and any v6 brackets.
func stripPort(s string) string {
	if host, _, err := net.SplitHostPort(s); err == nil {
		return host
	}
	return strings.Trim(s, "[]")
}

// apiAccount is the registration API response shape (fields we consume).
type apiAccount struct {
	ID     string `json:"id"`
	Token  string `json:"token"`
	Config struct {
		Peers []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				V4    string `json:"v4"`
				V6    string `json:"v6"`
				Ports []int  `json:"ports"`
			} `json:"endpoint"`
		} `json:"peers"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
	} `json:"config"`
}

// resolveViaDoH answers a hostname's A records through the JSON DoH API on
// 1.1.1.1 (SNI stays cloudflare-dns.com, so a poisoned api hostname cannot
// affect it).
func resolveViaDoH(ctx context.Context, host string) ([]string, error) {
	url := "https://" + DoHResolver + "/dns-query?name=" + host + "&type=A"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("doh query %s: %w", host, err)
	}
	defer resp.Body.Close()
	var answer struct {
		Answer []struct {
			Type int    `json:"type"` // 1 = A
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&answer); err != nil {
		return nil, fmt.Errorf("doh decode: %w", err)
	}
	var out []string
	for _, a := range answer.Answer {
		if a.Type == 1 && net.ParseIP(a.Data) != nil {
			out = append(out, a.Data)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("doh: no A record for %s", host)
	}
	return out, nil
}

// Delete removes the device registration from Cloudflare's API. A missing
// registration (404/403) counts as success: the goal is only that the old
// identity stops existing.
func (c *Client) Delete(ctx context.Context, id *Identity) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		strings.TrimRight(c.baseURL, "/")+"/"+APIVersion+"/reg/"+id.ID, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", APIUserAgent)
	req.Header.Set("CF-Client-Version", APIClientVersion)
	req.Header.Set("Authorization", "Bearer "+id.AccessToken)
	if c.pinAddr != "" {
		req.Host = req.URL.Host
		req.URL.Host = net.JoinHostPort(c.pinAddr, "443")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusForbidden {
		return nil
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("warp api delete: %d", resp.StatusCode)
	}
	return nil
}

// RegisterAuto registers through the direct client and falls back to the DoH
// bypass when the direct attempt fails (e.g. poisoned DNS).
func RegisterAuto(ctx context.Context, opts Options) (*Identity, error) {
	direct := NewClient()
	id, err := direct.Register(ctx, opts)
	if err == nil {
		return id, nil
	}
	bypass, bypassErr := NewDoHClient(ctx)
	if bypassErr != nil {
		return nil, fmt.Errorf("direct register failed (%v); DoH bypass unavailable (%v)",
			err, bypassErr)
	}
	if id2, err2 := bypass.Register(ctx, opts); err2 == nil {
		return id2, nil
	} else {
		return nil, fmt.Errorf("register failed (direct: %v; doh-bypass: %v)", err, err2)
	}
}
