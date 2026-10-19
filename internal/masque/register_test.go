package masque

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeAPI is a stand-in for the registration API: it records the calls and
// answers a fixed enroll response whose peer key is realPEM.
func fakeAPI(t *testing.T, realPEM string) (*httptest.Server, *[]apiCall) {
	t.Helper()
	calls := &[]apiCall{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*calls = append(*calls, apiCall{method: r.Method, path: r.URL.Path, auth: r.Header.Get("Authorization")})
		if r.Method == http.MethodPost {
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["key_type"] != "curve25519" || body["tunnel_type"] != "wireguard" {
				t.Errorf("step 1 key/tunnel type = %s/%s", body["key_type"], body["tunnel_type"])
			}
			if body["serial_number"] == "" || body["tos"] == "" || len(body["key"]) != 44 {
				t.Errorf("step 1 body incomplete: %v", body)
			}
			fmt.Fprintf(w, `{"id":"dev-1","token":"tok-1"}`)
			return
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["key_type"] != "secp256r1" || body["tunnel_type"] != "masque" {
			t.Errorf("step 2 key/tunnel type = %s/%s", body["key_type"], body["tunnel_type"])
		}
		// The enrolled key must be a real P-256 SPKI.
		der, err := base64.StdEncoding.DecodeString(body["key"])
		if err != nil {
			t.Errorf("enroll key not base64: %v", err)
		} else if pub, err := x509.ParsePKIXPublicKey(der); err != nil {
			t.Errorf("enroll key not SPKI: %v", err)
		} else if _, ok := pub.(*ecdsa.PublicKey); !ok {
			t.Errorf("enroll key is %T, want *ecdsa.PublicKey", pub)
		}
		fmt.Fprintf(w, `{"id":"dev-1","config":{
			"peers":[{"public_key":%q,"endpoint":{"v4":"162.159.198.1:0","v6":"[2606:4700:103::]:0",
			"ports":[443,500,1701,4500]}}],
			"interface":{"addresses":{"v4":"100.96.0.3/32","v6":"2606:4700:110::1/128"}}}}`,
			realPEM)
	}))
	t.Cleanup(srv.Close)
	return srv, calls
}

type apiCall struct{ method, path, auth string }

func TestRegisterFlow(t *testing.T) {
	realPEM := pemPub(t)
	srv, calls := fakeAPI(t, realPEM)

	c := &Client{baseURL: srv.URL, http: srv.Client()}
	id, err := c.Register(context.Background(), Options{Name: "probe"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if len(*calls) != 2 {
		t.Fatalf("api calls = %d, want 2", len(*calls))
	}
	if (*calls)[0].method != http.MethodPost || (*calls)[0].path != "/v0a4471/reg" {
		t.Errorf("call 0 = %s %s, want POST /v0a4471/reg", (*calls)[0].method, (*calls)[0].path)
	}
	if (*calls)[1].method != http.MethodPatch || (*calls)[1].path != "/v0a4471/reg/dev-1" {
		t.Errorf("call 1 = %s %s", (*calls)[1].method, (*calls)[1].path)
	}
	if (*calls)[1].auth != "Bearer tok-1" {
		t.Errorf("enroll auth = %q, want bearer token", (*calls)[1].auth)
	}
	if id.ID != "dev-1" || id.AccessToken != "tok-1" {
		t.Errorf("id = %s/%s", id.ID, id.AccessToken)
	}
	if id.EndpointV4 != "162.159.198.1" {
		t.Errorf("endpoint v4 = %q, want host without port", id.EndpointV4)
	}
	if id.EndpointV6 != "2606:4700:103::" {
		t.Errorf("endpoint v6 = %q, want unbracketed host", id.EndpointV6)
	}
	if id.IPv4 != "100.96.0.3/32" || id.IPv6 != "2606:4700:110::1/128" {
		t.Errorf("assigned addresses = %s / %s", id.IPv4, id.IPv6)
	}
	if id.PeerPubKeyPEM != realPEM {
		t.Error("peer public key not carried through")
	}
	wantPorts := []int{443, 500, 1701, 4500}
	if len(id.EndpointPorts) != len(wantPorts) {
		t.Fatalf("endpoint ports = %v, want %v", id.EndpointPorts, wantPorts)
	}
	for i, p := range wantPorts {
		if id.EndpointPorts[i] != p {
			t.Errorf("port[%d] = %d, want %d", i, id.EndpointPorts[i], p)
		}
	}
	// The identity must restore into the keypair whose key was enrolled.
	kp, err := id.Keypair()
	if err != nil {
		t.Fatalf("keypair from identity: %v", err)
	}
	spki, err := kp.PublicSPKIB64()
	if err != nil {
		t.Fatalf("spki: %v", err)
	}
	der, _ := base64.StdEncoding.DecodeString(spki)
	pub, _ := x509.ParsePKIXPublicKey(der)
	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		t.Errorf("restored key is %T, want P-256", pub)
	}
}

func TestRegisterMissingTokenFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"id":"dev-1"}`)
	}))
	defer srv.Close()
	c := &Client{baseURL: srv.URL, http: srv.Client()}
	if _, err := c.Register(context.Background(), Options{}); err == nil {
		t.Error("register succeeded without a token in the response")
	}
}

func TestRegisterAPIErrorSurfacesBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"success":false,"errors":[{"code":1020}]}`)
	}))
	defer srv.Close()
	c := &Client{baseURL: srv.URL, http: srv.Client()}
	_, err := c.Register(context.Background(), Options{})
	if err == nil {
		t.Fatal("register succeeded against a 403")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error %q does not carry the status", err)
	}
}

func TestIdentitySaveLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadIdentity(dir); err == nil {
		t.Error("load succeeded in an empty state dir")
	}
	id := &Identity{
		PrivateKey:    "priv",
		AccessToken:   "tok",
		ID:            "dev-9",
		EndpointV4:    "162.159.198.1",
		PeerPubKeyPEM: "-----BEGIN PUBLIC KEY-----",
		IPv4:          "100.96.0.3/32",
	}
	if err := id.Save(dir); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := LoadIdentity(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.ID != "dev-9" || got.EndpointV4 != "162.159.198.1" || got.IPv4 != "100.96.0.3/32" {
		t.Errorf("roundtrip mismatch: %+v", got)
	}
}

func TestTunnelEndpointPreference(t *testing.T) {
	id := &Identity{EndpointV4: "162.159.198.1"}
	got, err := id.TunnelEndpoint()
	if err != nil || got != "162.159.198.1:443" {
		t.Errorf("v4 endpoint = %q, err %v", got, err)
	}
	id = &Identity{EndpointV6: "2606:4700:103::"}
	got, err = id.TunnelEndpoint()
	if err != nil || got != "[2606:4700:103::]:443" {
		t.Errorf("v6 endpoint = %q, err %v", got, err)
	}
	if _, err := (&Identity{}).TunnelEndpoint(); err == nil {
		t.Error("empty identity produced an endpoint")
	}
}

// pemPub renders a real P-256 public key as the PEM the API returns.
func pemPub(t *testing.T) string {
	t.Helper()
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&kp.Key().PublicKey)
	if err != nil {
		t.Fatalf("spki: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}
