package masque

import (
	"encoding/base64"
	"testing"
)

func TestKeypairRoundtrips(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	b64, err := kp.PrivateB64()
	if err != nil {
		t.Fatalf("private b64: %v", err)
	}
	restored, err := KeypairFromPrivateB64(b64)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	got, err := restored.PublicSPKIB64()
	if err != nil {
		t.Fatalf("public b64: %v", err)
	}
	want, err := kp.PublicSPKIB64()
	if err != nil {
		t.Fatalf("public b64: %v", err)
	}
	if got != want {
		t.Error("restored keypair has a different public key")
	}
}

func TestKeyEncodingsAreBase64DER(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	priv, err := kp.PrivateB64()
	if err != nil {
		t.Fatalf("private b64: %v", err)
	}
	privDER, err := base64.StdEncoding.DecodeString(priv)
	if err != nil {
		t.Fatalf("decode private: %v", err)
	}
	// SEC1 EC private keys start with the SEQUENCE tag 0x30.
	if privDER[0] != 0x30 {
		t.Errorf("private DER starts with %#x, want 0x30", privDER[0])
	}
	pub, err := kp.PublicSPKIB64()
	if err != nil {
		t.Fatalf("public b64: %v", err)
	}
	pubDER, err := base64.StdEncoding.DecodeString(pub)
	if err != nil {
		t.Fatalf("decode public: %v", err)
	}
	// SPKI P-256 public keys start with 0x30 and are 91 bytes.
	if pubDER[0] != 0x30 || len(pubDER) != 91 {
		t.Errorf("public DER = %d bytes starting %#x, want 91 bytes starting 0x30",
			len(pubDER), pubDER[0])
	}
}

func TestRegistrationHelpersShape(t *testing.T) {
	serial, err := randomAndroidSerial()
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	if len(serial) != 16 {
		t.Errorf("serial = %q, want 16 chars", serial)
	}
	wg, err := randomWGPubkeyB64()
	if err != nil {
		t.Fatalf("wg key: %v", err)
	}
	// 32 bytes base64 = 44 chars including padding.
	if len(wg) != 44 {
		t.Errorf("wg key = %d chars, want 44", len(wg))
	}
}
