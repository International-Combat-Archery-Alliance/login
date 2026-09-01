package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"
)

func generateECKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func TestParseRSAJWTSigningKeysJSON(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	raw, err := json.Marshal(map[string]any{
		"currentKey": "machine-01",
		"keys":       map[string]string{"machine-01": pemStr, "machine-00": pemStr},
	})
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}

	keys, current, err := parseRSAJWTSigningKeysJSON(string(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if current != "machine-01" {
		t.Fatalf("expected currentKey machine-01, got %q", current)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
	if !keys["machine-01"].PublicKey.Equal(&priv.PublicKey) {
		t.Fatal("parsed key does not match generated key")
	}
}

func TestParseRSAJWTSigningKeysJSONErrors(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{name: "not json", raw: "not json"},
		{name: "missing currentKey", raw: `{"keys":{}}`},
		{name: "currentKey not in keys", raw: `{"currentKey":"machine-01","keys":{}}`},
		{name: "garbage pem", raw: `{"currentKey":"machine-01","keys":{"machine-01":"not-a-pem"}}`},
		{name: "empty", raw: ``},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := parseRSAJWTSigningKeysJSON(tt.raw); err == nil {
				t.Fatalf("expected error for %q", tt.raw)
			}
		})
	}
}

func TestParseRSAPrivateKeyPEMRejectsNonRSA(t *testing.T) {
	// EC key must be rejected (only RSA is accepted for JWKS/RS256).
	ecKey, err := generateECKey()
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatalf("marshal ec key: %v", err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	if _, err := parseRSAPrivateKeyPEM(pemStr); err == nil {
		t.Fatal("expected non-RSA key to be rejected")
	}
}
