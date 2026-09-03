package main

import (
	"crypto/rsa"
	"encoding/base64"
	"testing"

	"github.com/International-Combat-Archery-Alliance/auth/token"
	"github.com/International-Combat-Archery-Alliance/login/api"
)

func TestKeypairJWKSDeterministicOrder(t *testing.T) {
	keys := map[string]*rsa.PrivateKey{}
	for _, kid := range []string{"machine-z", "machine-a", "machine-m"} {
		priv, _, err := token.GenerateMachineDevKeypair()
		if err != nil {
			t.Fatalf("generate dev keypair: %v", err)
		}
		keys[kid] = priv
	}

	jwks := keypairJWKS(keys)

	if len(jwks.Keys) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(jwks.Keys))
	}
	want := []string{"machine-a", "machine-m", "machine-z"}
	for i, jwk := range jwks.Keys {
		if jwk.Kid != want[i] {
			t.Fatalf("key order not deterministic: index %d = %q, want %q (all: %v)",
				i, jwk.Kid, want[i], jwkKids(jwks))
		}
		assertJWKShape(t, jwk, keys[jwk.Kid])
	}
}

func TestKeypairJWKSSingleKey(t *testing.T) {
	priv, _, err := token.GenerateMachineDevKeypair()
	if err != nil {
		t.Fatalf("generate dev keypair: %v", err)
	}

	jwks := keypairJWKS(map[string]*rsa.PrivateKey{"machine-01": priv})

	if len(jwks.Keys) != 1 || jwks.Keys[0].Kid != "machine-01" {
		t.Fatalf("unexpected jwks: %+v", jwks.Keys)
	}
	assertJWKShape(t, jwks.Keys[0], priv)
}

func assertJWKShape(t *testing.T, jwk api.JWK, priv *rsa.PrivateKey) {
	t.Helper()
	if jwk.Kty != api.RSA {
		t.Errorf("kty = %q, want RSA", jwk.Kty)
	}
	if jwk.Alg == nil || *jwk.Alg != api.RS256 {
		t.Errorf("alg = %v, want RS256", jwk.Alg)
	}
	if jwk.Use == nil || *jwk.Use != api.Sig {
		t.Errorf("use = %v, want sig", jwk.Use)
	}
	if _, err := base64.RawURLEncoding.DecodeString(jwk.N); err != nil {
		t.Errorf("n is not base64url: %v", err)
	}
	if _, err := base64.RawURLEncoding.DecodeString(jwk.E); err != nil {
		t.Errorf("e is not base64url: %v", err)
	}
}

func jwkKids(jwks api.JWKS) []string {
	kids := make([]string, len(jwks.Keys))
	for i, k := range jwks.Keys {
		kids[i] = k.Kid
	}
	return kids
}