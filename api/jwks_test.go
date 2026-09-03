package api

import (
	"context"
	"errors"
	"testing"

	"github.com/International-Combat-Archery-Alliance/login/m2m"
)

func TestGetLoginWellKnownJwksJson(t *testing.T) {
	store := &fakeM2MStore{window: &m2m.RateWindow{WindowCount: 1}}
	a, _, _ := testAPI(t, store)
	a.jwksProvider = fakeJWKSProvider{jwks: JWKS{
		Keys: []JWK{{
			Kty: "RSA",
			Kid: "machine-test",
			N:   "abc",
			E:   "AQAB",
		}},
	}}

	resp, err := a.GetLoginWellKnownJwksJson(context.Background(), GetLoginWellKnownJwksJsonRequestObject{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	jwksResp, ok := resp.(GetLoginWellKnownJwksJson200JSONResponse)
	if !ok {
		t.Fatalf("expected 200 response, got %T", resp)
	}
	if jwksResp.Headers.CacheControl != "public, max-age=300, stale-while-revalidate=3600" {
		t.Fatalf("unexpected Cache-Control: %q", jwksResp.Headers.CacheControl)
	}
	if len(jwksResp.Body.Keys) != 1 || jwksResp.Body.Keys[0].Kid != "machine-test" {
		t.Fatalf("unexpected jwks body: %+v", jwksResp.Body)
	}
}

func TestGetLoginWellKnownJwksJsonProviderFailure(t *testing.T) {
	store := &fakeM2MStore{window: &m2m.RateWindow{WindowCount: 1}}
	a, _, _ := testAPI(t, store)
	a.jwksProvider = failingJWKSProvider{}

	resp, err := a.GetLoginWellKnownJwksJson(context.Background(), GetLoginWellKnownJwksJsonRequestObject{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := resp.(GetLoginWellKnownJwksJson500JSONResponse); !ok {
		t.Fatalf("expected 500 response, got %T", resp)
	}
}

// fakeJWKSProvider returns a fixed key set.
type fakeJWKSProvider struct {
	jwks JWKS
}

func (f fakeJWKSProvider) PublicJWKS(context.Context) (JWKS, error) {
	return f.jwks, nil
}

// failingJWKSProvider simulates a signing-key load failure.
type failingJWKSProvider struct{}

func (failingJWKSProvider) PublicJWKS(context.Context) (JWKS, error) {
	return JWKS{}, errors.New("ssm unreachable")
}
