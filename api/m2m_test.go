package api

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/International-Combat-Archery-Alliance/auth/token"
	"github.com/International-Combat-Archery-Alliance/login/m2m"
	"golang.org/x/crypto/bcrypt"
)

const (
	testClientID = "event-registration"
	testSecret   = "test-secret-value-that-is-longer-than-32-bytes!!"
)

// fakeM2MStore is an in-memory m2m.Store for adapter tests.
type fakeM2MStore struct {
	client      *m2m.Client
	window      *m2m.RateWindow
	windowLimit int64
	bumps       int
}

func (f *fakeM2MStore) GetClient(ctx context.Context, clientID string) (*m2m.Client, error) {
	if f.client == nil || f.client.ID != clientID {
		return nil, nil
	}
	return f.client, nil
}

func (f *fakeM2MStore) BumpWindow(ctx context.Context, clientID string) (*m2m.RateWindow, error) {
	f.bumps++
	return f.window, nil
}

func (f *fakeM2MStore) WindowLimit() int64 {
	if f.windowLimit == 0 {
		return 30
	}
	return f.windowLimit
}

// testAPI builds an API with a fixed machine keypair + fake store.
func testAPI(t *testing.T, store *fakeM2MStore) (*API, *rsa.PrivateKey, *token.MachineTokenSigner) {
	t.Helper()
	priv, _, err := token.GenerateMachineDevKeypair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	keys := map[string]*rsa.PrivateKey{"machine-test": priv}
	signer, err := token.NewMachineTokenSigner(keys, "machine-test")
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	api := NewAPI(Config{
		MachineTokenSigner: signer,
		M2MStore:           store,
		JWKSProvider:       fakeJWKSProvider{jwks: JWKS{Keys: []JWK{}}},
		Logger:             slog.New(slog.DiscardHandler),
		Environment:        PROD,
	})
	return api, priv, signer
}

func testClientItem(secret string) *m2m.Client {
	hash, _ := bcrypt.GenerateFromPassword([]byte(secret), m2m.BcryptCost)
	return &m2m.Client{
		ID:           testClientID,
		SecretRounds: []string{string(hash)},
		Audience:     "profiles-api",
		Scopes:       []string{"m2m:player-profiles"},
		Active:       true,
	}
}

func basicAuthHeader(clientID, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(clientID+":"+secret))
}

func b64Std(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func TestPostLoginV1M2mTokensHappyPath(t *testing.T) {
	store := &fakeM2MStore{
		client: testClientItem(testSecret),
		window: &m2m.RateWindow{WindowCount: 1},
	}
	a, priv, _ := testAPI(t, store)

	resp, err := a.PostLoginV1M2mTokens(context.Background(), PostLoginV1M2mTokensRequestObject{
		Params: PostLoginV1M2mTokensParams{Authorization: basicAuthHeader(testClientID, testSecret)},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tokenResp, ok := resp.(PostLoginV1M2mTokens200JSONResponse)
	if !ok {
		t.Fatalf("expected 200 response, got %T", resp)
	}
	if tokenResp.TokenType != "Bearer" {
		t.Fatalf("expected token_type Bearer, got %q", tokenResp.TokenType)
	}
	if tokenResp.ExpiresIn != 300 {
		t.Fatalf("expected expires_in 300, got %d", tokenResp.ExpiresIn)
	}
	if store.bumps != 1 {
		t.Fatalf("expected 1 bump, got %d", store.bumps)
	}

	claims, err := validateWithTestCache(t, priv, tokenResp.AccessToken, "profiles-api", "m2m:player-profiles")
	if err != nil {
		t.Fatalf("issued token must verify: %v", err)
	}
	if claims.Subject != testClientID {
		t.Fatalf("expected sub %q, got %q", testClientID, claims.Subject)
	}
}

func TestPostLoginV1M2mTokensWrongSecret(t *testing.T) {
	store := &fakeM2MStore{client: testClientItem(testSecret), window: &m2m.RateWindow{WindowCount: 1}}
	a, _, _ := testAPI(t, store)

	resp, err := a.PostLoginV1M2mTokens(context.Background(), PostLoginV1M2mTokensRequestObject{
		Params: PostLoginV1M2mTokensParams{Authorization: basicAuthHeader(testClientID, "wrong-secret")},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := resp.(PostLoginV1M2mTokens401JSONResponse); !ok {
		t.Fatalf("expected 401 response, got %T", resp)
	}
}

func TestPostLoginV1M2mTokensUnknownClient(t *testing.T) {
	store := &fakeM2MStore{window: &m2m.RateWindow{WindowCount: 1}}
	a, _, _ := testAPI(t, store)

	resp, err := a.PostLoginV1M2mTokens(context.Background(), PostLoginV1M2mTokensRequestObject{
		Params: PostLoginV1M2mTokensParams{Authorization: basicAuthHeader("unknown-client", testSecret)},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := resp.(PostLoginV1M2mTokens401JSONResponse); !ok {
		t.Fatalf("expected 401 response, got %T", resp)
	}
	if store.bumps != 0 {
		t.Fatalf("unknown client must not bump window, got %d", store.bumps)
	}
}

func TestPostLoginV1M2mTokensInactiveClient(t *testing.T) {
	client := testClientItem(testSecret)
	client.Active = false
	store := &fakeM2MStore{client: client, window: &m2m.RateWindow{WindowCount: 1}}
	a, _, _ := testAPI(t, store)

	resp, err := a.PostLoginV1M2mTokens(context.Background(), PostLoginV1M2mTokensRequestObject{
		Params: PostLoginV1M2mTokensParams{Authorization: basicAuthHeader(testClientID, testSecret)},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := resp.(PostLoginV1M2mTokens401JSONResponse); !ok {
		t.Fatalf("expected 401 response for inactive client, got %T", resp)
	}
	if store.bumps != 0 {
		t.Fatalf("inactive client must not bump window, got %d", store.bumps)
	}
}

func TestPostLoginV1M2mTokensRotationGraceWindow(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("old-secret-value"), m2m.BcryptCost)
	client := testClientItem(testSecret)
	client.SecretRounds = []string{string(hash), client.SecretRounds[0]}
	store := &fakeM2MStore{client: client, window: &m2m.RateWindow{WindowCount: 1}}
	a, _, _ := testAPI(t, store)

	resp, err := a.PostLoginV1M2mTokens(context.Background(), PostLoginV1M2mTokensRequestObject{
		Params: PostLoginV1M2mTokensParams{Authorization: basicAuthHeader(testClientID, "old-secret-value")},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := resp.(PostLoginV1M2mTokens200JSONResponse); !ok {
		t.Fatalf("expected 200 with old round still in secretRounds, got %T", resp)
	}
}

func TestPostLoginV1M2mTokensWindowExceeded(t *testing.T) {
	store := &fakeM2MStore{
		client:      testClientItem(testSecret),
		window:      &m2m.RateWindow{WindowCount: 31},
		windowLimit: 30,
	}
	a, _, _ := testAPI(t, store)

	resp, err := a.PostLoginV1M2mTokens(context.Background(), PostLoginV1M2mTokensRequestObject{
		Params: PostLoginV1M2mTokensParams{Authorization: basicAuthHeader(testClientID, testSecret)},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := resp.(PostLoginV1M2mTokens429JSONResponse); !ok {
		t.Fatalf("expected 429 over window limit, got %T", resp)
	}
}

func TestPostLoginV1M2mTokensBadCredentialsFormat(t *testing.T) {
	store := &fakeM2MStore{window: &m2m.RateWindow{WindowCount: 1}}
	a, _, _ := testAPI(t, store)

	tests := []struct {
		name   string
		header string
	}{
		{name: "empty header", header: ""},
		{name: "not basic", header: "Bearer abc"},
		{name: "bad base64", header: "Basic not-base64!!"},
		{name: "missing colon", header: "Basic " + b64Std("justanid")},
		{name: "empty secret", header: "Basic " + b64Std(testClientID+":")},
		{name: "empty client", header: "Basic " + b64Std(":"+testSecret)},
		{name: "oversized client id", header: "Basic " + b64Std(strings.Repeat("c", maxM2MClientIDLen+1)+":"+testSecret)},
		{name: "oversized secret", header: "Basic " + b64Std(testClientID+":"+strings.Repeat("s", maxM2MSecretLen+1))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := a.PostLoginV1M2mTokens(context.Background(), PostLoginV1M2mTokensRequestObject{
				Params: PostLoginV1M2mTokensParams{Authorization: tt.header},
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if _, ok := resp.(PostLoginV1M2mTokens400JSONResponse); !ok {
				t.Fatalf("expected 400 response, got %T", resp)
			}
		})
	}
}

func TestPostLoginV1M2mTokensExpiresInMatchesLifetime(t *testing.T) {
	priv, _, err := token.GenerateMachineDevKeypair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	keys := map[string]*rsa.PrivateKey{"machine-test": priv}
	signer, err := token.NewMachineTokenSigner(keys, "machine-test",
		token.WithMachineTokenLifetime(10*time.Minute))
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	a := NewAPI(Config{
		MachineTokenSigner:   signer,
		MachineTokenLifetime: 10 * time.Minute,
		M2MStore: &fakeM2MStore{
			client: testClientItem(testSecret),
			window: &m2m.RateWindow{WindowCount: 1},
		},
		JWKSProvider: fakeJWKSProvider{jwks: JWKS{Keys: []JWK{}}},
		Logger:       slog.New(slog.DiscardHandler),
		Environment:  PROD,
	})

	resp, err := a.PostLoginV1M2mTokens(context.Background(), PostLoginV1M2mTokensRequestObject{
		Params: PostLoginV1M2mTokensParams{Authorization: basicAuthHeader(testClientID, testSecret)},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tokenResp, ok := resp.(PostLoginV1M2mTokens200JSONResponse)
	if !ok {
		t.Fatalf("expected 200 response, got %T", resp)
	}
	if tokenResp.ExpiresIn != 600 {
		t.Fatalf("expected expires_in 600, got %d", tokenResp.ExpiresIn)
	}
}

// validateWithTestCache verifies a machine token with the authenticating
// service side (auth lib KeyCache with the dev public key).
func validateWithTestCache(t *testing.T, priv *rsa.PrivateKey, tokenString, audience, scope string) (*token.MachineTokenClaims, error) {
	t.Helper()
	cache := token.NewKeyCache("",
		token.WithLocalMode(),
		token.WithDevKeys(map[string]*rsa.PublicKey{"machine-test": &priv.PublicKey}),
	)
	return cache.ValidateMachineToken(context.Background(), tokenString, audience, scope)
}
