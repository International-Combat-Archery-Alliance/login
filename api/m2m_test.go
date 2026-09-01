package api

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/International-Combat-Archery-Alliance/auth/token"
	"github.com/International-Combat-Archery-Alliance/login/dynamo"
	"golang.org/x/crypto/bcrypt"
)

const (
	testClientID = "event-registration"
	testSecret   = "test-secret-value-that-is-longer-than-32-bytes!!"
)

// fakeM2MStore is an in-memory M2MStore for handler tests.
type fakeM2MStore struct {
	client        *dynamo.MachineClientItem
	window        *dynamo.RateWindow
	windowLimit   int64
	recordFailErr error
	failures      int
	resets        int
}

func (f *fakeM2MStore) GetClient(ctx context.Context, clientID string) (*dynamo.MachineClientItem, error) {
	if f.client == nil || f.client.PK != dynamo.MachineClientPrefix+clientID {
		return nil, nil
	}
	return f.client, nil
}

func (f *fakeM2MStore) BumpWindow(ctx context.Context, clientID string, now time.Time) (*dynamo.RateWindow, error) {
	return f.window, nil
}

func (f *fakeM2MStore) RecordFailure(ctx context.Context, clientID string, now time.Time) error {
	f.failures++
	return f.recordFailErr
}

func (f *fakeM2MStore) ResetFailures(ctx context.Context, clientID string, now time.Time) error {
	f.resets++
	return nil
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

func testClientItem(secret string) *dynamo.MachineClientItem {
	hash, _ := bcrypt.GenerateFromPassword([]byte(secret), m2mBcryptCost)
	now := time.Now().UTC()
	return &dynamo.MachineClientItem{
		PK:           dynamo.MachineClientPrefix + testClientID,
		SK:           dynamo.MachineClientPrefix + testClientID,
		SecretRounds: []string{string(hash)},
		Audience:     "profiles-api",
		Scopes:       []string{"m2m:player-profiles"},
		Active:       true,
		CreatedAt:    now,
		UpdatedAt:    now,
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
		window: &dynamo.RateWindow{WindowCount: 1, FailCount: 0},
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
	if store.resets != 1 {
		t.Fatalf("expected 1 reset, got %d", store.resets)
	}

	// End-to-end: the issued token verifies against the public key with the
	// auth lib, with the client's audience + exact scope enforced.
	claims, err := validateWithTestCache(t, priv, tokenResp.AccessToken, "profiles-api", "m2m:player-profiles")
	if err != nil {
		t.Fatalf("issued token must verify: %v", err)
	}
	if claims.Subject != testClientID {
		t.Fatalf("expected sub %q, got %q", testClientID, claims.Subject)
	}
}

func TestPostLoginV1M2mTokensWrongSecret(t *testing.T) {
	store := &fakeM2MStore{client: testClientItem(testSecret), window: &dynamo.RateWindow{WindowCount: 1}}
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
	if store.failures != 1 {
		t.Fatalf("expected 1 recorded failure, got %d", store.failures)
	}
}

func TestPostLoginV1M2mTokensUnknownClient(t *testing.T) {
	store := &fakeM2MStore{window: &dynamo.RateWindow{WindowCount: 1}}
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
	if store.failures != 1 {
		t.Fatalf("expected 1 recorded failure, got %d", store.failures)
	}
}

func TestPostLoginV1M2mTokensInactiveClient(t *testing.T) {
	client := testClientItem(testSecret)
	client.Active = false
	store := &fakeM2MStore{client: client, window: &dynamo.RateWindow{WindowCount: 1}}
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
}

func TestPostLoginV1M2mTokensRotationGraceWindow(t *testing.T) {
	// Old round + new round in secretRounds[]: both must be accepted until the
	// old round is removed (ADR-0006 appendix: rotation grace).
	hash, _ := bcrypt.GenerateFromPassword([]byte("old-secret-value"), m2mBcryptCost)
	client := testClientItem(testSecret)
	client.SecretRounds = []string{string(hash), client.SecretRounds[0]}
	store := &fakeM2MStore{client: client, window: &dynamo.RateWindow{WindowCount: 1}}
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

func TestPostLoginV1M2mTokensLockedOut(t *testing.T) {
	lockedUntil := time.Now().Add(15 * time.Minute)
	store := &fakeM2MStore{
		client: testClientItem(testSecret),
		window: &dynamo.RateWindow{WindowCount: 1, FailCount: 5, LockedUntil: &lockedUntil},
	}
	a, _, _ := testAPI(t, store)

	resp, err := a.PostLoginV1M2mTokens(context.Background(), PostLoginV1M2mTokensRequestObject{
		Params: PostLoginV1M2mTokensParams{Authorization: basicAuthHeader(testClientID, testSecret)},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := resp.(PostLoginV1M2mTokens429JSONResponse); !ok {
		t.Fatalf("expected 429 while locked out, got %T", resp)
	}
	if store.failures != 0 {
		t.Fatalf("locked requests must not count failures (bcrypt skipped), got %d", store.failures)
	}
}

func TestPostLoginV1M2mTokensWindowExceeded(t *testing.T) {
	store := &fakeM2MStore{
		client:      testClientItem(testSecret),
		window:      &dynamo.RateWindow{WindowCount: 31},
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
	store := &fakeM2MStore{window: &dynamo.RateWindow{WindowCount: 1}}
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

func TestPostLoginV1M2mTokensRecordFailureErrorStill401(t *testing.T) {
	// An unknown client is an auth failure regardless of whether the failure
	// counter could be updated (counter is fail-open, verdict is fail-closed).
	store := &fakeM2MStore{window: &dynamo.RateWindow{WindowCount: 1}, recordFailErr: errors.New("dynamo down")}
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
}

// validateWithTestCache verifies a machine token with the authenticating
// service side (auth lib KeyCache with the dev public key).
func validateWithTestCache(t *testing.T, priv *rsa.PrivateKey, tokenString, audience, scope string) (*token.MachineTokenClaims, error) {
	t.Helper()
	cache := token.NewKeyCache("",
		token.WithDevKeys(map[string]*rsa.PublicKey{"machine-test": &priv.PublicKey}),
	)
	return cache.ValidateMachineToken(context.Background(), tokenString, audience, scope)
}
