package api

import (
	"context"
	"crypto/rsa"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/International-Combat-Archery-Alliance/auth"
	"github.com/International-Combat-Archery-Alliance/auth/token"
	"github.com/International-Combat-Archery-Alliance/middleware"
)

// memRefreshStore is an in-memory token.RefreshTokenStore for handler tests.
type memRefreshStore struct {
	mu     sync.Mutex
	tokens map[string]token.RefreshTokenData
}

func newMemRefreshStore() *memRefreshStore {
	return &memRefreshStore{tokens: map[string]token.RefreshTokenData{}}
}

func (m *memRefreshStore) Save(_ context.Context, tokenID string, data token.RefreshTokenData, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[tokenID] = data
	return nil
}

func (m *memRefreshStore) Get(_ context.Context, tokenID string) (*token.RefreshTokenData, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.tokens[tokenID]
	if !ok {
		return nil, token.ErrTokenNotFound
	}
	return &data, nil
}

func (m *memRefreshStore) Delete(_ context.Context, tokenID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.tokens, tokenID)
	return nil
}

// logoutTestAPI builds an API with a real user-token signer and an
// in-memory refresh store, so logout revocation is tested end to end.
func logoutTestAPI(t *testing.T) (*API, *token.UserTokenSigner, *memRefreshStore) {
	t.Helper()
	priv, _, err := token.GenerateUserDevKeypair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	signer, err := token.NewUserTokenSigner(
		map[string]*rsa.PrivateKey{"user-test": priv}, "user-test")
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	store := newMemRefreshStore()

	a := NewAPI(Config{
		UserTokens:        signer,
		RefreshTokenStore: store,
		JWKSProvider:      fakeJWKSProvider{jwks: JWKS{Keys: []JWK{}}},
		Logger:            slog.New(slog.DiscardHandler),
		Environment:       PROD,
	})
	return a, signer, store
}

// testAuthToken is a minimal auth.AuthToken for handler tests.
type testAuthToken struct{}

func (testAuthToken) ExpiresAt() time.Time  { return time.Now().Add(time.Hour) }
func (testAuthToken) ProfilePicURL() string { return "" }
func (testAuthToken) IsAdmin() bool         { return false }
func (testAuthToken) UserEmail() string     { return "u@icaa.world" }
func (testAuthToken) Roles() []auth.Role    { return nil }

func TestDeleteLoginSessionRevokesRefreshToken(t *testing.T) {
	a, signer, store := logoutTestAPI(t)
	ctx := context.Background()

	tokenID, _, expiresAt, err := signer.GenerateRefreshToken()
	if err != nil {
		t.Fatalf("mint refresh token: %v", err)
	}
	if err := store.Save(ctx, tokenID, token.RefreshTokenData{UserEmail: "u@icaa.world"}, expiresAt); err != nil {
		t.Fatalf("save refresh token: %v", err)
	}

	ctx = middleware.CtxWithJWT(ctx, testAuthToken{})
	ctx = middleware.CtxWithRefreshTokenID(ctx, tokenID)
	resp, err := a.DeleteLoginSession(ctx, DeleteLoginSessionRequestObject{})
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	if _, ok := resp.(DeleteLoginSession200Response); !ok {
		t.Fatalf("expected 200 response, got %T", resp)
	}

	if _, err := store.Get(ctx, tokenID); err == nil {
		t.Fatal("expected refresh token to be revoked after logout")
	}
}

func TestDeleteLoginSessionWithoutRefreshTokenStillClearsCookies(t *testing.T) {
	a, _, _ := logoutTestAPI(t)

	ctx := middleware.CtxWithJWT(context.Background(), testAuthToken{})
	resp, err := a.DeleteLoginSession(ctx, DeleteLoginSessionRequestObject{})
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	got, ok := resp.(DeleteLoginSession200Response)
	if !ok {
		t.Fatalf("expected 200 response, got %T", resp)
	}
	if len(got.Headers.SetCookie) != 2 {
		t.Fatalf("expected access + refresh clearing cookies, got %d Set-Cookie headers", len(got.Headers.SetCookie))
	}
}
