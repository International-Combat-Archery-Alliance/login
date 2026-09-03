package m2m

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type fakeStore struct {
	client      *Client
	window      *RateWindow
	windowLimit int64
	bumps       int
	bumpErr     error
}

func (f *fakeStore) GetClient(_ context.Context, id string) (*Client, error) {
	if f.client == nil || f.client.ID != id {
		return nil, nil
	}
	return f.client, nil
}

func (f *fakeStore) BumpWindow(_ context.Context, _ string) (*RateWindow, error) {
	f.bumps++
	if f.bumpErr != nil {
		return nil, f.bumpErr
	}
	return f.window, nil
}

func (f *fakeStore) WindowLimit() int64 {
	if f.windowLimit == 0 {
		return 30
	}
	return f.windowLimit
}

type fakeSigner struct {
	signed string
	err    error
	calls  int
}

func (f *fakeSigner) Sign(clientID, audience string, scopes []string) (string, error) {
	f.calls++
	if f.err != nil {
		return "", f.err
	}
	return f.signed, nil
}

func testClient(secret string) *Client {
	hash, _ := bcrypt.GenerateFromPassword([]byte(secret), BcryptCost)
	return &Client{
		ID:           "event-registration",
		SecretRounds: []string{string(hash)},
		Audiences:    map[string][]string{"profiles-api": {"m2m:player-profiles"}},
		Active:       true,
	}
}

func testLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

func TestExchangeHappyPath(t *testing.T) {
	store := &fakeStore{client: testClient("secret"), window: &RateWindow{WindowCount: 1}}
	signer := &fakeSigner{signed: "jwt"}
	svc := NewService(store, signer, 5*time.Minute)

	signed, err := svc.Exchange(context.Background(), "event-registration", "secret", "profiles-api", testLogger())
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if signed != "jwt" || signer.calls != 1 || store.bumps != 1 {
		t.Fatalf("unexpected result signed=%q calls=%d bumps=%d", signed, signer.calls, store.bumps)
	}
	if svc.Lifetime() != 5*time.Minute {
		t.Fatalf("lifetime = %v", svc.Lifetime())
	}
}

func TestExchangeUnknownNoWrites(t *testing.T) {
	store := &fakeStore{window: &RateWindow{WindowCount: 1}}
	svc := NewService(store, &fakeSigner{signed: "x"}, 5*time.Minute)

	if _, err := svc.Exchange(context.Background(), "nope", "secret", "profiles-api", testLogger()); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
	if store.bumps != 0 {
		t.Fatalf("unknown must not touch limiter (bumps=%d)", store.bumps)
	}
}

func TestExchangeWrongSecret(t *testing.T) {
	store := &fakeStore{client: testClient("secret"), window: &RateWindow{WindowCount: 1}}
	svc := NewService(store, &fakeSigner{signed: "jwt"}, 5*time.Minute)

	if _, err := svc.Exchange(context.Background(), "event-registration", "bad", "profiles-api", testLogger()); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestExchangeRateLimited(t *testing.T) {
	store := &fakeStore{
		client:      testClient("secret"),
		window:      &RateWindow{WindowCount: 31},
		windowLimit: 30,
	}
	svc := NewService(store, &fakeSigner{signed: "jwt"}, 5*time.Minute)

	if _, err := svc.Exchange(context.Background(), "event-registration", "secret", "profiles-api", testLogger()); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("expected ErrRateLimited, got %v", err)
	}
}

func TestExchangeBumpError(t *testing.T) {
	store := &fakeStore{client: testClient("secret"), bumpErr: errors.New("ddb down")}
	svc := NewService(store, &fakeSigner{signed: "jwt"}, 5*time.Minute)

	if _, err := svc.Exchange(context.Background(), "event-registration", "secret", "profiles-api", testLogger()); err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestExchangeUnprovisionedAudience(t *testing.T) {
	store := &fakeStore{client: testClient("secret"), window: &RateWindow{WindowCount: 1}}
	svc := NewService(store, &fakeSigner{signed: "jwt"}, 5*time.Minute)

	// Correct secret, wrong audience: uniform invalid_client family, and the
	// limiter was already bumped (same observable shape as a bad secret).
	if _, err := svc.Exchange(context.Background(), "event-registration", "secret", "other-api", testLogger()); !errors.Is(err, ErrAudienceNotAllowed) {
		t.Fatalf("expected ErrAudienceNotAllowed, got %v", err)
	}
	if store.bumps != 1 {
		t.Fatalf("membership check runs after the limiter (bumps=%d)", store.bumps)
	}
}

func TestExchangeEmptyAudiences(t *testing.T) {
	client := testClient("secret")
	client.Audiences = nil
	store := &fakeStore{client: client, window: &RateWindow{WindowCount: 1}}
	svc := NewService(store, &fakeSigner{signed: "jwt"}, 5*time.Minute)

	if _, err := svc.Exchange(context.Background(), "event-registration", "secret", "profiles-api", testLogger()); !errors.Is(err, ErrAudienceNotAllowed) {
		t.Fatalf("expected ErrAudienceNotAllowed, got %v", err)
	}
}
