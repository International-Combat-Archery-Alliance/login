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
	recordErr   error
	resetErr    error
	failures    int
	resets      int
	bumps       int
}

func (f *fakeStore) GetClient(_ context.Context, id string) (*Client, error) {
	if f.client == nil || f.client.ID != id {
		return nil, nil
	}
	return f.client, nil
}

func (f *fakeStore) BumpWindow(_ context.Context, _ string) (*RateWindow, error) {
	f.bumps++
	return f.window, nil
}

func (f *fakeStore) RecordFailure(_ context.Context, _ string) error {
	f.failures++
	return f.recordErr
}

func (f *fakeStore) ResetFailures(_ context.Context, _ string) error {
	f.resets++
	return f.resetErr
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
		Audience:     "profiles-api",
		Scopes:       []string{"m2m:player-profiles"},
		Active:       true,
	}
}

func testLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

func TestExchangeHappyPath(t *testing.T) {
	store := &fakeStore{client: testClient("secret"), window: &RateWindow{WindowCount: 1}}
	signer := &fakeSigner{signed: "jwt"}
	svc := NewService(store, signer, 5*time.Minute)

	signed, err := svc.Exchange(context.Background(), "event-registration", "secret", testLogger())
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if signed != "jwt" || signer.calls != 1 || store.resets != 1 {
		t.Fatalf("unexpected result signed=%q calls=%d resets=%d", signed, signer.calls, store.resets)
	}
	if svc.Lifetime() != 5*time.Minute {
		t.Fatalf("lifetime = %v", svc.Lifetime())
	}
}

func TestExchangeUnknownNoWrites(t *testing.T) {
	store := &fakeStore{window: &RateWindow{WindowCount: 1}}
	svc := NewService(store, &fakeSigner{signed: "x"}, 5*time.Minute)

	if _, err := svc.Exchange(context.Background(), "nope", "secret", testLogger()); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
	if store.bumps != 0 || store.failures != 0 {
		t.Fatalf("unknown must not touch limiter (bumps=%d failures=%d)", store.bumps, store.failures)
	}
}

func TestExchangeLockedValidBypass(t *testing.T) {
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	locked := base.Add(15 * time.Minute)
	store := &fakeStore{
		client: testClient("secret"),
		window: &RateWindow{WindowCount: 1, LockedUntil: &locked},
	}
	svc := NewService(store, &fakeSigner{signed: "jwt"}, 5*time.Minute, WithClock(FixedClock(base)))

	if _, err := svc.Exchange(context.Background(), "event-registration", "secret", testLogger()); err != nil {
		t.Fatalf("valid bypass: %v", err)
	}
	if store.resets != 1 {
		t.Fatalf("expected reset, got %d", store.resets)
	}
}

func TestExchangeLockedInvalidStaysLocked(t *testing.T) {
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	locked := base.Add(15 * time.Minute)
	store := &fakeStore{
		client: testClient("secret"),
		window: &RateWindow{WindowCount: 1, LockedUntil: &locked},
	}
	svc := NewService(store, &fakeSigner{signed: "jwt"}, 5*time.Minute, WithClock(FixedClock(base)))

	if _, err := svc.Exchange(context.Background(), "event-registration", "bad", testLogger()); !errors.Is(err, ErrLockedOut) {
		t.Fatalf("expected ErrLockedOut, got %v", err)
	}
	if store.failures != 0 {
		t.Fatalf("locked invalid must not record, got %d", store.failures)
	}
}

func TestExchangeRateLimited(t *testing.T) {
	store := &fakeStore{
		client:      testClient("secret"),
		window:      &RateWindow{WindowCount: 31},
		windowLimit: 30,
	}
	svc := NewService(store, &fakeSigner{signed: "jwt"}, 5*time.Minute)

	if _, err := svc.Exchange(context.Background(), "event-registration", "secret", testLogger()); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("expected ErrRateLimited, got %v", err)
	}
}
