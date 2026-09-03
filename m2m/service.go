package m2m

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	// BcryptCost is the bcrypt cost for client-secret hashes so the CPU budget
	// per attempt is known. Provisioned rounds must also use this cost: the
	// unknown-client dummy compare runs at this cost, so any other cost makes
	// known vs unknown clientIds timing-distinguishable.
	BcryptCost = 10
)

// Domain entities (persistence-agnostic).
type Client struct {
	ID           string
	SecretRounds []string
	Audience     string
	Scopes       []string
	Active       bool
}

type RateWindow struct {
	WindowCount int64
	FailCount   int64
	LockedUntil *time.Time
}

// Sentinel verdicts (transport maps these to HTTP codes).
var (
	ErrInvalidCredentials = errors.New("invalid client credentials")
	ErrRateLimited        = errors.New("rate limit exceeded")
	ErrLockedOut          = errors.New("too many failed attempts; try again later")
)

// Ports (implemented by adapters).
type ClientStore interface {
	GetClient(ctx context.Context, clientID string) (*Client, error)
}

type RateStore interface {
	BumpWindow(ctx context.Context, clientID string) (*RateWindow, error)
	RecordFailure(ctx context.Context, clientID string) error
	ResetFailures(ctx context.Context, clientID string) error
	WindowLimit() int64
}

type Store interface {
	ClientStore
	RateStore
}

type TokenSigner interface {
	Sign(clientID string, audience string, scopes []string) (string, error)
}

// Service holds the client-credentials exchange policy.
type Service struct {
	store     Store
	signer    TokenSigner
	lifetime  time.Duration
	dummyHash []byte
	clock     Clock
}

// ServiceOption configures a Service.
type ServiceOption func(*Service)

// WithClock overrides the clock (tests).
func WithClock(c Clock) ServiceOption {
	return func(s *Service) { s.clock = c }
}

func NewService(store Store, signer TokenSigner, lifetime time.Duration, opts ...ServiceOption) *Service {
	s := &Service{
		store:     store,
		signer:    signer,
		lifetime:  lifetime,
		dummyHash: makeDummyHash(),
		clock:     SystemClock(),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Lifetime returns the token lifetime reported as expires_in.
func (s *Service) Lifetime() time.Duration {
	return s.lifetime
}

// Exchange authenticates clientID:secret and mints a machine token.
//
// Flow:
//  1. Existence first: unknown/inactive get a dummy bcrypt + ErrInvalidCredentials
//     with no RATE writes.
//  2. Known clients: fixed-window limiter, then bcrypt. Locked IDs accept a
//     valid secret (bypass, throttled by the same window); invalid while locked
//     stays locked with no failure record so the lock is not sticky.
//  3. Success mints then clears failures non-fatally.
func (s *Service) Exchange(ctx context.Context, clientID, secret string, logger *slog.Logger) (signed string, err error) {
	now := s.clock.Now()

	client, err := s.store.GetClient(ctx, clientID)
	if err != nil {
		return "", fmt.Errorf("get machine client: %w", err)
	}

	if client == nil || len(client.SecretRounds) == 0 || !client.Active {
		_ = bcrypt.CompareHashAndPassword(s.dummyHash, []byte(secret))
		logger.Warn("m2m invalid_client", slog.String("clientId", clientID))
		return "", ErrInvalidCredentials
	}

	window, err := s.store.BumpWindow(ctx, clientID)
	if err != nil {
		return "", fmt.Errorf("bump rate window: %w", err)
	}

	if window.WindowCount > s.store.WindowLimit() {
		return "", ErrRateLimited
	}

	if window.LockedUntil != nil && window.LockedUntil.After(now) {
		if VerifySecret(client.SecretRounds, secret) {
			return s.issue(ctx, clientID, client, logger)
		}
		logger.Warn("m2m lockout", slog.String("clientId", clientID), slog.Time("lockedUntil", *window.LockedUntil))
		return "", ErrLockedOut
	}

	if !VerifySecret(client.SecretRounds, secret) {
		s.recordFailure(ctx, clientID, logger)
		return "", ErrInvalidCredentials
	}

	return s.issue(ctx, clientID, client, logger)
}

// VerifySecret compares against any active round (rotation grace window).
func VerifySecret(rounds []string, secret string) bool {
	for _, round := range rounds {
		if bcrypt.CompareHashAndPassword([]byte(round), []byte(secret)) == nil {
			return true
		}
	}
	return false
}

func (s *Service) issue(ctx context.Context, clientID string, client *Client, logger *slog.Logger) (string, error) {
	signed, err := s.signer.Sign(clientID, client.Audience, client.Scopes)
	if err != nil {
		return "", fmt.Errorf("sign machine token: %w", err)
	}

	if err := s.store.ResetFailures(ctx, clientID); err != nil {
		logger.Error("failed to reset m2m failures", slog.String("clientId", clientID), slog.String("error", err.Error()))
	}

	logger.Info("m2m token issued", slog.String("clientId", clientID))
	return signed, nil
}

func (s *Service) recordFailure(ctx context.Context, clientID string, logger *slog.Logger) {
	if err := s.store.RecordFailure(ctx, clientID); err != nil {
		logger.Error("failed to record m2m failure", slog.String("clientId", clientID), slog.String("error", err.Error()))
	}
	logger.Warn("m2m invalid_client", slog.String("clientId", clientID))
}

func makeDummyHash() []byte {
	randomSecret := make([]byte, 32)
	if _, err := rand.Read(randomSecret); err != nil {
		panic(fmt.Sprintf("failed to read random bytes for dummy client hash: %v", err))
	}
	hash, err := bcrypt.GenerateFromPassword(randomSecret, BcryptCost)
	if err != nil {
		panic(fmt.Sprintf("failed to precompute dummy client hash: %v", err))
	}
	return hash
}
