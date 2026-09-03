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
}

// Sentinel verdicts (transport maps these to HTTP codes).
var (
	ErrInvalidCredentials = errors.New("invalid client credentials")
	ErrRateLimited        = errors.New("rate limit exceeded")
)

// Ports (implemented by adapters).
type ClientStore interface {
	GetClient(ctx context.Context, clientID string) (*Client, error)
}

type RateStore interface {
	BumpWindow(ctx context.Context, clientID string) (*RateWindow, error)
	WindowLimit() int64
}

type Store interface {
	ClientStore
	RateStore
}

type TokenSigner interface {
	Sign(clientID string, audience string, scopes []string) (string, error)
}

// Service holds the client-credentials exchange policy: lookup, rate-limit,
// verify, mint. No lockout by design (fixed-window rate limiting is the only
// throttle; strong secrets make guessing infeasible).
type Service struct {
	store     Store
	signer    TokenSigner
	lifetime  time.Duration
	dummyHash []byte
}

func NewService(store Store, signer TokenSigner, lifetime time.Duration) *Service {
	return &Service{
		store:     store,
		signer:    signer,
		lifetime:  lifetime,
		dummyHash: makeDummyHash(),
	}
}

// Lifetime returns the token lifetime reported as expires_in.
func (s *Service) Lifetime() time.Duration {
	return s.lifetime
}

// Exchange authenticates clientID:secret and mints a machine token.
func (s *Service) Exchange(ctx context.Context, clientID, secret string, logger *slog.Logger) (signed string, err error) {
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

	if !VerifySecret(client.SecretRounds, secret) {
		logger.Warn("m2m invalid_client", slog.String("clientId", clientID))
		return "", ErrInvalidCredentials
	}

	signed, err = s.signer.Sign(clientID, client.Audience, client.Scopes)
	if err != nil {
		return "", fmt.Errorf("sign machine token: %w", err)
	}

	logger.Info("m2m token issued", slog.String("clientId", clientID))
	return signed, nil
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
