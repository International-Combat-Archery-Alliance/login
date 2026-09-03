package m2m

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"golang.org/x/crypto/bcrypt"
)

// Sentinel provisioning verdicts (transport maps these to HTTP codes).
var (
	ErrClientExists   = errors.New("machine client already exists")
	ErrClientNotFound = errors.New("machine client not found")
	ErrClientInactive = errors.New("machine client is revoked")
	ErrRoundsConflict = errors.New("machine client changed concurrently")
)

// ProvisionStore persists CLIENT# records for the admin provisioning API.
// DynamoDB conditions make every verdict exact: create fails only when the id
// exists, deactivate only when it does not, and UpdateRounds only on a
// concurrent write (optimistic locking on secretRounds).
type ProvisionStore interface {
	GetClient(ctx context.Context, clientID string) (*Client, error)
	CreateClient(ctx context.Context, client *Client) error
	ListClients(ctx context.Context) ([]*Client, error)
	DeactivateClient(ctx context.Context, clientID string) (*Client, error)
	UpdateRounds(ctx context.Context, clientID string, expected, next []string) error
}

// ProvisionService holds the admin provisioning policy: validate, generate,
// hash, persist. The service is intentionally DDB-only: it stores bcrypt
// rounds plus metadata and returns the plaintext secret exactly once. Secret
// distribution to callers (SSM params, deploy config) is an explicit operator
// step outside this API — the service never writes plaintext anywhere.
type ProvisionService struct {
	clients ProvisionStore
}

func NewProvisionService(clients ProvisionStore) *ProvisionService {
	return &ProvisionService{clients: clients}
}

// CreateClient validates, generates a secret, and stores its bcrypt round
// plus metadata. Returns the plaintext secret exactly once — the operator
// delivers it to the caller; the record is unusable until that happens.
func (s *ProvisionService) CreateClient(ctx context.Context, clientID string, audiences map[string][]string, logger *slog.Logger) (string, error) {
	if err := ValidateClientID(clientID); err != nil {
		return "", err
	}
	if err := ValidateAudiences(audiences); err != nil {
		return "", err
	}

	secret, err := GenerateClientSecret()
	if err != nil {
		return "", err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), BcryptCost)
	if err != nil {
		return "", fmt.Errorf("hash client secret: %w", err)
	}

	client := &Client{
		ID:           clientID,
		SecretRounds: []string{string(hash)},
		Audiences:    audiences,
		Active:       true,
	}
	if err := s.clients.CreateClient(ctx, client); err != nil {
		return "", err
	}

	logger.Info("m2m client provisioned",
		slog.String("clientId", clientID),
		slog.Int("audiences", len(audiences)))
	return secret, nil
}

// ListClients returns client metadata (never secrets).
func (s *ProvisionService) ListClients(ctx context.Context) ([]*Client, error) {
	return s.clients.ListClients(ctx)
}

// RevokeClient soft-deactivates the record (active=false): new exchanges fail
// immediately while outstanding tokens run out their <=5-minute TTL.
// Idempotent: revoking an already-inactive client succeeds. Revocation is
// permanent via this API — there is no reactivate endpoint, so a mistaken
// revoke needs operator intervention (and the operator-held secret delivery
// repeated for any replacement id).
func (s *ProvisionService) RevokeClient(ctx context.Context, clientID string, logger *slog.Logger) (*Client, error) {
	if err := ValidateClientID(clientID); err != nil {
		return nil, err
	}

	client, err := s.clients.DeactivateClient(ctx, clientID)
	if err != nil {
		return nil, err
	}

	logger.Info("m2m client revoked", slog.String("clientId", clientID))
	return client, nil
}

// RotateClient mints a new secret and prepends its bcrypt round (trimmed to
// MaxSecretRounds so the previous secret keeps working until callers are
// re-delivered and recycled). Returns the plaintext secret exactly once —
// callers must not log or retain it. The new secret takes effect for callers
// only after the operator delivers it (e.g. SSM) and recycles them.
func (s *ProvisionService) RotateClient(ctx context.Context, clientID string, logger *slog.Logger) (string, error) {
	if err := ValidateClientID(clientID); err != nil {
		return "", err
	}

	client, err := s.clients.GetClient(ctx, clientID)
	if err != nil {
		return "", err
	}
	if client == nil {
		return "", ErrClientNotFound
	}
	if !client.Active {
		return "", ErrClientInactive
	}

	secret, err := GenerateClientSecret()
	if err != nil {
		return "", err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), BcryptCost)
	if err != nil {
		return "", fmt.Errorf("hash client secret: %w", err)
	}

	next := append([]string{string(hash)}, client.SecretRounds...)
	if len(next) > MaxSecretRounds {
		next = next[:MaxSecretRounds]
	}
	if err := s.clients.UpdateRounds(ctx, clientID, client.SecretRounds, next); err != nil {
		return "", err
	}

	logger.Info("m2m client rotated", slog.String("clientId", clientID))
	return secret, nil
}
