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

// ProvisionStore persists machine-client records for the admin provisioning
// API. Implementations report exact verdicts: create fails only when the id
// exists, deactivate/metadata-update only when it does not, and UpdateRounds
// only on a concurrent write (optimistic locking on secret rounds).
type ProvisionStore interface {
	GetClient(ctx context.Context, clientID string) (*Client, error)
	CreateClient(ctx context.Context, client *Client) error
	ListClients(ctx context.Context) ([]*Client, error)
	DeactivateClient(ctx context.Context, clientID string) (*Client, error)
	UpdateRounds(ctx context.Context, clientID string, expected, next []string) error
	UpdateAudiences(ctx context.Context, clientID string, audiences map[string][]string) (*Client, error)
}

// ProvisionService holds the admin provisioning policy: validate, generate,
// hash, persist. It stores one-way hashes plus metadata and returns the
// plaintext secret exactly once. Delivering the secret to the caller is an
// explicit operator step outside this API — the service never writes
// plaintext anywhere.
type ProvisionService struct {
	clients ProvisionStore
}

func NewProvisionService(clients ProvisionStore) *ProvisionService {
	return &ProvisionService{clients: clients}
}

// newSecretHash generates a client secret and returns it alongside its
// one-way hash for storage.
func newSecretHash() (secret, hash string, err error) {
	secret, err = GenerateClientSecret()
	if err != nil {
		return "", "", err
	}
	raw, err := bcrypt.GenerateFromPassword([]byte(secret), BcryptCost)
	if err != nil {
		return "", "", fmt.Errorf("hash client secret: %w", err)
	}
	return secret, string(raw), nil
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

	secret, hash, err := newSecretHash()
	if err != nil {
		return "", err
	}

	client := &Client{
		ID:           clientID,
		SecretRounds: []string{hash},
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

// UpdateClient replaces the complete audiences-to-scopes map. Entries
// omitted by the caller are removed (pass {} to strip all access). Secrets
// are untouched. Applies to active and revoked clients alike — exchanges for
// revoked clients keep failing regardless of metadata.
func (s *ProvisionService) UpdateClient(ctx context.Context, clientID string, audiences map[string][]string, logger *slog.Logger) (*Client, error) {
	if err := ValidateClientID(clientID); err != nil {
		return nil, err
	}
	if err := ValidateAudiences(audiences); err != nil {
		return nil, err
	}

	client, err := s.clients.UpdateAudiences(ctx, clientID, audiences)
	if err != nil {
		return nil, err
	}

	logger.Info("m2m client audiences replaced",
		slog.String("clientId", clientID),
		slog.Int("audiences", len(audiences)))
	return client, nil
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

// RotateClient mints a new secret and prepends its hash (trimmed to
// MaxSecretRounds so the previous secret keeps working until callers are
// re-delivered and recycled). Returns the plaintext secret exactly once.
// The new secret takes effect for callers only after the operator delivers
// it and recycles them.
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

	secret, hash, err := newSecretHash()
	if err != nil {
		return "", err
	}

	next := append([]string{hash}, client.SecretRounds...)
	if len(next) > MaxSecretRounds {
		next = next[:MaxSecretRounds]
	}
	if err := s.clients.UpdateRounds(ctx, clientID, client.SecretRounds, next); err != nil {
		return "", err
	}

	logger.Info("m2m client rotated", slog.String("clientId", clientID))
	return secret, nil
}
