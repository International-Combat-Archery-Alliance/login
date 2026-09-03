package m2m

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"sync"
	"testing"
)

// fakeProvisionStore is a map-backed ProvisionStore with real CAS semantics.
type fakeProvisionStore struct {
	mu      sync.Mutex
	clients map[string]*Client
}

func newFakeProvisionStore() *fakeProvisionStore {
	return &fakeProvisionStore{clients: map[string]*Client{}}
}

func copyClient(c *Client) *Client {
	if c == nil {
		return nil
	}
	out := *c
	out.SecretRounds = append([]string{}, c.SecretRounds...)
	out.Audiences = map[string][]string{}
	for aud, scopes := range c.Audiences {
		out.Audiences[aud] = append([]string{}, scopes...)
	}
	return &out
}

func (f *fakeProvisionStore) GetClient(_ context.Context, id string) (*Client, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return copyClient(f.clients[id]), nil
}

func (f *fakeProvisionStore) CreateClient(_ context.Context, client *Client) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.clients[client.ID]; ok {
		return ErrClientExists
	}
	f.clients[client.ID] = copyClient(client)
	return nil
}

func (f *fakeProvisionStore) ListClients(_ context.Context) ([]*Client, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*Client
	for _, c := range f.clients {
		out = append(out, copyClient(c))
	}
	return out, nil
}

func (f *fakeProvisionStore) DeactivateClient(_ context.Context, id string) (*Client, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.clients[id]
	if !ok {
		return nil, ErrClientNotFound
	}
	c.Active = false
	return copyClient(c), nil
}

func (f *fakeProvisionStore) UpdateRounds(_ context.Context, id string, expected, next []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.clients[id]
	if !ok {
		return ErrClientNotFound
	}
	if !reflect.DeepEqual(c.SecretRounds, expected) {
		return ErrRoundsConflict
	}
	c.SecretRounds = append([]string{}, next...)
	return nil
}

func testAudiences() map[string][]string {
	return map[string][]string{"profiles-api": {"m2m:player-profiles"}}
}

func TestProvisionCreateHappyPath(t *testing.T) {
	store := newFakeProvisionStore()
	svc := NewProvisionService(store)

	secret, err := svc.CreateClient(context.Background(), "event-registration",
		testAudiences(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	if secret == "" {
		t.Fatal("expected a plaintext secret, got empty")
	}

	client, err := store.GetClient(context.Background(), "event-registration")
	if err != nil || client == nil {
		t.Fatalf("stored client: %v (nil=%v)", err, client == nil)
	}
	if !client.Active || !reflect.DeepEqual(client.Audiences, testAudiences()) {
		t.Fatalf("unexpected stored client: %+v", client)
	}
	if len(client.SecretRounds) != 1 {
		t.Fatalf("expected 1 secret round, got %d", len(client.SecretRounds))
	}
	// The returned secret must verify against the stored bcrypt round. Only
	// the hash is persisted — plaintext lives solely in the return value.
	if !VerifySecret(client.SecretRounds, secret) {
		t.Fatal("returned secret does not verify against stored round")
	}
}

func TestProvisionCreateValidation(t *testing.T) {
	tests := []struct {
		name      string
		id        string
		audiences map[string][]string
		sentinel  error
	}{
		{name: "bad id", id: "Bad_ID", audiences: testAudiences(), sentinel: ErrInvalidClientID},
		{name: "bad audience key", id: "a", audiences: map[string][]string{"Bad Aud!": {"m2m:x"}}, sentinel: ErrInvalidAudience},
		{name: "bad scope entry", id: "a", audiences: map[string][]string{"profiles-api": {"nope"}}, sentinel: ErrInvalidScopes},
		{name: "empty map allowed", id: "a", audiences: nil, sentinel: nil},
		{name: "empty scopes allowed", id: "a", audiences: map[string][]string{"profiles-api": {}}, sentinel: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := NewProvisionService(newFakeProvisionStore())
			_, err := svc.CreateClient(context.Background(), tt.id, tt.audiences, slog.New(slog.DiscardHandler))
			if tt.sentinel == nil {
				if err != nil {
					t.Fatalf("expected success, got %v", err)
				}
				return
			}
			if !errors.Is(err, tt.sentinel) {
				t.Fatalf("expected %v, got %v", tt.sentinel, err)
			}
		})
	}
}

func TestProvisionCreateConflict(t *testing.T) {
	store := newFakeProvisionStore()
	svc := NewProvisionService(store)

	if _, err := svc.CreateClient(context.Background(), "a", testAudiences(), slog.New(slog.DiscardHandler)); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if _, err := svc.CreateClient(context.Background(), "a", testAudiences(), slog.New(slog.DiscardHandler)); !errors.Is(err, ErrClientExists) {
		t.Fatalf("expected ErrClientExists, got %v", err)
	}
}

func TestProvisionCreateStoreFailureDropsSecret(t *testing.T) {
	store := newFakeProvisionStore()
	svc := NewProvisionService(store)

	// Seed the id so the create fails: the secret must not be returned.
	if _, err := svc.CreateClient(context.Background(), "a", testAudiences(), slog.New(slog.DiscardHandler)); err != nil {
		t.Fatalf("seed create: %v", err)
	}
	secret, err := svc.CreateClient(context.Background(), "a", testAudiences(), slog.New(slog.DiscardHandler))
	if !errors.Is(err, ErrClientExists) {
		t.Fatalf("expected ErrClientExists, got %v", err)
	}
	if secret != "" {
		t.Fatal("failed create must not return the secret")
	}
}

func TestProvisionRevoke(t *testing.T) {
	store := newFakeProvisionStore()
	svc := NewProvisionService(store)
	logger := slog.New(slog.DiscardHandler)

	if _, err := svc.CreateClient(context.Background(), "a", testAudiences(), logger); err != nil {
		t.Fatalf("create: %v", err)
	}

	revoked, err := svc.RevokeClient(context.Background(), "a", logger)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if revoked.Active {
		t.Fatal("revoked client must be inactive")
	}
	if !reflect.DeepEqual(revoked.Audiences, testAudiences()) {
		t.Fatalf("revoke must preserve audiences: %+v", revoked)
	}

	// Idempotent: revoking again succeeds.
	if _, err := svc.RevokeClient(context.Background(), "a", logger); err != nil {
		t.Fatalf("second revoke: %v", err)
	}

	if _, err := svc.RevokeClient(context.Background(), "missing", logger); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("expected ErrClientNotFound, got %v", err)
	}
	if _, err := svc.RevokeClient(context.Background(), "BAD", logger); !errors.Is(err, ErrInvalidClientID) {
		t.Fatalf("expected ErrInvalidClientID, got %v", err)
	}
}

func TestProvisionRotate(t *testing.T) {
	store := newFakeProvisionStore()
	svc := NewProvisionService(store)
	logger := slog.New(slog.DiscardHandler)
	ctx := context.Background()

	oldSecret, err := svc.CreateClient(ctx, "a", testAudiences(), logger)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	newSecret, err := svc.RotateClient(ctx, "a", logger)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if newSecret == oldSecret {
		t.Fatal("rotated secret must differ")
	}

	client, _ := store.GetClient(ctx, "a")
	if len(client.SecretRounds) != 2 {
		t.Fatalf("expected 2 rounds after first rotate, got %d", len(client.SecretRounds))
	}
	// Grace window: both the old and new secrets verify, so callers keep
	// working until the operator delivers the new secret and recycles them.
	if !VerifySecret(client.SecretRounds, oldSecret) {
		t.Fatal("old secret must still verify during the grace window")
	}
	if !VerifySecret(client.SecretRounds, newSecret) {
		t.Fatal("new secret must verify")
	}
	if !reflect.DeepEqual(client.Audiences, testAudiences()) {
		t.Fatalf("rotate must preserve audiences: %+v", client)
	}

	// Second rotate trims to the newest 2 (the original round drops).
	newest, err := svc.RotateClient(ctx, "a", logger)
	if err != nil {
		t.Fatalf("second rotate: %v", err)
	}
	client, _ = store.GetClient(ctx, "a")
	if len(client.SecretRounds) != MaxSecretRounds {
		t.Fatalf("expected %d rounds, got %d", MaxSecretRounds, len(client.SecretRounds))
	}
	if VerifySecret(client.SecretRounds, oldSecret) {
		t.Fatal("original round must drop after the second rotate")
	}
	if !VerifySecret(client.SecretRounds, newest) {
		t.Fatal("newest secret must verify")
	}
}

func TestProvisionRotateErrors(t *testing.T) {
	store := newFakeProvisionStore()
	svc := NewProvisionService(store)
	logger := slog.New(slog.DiscardHandler)
	ctx := context.Background()

	if _, err := svc.RotateClient(ctx, "missing", logger); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("expected ErrClientNotFound, got %v", err)
	}

	if _, err := svc.CreateClient(ctx, "a", testAudiences(), logger); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := svc.RevokeClient(ctx, "a", logger); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := svc.RotateClient(ctx, "a", logger); !errors.Is(err, ErrClientInactive) {
		t.Fatalf("expected ErrClientInactive, got %v", err)
	}
}

func TestProvisionRotateConflict(t *testing.T) {
	store := newFakeProvisionStore()
	svc := NewProvisionService(store)
	logger := slog.New(slog.DiscardHandler)
	ctx := context.Background()

	if _, err := svc.CreateClient(ctx, "a", testAudiences(), logger); err != nil {
		t.Fatalf("create: %v", err)
	}
	before, _ := store.GetClient(ctx, "a")

	// A concurrent writer lands first; a stale CAS on the old rounds must fail
	// instead of silently dropping the concurrent round.
	if err := store.UpdateRounds(ctx, "a", before.SecretRounds, append([]string{"other"}, before.SecretRounds...)); err != nil {
		t.Fatalf("concurrent update: %v", err)
	}
	if err := store.UpdateRounds(ctx, "a", before.SecretRounds, []string{"stale"}); !errors.Is(err, ErrRoundsConflict) {
		t.Fatalf("expected ErrRoundsConflict, got %v", err)
	}
}

func TestProvisionList(t *testing.T) {
	store := newFakeProvisionStore()
	svc := NewProvisionService(store)
	logger := slog.New(slog.DiscardHandler)
	ctx := context.Background()

	empty, err := svc.ListClients(ctx)
	if err != nil || len(empty) != 0 {
		t.Fatalf("expected empty list, got %v / %v", empty, err)
	}

	for _, id := range []string{"a", "b"} {
		if _, err := svc.CreateClient(ctx, id, testAudiences(), logger); err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
	}
	got, err := svc.ListClients(ctx)
	if err != nil || len(got) != 2 {
		t.Fatalf("expected 2 clients, got %v / %v", got, err)
	}
}
