package api

import (
	"context"
	"log/slog"
	"reflect"
	"testing"

	"github.com/International-Combat-Archery-Alliance/login/m2m"
)

// fakeAdminStore is a map-backed m2m.ProvisionStore for handler tests.
type fakeAdminStore struct {
	clients map[string]*m2m.Client
	casErr  error
}

func newFakeAdminStore() *fakeAdminStore {
	return &fakeAdminStore{clients: map[string]*m2m.Client{}}
}

func (f *fakeAdminStore) GetClient(_ context.Context, id string) (*m2m.Client, error) {
	c, ok := f.clients[id]
	if !ok {
		return nil, nil
	}
	out := *c
	out.SecretRounds = append([]string{}, c.SecretRounds...)
	out.Audiences = map[string][]string{}
	for aud, scopes := range c.Audiences {
		out.Audiences[aud] = append([]string{}, scopes...)
	}
	return &out, nil
}

func (f *fakeAdminStore) CreateClient(_ context.Context, client *m2m.Client) error {
	if _, ok := f.clients[client.ID]; ok {
		return m2m.ErrClientExists
	}
	f.clients[client.ID] = client
	return nil
}

func (f *fakeAdminStore) ListClients(_ context.Context) ([]*m2m.Client, error) {
	var out []*m2m.Client
	for _, c := range f.clients {
		out = append(out, c)
	}
	return out, nil
}

func (f *fakeAdminStore) DeactivateClient(_ context.Context, id string) (*m2m.Client, error) {
	c, ok := f.clients[id]
	if !ok {
		return nil, m2m.ErrClientNotFound
	}
	c.Active = false
	return c, nil
}

func (f *fakeAdminStore) UpdateRounds(_ context.Context, id string, expected, next []string) error {
	if f.casErr != nil {
		return f.casErr
	}
	c, ok := f.clients[id]
	if !ok {
		return m2m.ErrClientNotFound
	}
	if !reflect.DeepEqual(c.SecretRounds, expected) {
		return m2m.ErrRoundsConflict
	}
	c.SecretRounds = next
	return nil
}

func testProvisionAPI(store *fakeAdminStore) *API {
	return NewAPI(Config{
		M2MProvisionStore: store,
		JWKSProvider:      fakeJWKSProvider{jwks: JWKS{Keys: []JWK{}}},
		Logger:            slog.New(slog.DiscardHandler),
		Environment:       PROD,
	})
}

func createBody(id string, audiences map[string][]string) *PostLoginV1M2mClientsJSONRequestBody {
	return &PostLoginV1M2mClientsJSONRequestBody{ClientId: id, Audiences: audiences}
}

func testAudiencesBody() map[string][]string {
	return map[string][]string{"profiles-api": {"m2m:player-profiles"}}
}

func TestPostM2MClientsHappyPath(t *testing.T) {
	store := newFakeAdminStore()
	a := testProvisionAPI(store)

	resp, err := a.PostLoginV1M2mClients(context.Background(), PostLoginV1M2mClientsRequestObject{
		Body: createBody("event-registration", testAudiencesBody()),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	created, ok := resp.(PostLoginV1M2mClients201JSONResponse)
	if !ok {
		t.Fatalf("expected 201 response, got %T", resp)
	}
	if created.ClientId != "event-registration" || created.ClientSecret == "" {
		t.Fatalf("unexpected body: %+v", created)
	}
	// Secret-once: stored only as bcrypt in DDB, and the returned secret
	// verifies against the stored round.
	stored := store.clients["event-registration"]
	if !m2m.VerifySecret(stored.SecretRounds, created.ClientSecret) {
		t.Fatal("returned secret does not verify against the stored round")
	}
}

func TestPostM2MClientsValidation(t *testing.T) {
	a := testProvisionAPI(newFakeAdminStore())

	tests := []struct {
		name string
		body *PostLoginV1M2mClientsJSONRequestBody
	}{
		{name: "nil body", body: nil},
		{name: "bad id", body: createBody("Bad!", testAudiencesBody())},
		{name: "bad audience", body: createBody("a", map[string][]string{"Bad Aud!": {"m2m:a"}})},
		{name: "bad scopes", body: createBody("a", map[string][]string{"profiles-api": {"nope"}})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := a.PostLoginV1M2mClients(context.Background(), PostLoginV1M2mClientsRequestObject{Body: tt.body})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			bad, ok := resp.(PostLoginV1M2mClients400JSONResponse)
			if !ok {
				t.Fatalf("expected 400 response, got %T", resp)
			}
			if bad.Code != InputValidationError {
				t.Fatalf("code = %q, want InputValidationError", bad.Code)
			}
		})
	}
}

func TestPostM2MClientsConflict(t *testing.T) {
	store := newFakeAdminStore()
	store.clients["a"] = &m2m.Client{ID: "a", Active: true}
	a := testProvisionAPI(store)

	resp, err := a.PostLoginV1M2mClients(context.Background(), PostLoginV1M2mClientsRequestObject{
		Body: createBody("a", map[string][]string{"b-api": {"m2m:c"}}),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	conflict, ok := resp.(PostLoginV1M2mClients409JSONResponse)
	if !ok {
		t.Fatalf("expected 409 response, got %T", resp)
	}
	if conflict.Code != Conflict {
		t.Fatalf("code = %q, want Conflict", conflict.Code)
	}
}

func TestGetM2MClients(t *testing.T) {
	store := newFakeAdminStore()
	store.clients["b"] = &m2m.Client{ID: "b", Audiences: map[string][]string{"x-api": {"m2m:y"}}, Active: true}
	store.clients["a"] = &m2m.Client{ID: "a", Audiences: map[string][]string{"x-api": {"m2m:y"}}, Active: false}
	a := testProvisionAPI(store)

	resp, err := a.GetLoginV1M2mClients(context.Background(), GetLoginV1M2mClientsRequestObject{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	list, ok := resp.(GetLoginV1M2mClients200JSONResponse)
	if !ok {
		t.Fatalf("expected 200 response, got %T", resp)
	}
	if len(list.Clients) != 2 {
		t.Fatalf("expected 2 clients, got %+v", list.Clients)
	}
}

func TestDeleteM2MClient(t *testing.T) {
	store := newFakeAdminStore()
	store.clients["a"] = &m2m.Client{ID: "a", Audiences: map[string][]string{"b-api": {"m2m:c"}}, Active: true}
	a := testProvisionAPI(store)

	resp, err := a.DeleteLoginV1M2mClientsClientId(context.Background(), DeleteLoginV1M2mClientsClientIdRequestObject{ClientId: "a"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	revoked, ok := resp.(DeleteLoginV1M2mClientsClientId200JSONResponse)
	if !ok {
		t.Fatalf("expected 200 response, got %T", resp)
	}
	if revoked.Active || revoked.ClientId != "a" {
		t.Fatalf("unexpected body: %+v", revoked)
	}

	resp, err = a.DeleteLoginV1M2mClientsClientId(context.Background(), DeleteLoginV1M2mClientsClientIdRequestObject{ClientId: "missing"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if notFound, ok := resp.(DeleteLoginV1M2mClientsClientId404JSONResponse); !ok || notFound.Code != NotFound {
		t.Fatalf("expected 404 NotFound, got %T", resp)
	}

	resp, err = a.DeleteLoginV1M2mClientsClientId(context.Background(), DeleteLoginV1M2mClientsClientIdRequestObject{ClientId: "BAD!"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := resp.(DeleteLoginV1M2mClientsClientId400JSONResponse); !ok {
		t.Fatalf("expected 400 response, got %T", resp)
	}
}

func TestRotateM2MClient(t *testing.T) {
	store := newFakeAdminStore()
	store.clients["a"] = &m2m.Client{ID: "a", Audiences: map[string][]string{"b-api": {"m2m:c"}}, SecretRounds: []string{"old-round"}, Active: true}
	a := testProvisionAPI(store)

	resp, err := a.PostLoginV1M2mClientsClientIdRotate(context.Background(), PostLoginV1M2mClientsClientIdRotateRequestObject{ClientId: "a"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	rotated, ok := resp.(PostLoginV1M2mClientsClientIdRotate200JSONResponse)
	if !ok {
		t.Fatalf("expected 200 response, got %T", resp)
	}
	if rotated.ClientId != "a" || rotated.ClientSecret == "" {
		t.Fatalf("unexpected body: %+v", rotated)
	}

	// Missing → 404, revoked → 409, concurrent CAS failure → 409.
	resp, _ = a.PostLoginV1M2mClientsClientIdRotate(context.Background(), PostLoginV1M2mClientsClientIdRotateRequestObject{ClientId: "missing"})
	if notFound, ok := resp.(PostLoginV1M2mClientsClientIdRotate404JSONResponse); !ok || notFound.Code != NotFound {
		t.Fatalf("expected 404 NotFound, got %T", resp)
	}

	store.clients["a"].Active = false
	resp, _ = a.PostLoginV1M2mClientsClientIdRotate(context.Background(), PostLoginV1M2mClientsClientIdRotateRequestObject{ClientId: "a"})
	if conflict, ok := resp.(PostLoginV1M2mClientsClientIdRotate409JSONResponse); !ok || conflict.Code != Conflict {
		t.Fatalf("expected 409 Conflict for revoked client, got %T", resp)
	}

	store.clients["a"].Active = true
	store.casErr = m2m.ErrRoundsConflict
	resp, _ = a.PostLoginV1M2mClientsClientIdRotate(context.Background(), PostLoginV1M2mClientsClientIdRotateRequestObject{ClientId: "a"})
	if _, ok := resp.(PostLoginV1M2mClientsClientIdRotate409JSONResponse); !ok {
		t.Fatalf("expected 409 Conflict on concurrent rotation, got %T", resp)
	}
}

func TestProvisionEndpointsUnconfigured(t *testing.T) {
	// Configs without the provisioning stores (e.g. older wiring) fail closed.
	a, _, _ := testAPI(t, &fakeM2MStore{window: &m2m.RateWindow{WindowCount: 1}})

	if resp, _ := a.GetLoginV1M2mClients(context.Background(), GetLoginV1M2mClientsRequestObject{}); resp == nil {
		t.Fatal("expected a response, got nil")
	} else if _, ok := resp.(GetLoginV1M2mClients500JSONResponse); !ok {
		t.Fatalf("expected 500 response, got %T", resp)
	}
}
