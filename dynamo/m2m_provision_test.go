package dynamo

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/International-Combat-Archery-Alliance/login/m2m"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go/middleware"
)

// fakeProvisionDDB intercepts PutItem/Query/UpdateItem/GetItem with scripted
// outcomes and records every input for expression assertions.
type fakeProvisionDDB struct {
	mu      sync.Mutex
	puts    []*dynamodb.PutItemInput
	queries []*dynamodb.QueryInput
	updates []*dynamodb.UpdateItemInput
	gets    []*dynamodb.GetItemInput

	putErr      error
	putCondFail bool

	queryPages []*dynamodb.QueryOutput
	queryErr   error

	updateResult   *dynamodb.UpdateItemOutput
	updateCondFail bool
	updateErr      error

	getResult *dynamodb.GetItemOutput
	getErr    error
}

func (f *fakeProvisionDDB) client() *dynamodb.Client {
	cfg := aws.Config{Region: "us-east-1", Credentials: aws.AnonymousCredentials{}}
	return dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
		o.APIOptions = append(o.APIOptions, func(stack *middleware.Stack) error {
			return stack.Initialize.Add(
				middleware.InitializeMiddlewareFunc("fake-provision-dynamo", func(
					ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler,
				) (middleware.InitializeOutput, middleware.Metadata, error) {
					f.mu.Lock()
					defer f.mu.Unlock()
					switch req := in.Parameters.(type) {
					case *dynamodb.PutItemInput:
						f.puts = append(f.puts, req)
						if f.putErr != nil {
							return middleware.InitializeOutput{}, middleware.Metadata{}, f.putErr
						}
						if f.putCondFail {
							return middleware.InitializeOutput{}, middleware.Metadata{},
								&types.ConditionalCheckFailedException{Message: aws.String("conditional check failed")}
						}
						return middleware.InitializeOutput{Result: &dynamodb.PutItemOutput{}}, middleware.Metadata{}, nil
					case *dynamodb.QueryInput:
						f.queries = append(f.queries, req)
						if f.queryErr != nil {
							return middleware.InitializeOutput{}, middleware.Metadata{}, f.queryErr
						}
						if len(f.queryPages) == 0 {
							return middleware.InitializeOutput{}, middleware.Metadata{},
								fmt.Errorf("no scripted query page for call %d", len(f.queries))
						}
						page := f.queryPages[0]
						f.queryPages = f.queryPages[1:]
						return middleware.InitializeOutput{Result: page}, middleware.Metadata{}, nil
					case *dynamodb.UpdateItemInput:
						f.updates = append(f.updates, req)
						if f.updateErr != nil {
							return middleware.InitializeOutput{}, middleware.Metadata{}, f.updateErr
						}
						if f.updateCondFail {
							return middleware.InitializeOutput{}, middleware.Metadata{},
								&types.ConditionalCheckFailedException{Message: aws.String("conditional check failed")}
						}
						if f.updateResult == nil {
							return middleware.InitializeOutput{}, middleware.Metadata{},
								fmt.Errorf("no scripted update result for call %d", len(f.updates))
						}
						return middleware.InitializeOutput{Result: f.updateResult}, middleware.Metadata{}, nil
					case *dynamodb.GetItemInput:
						f.gets = append(f.gets, req)
						if f.getErr != nil {
							return middleware.InitializeOutput{}, middleware.Metadata{}, f.getErr
						}
						if f.getResult == nil {
							return middleware.InitializeOutput{Result: &dynamodb.GetItemOutput{}}, middleware.Metadata{}, nil
						}
						return middleware.InitializeOutput{Result: f.getResult}, middleware.Metadata{}, nil
					default:
						return next.HandleInitialize(ctx, in)
					}
				}), middleware.After)
		})
	})
}

func provisionTestStore(f *fakeProvisionDDB) *M2MStore {
	return NewM2MStore(f.client(), "login-api-table", WithClock(&manualClock{t: time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)}))
}

func clientItemMap(t *testing.T, item MachineClientItem) map[string]types.AttributeValue {
	t.Helper()
	m, err := attributevalue.MarshalMap(item)
	if err != nil {
		t.Fatalf("marshal item: %v", err)
	}
	return m
}

func strAttr(t *testing.T, av types.AttributeValue, name string) string {
	t.Helper()
	s, ok := av.(*types.AttributeValueMemberS)
	if !ok {
		t.Fatalf("%s: expected S, got %T", name, av)
	}
	return s.Value
}

func TestCreateClientRequestShape(t *testing.T) {
	f := &fakeProvisionDDB{}
	store := provisionTestStore(f)

	err := store.CreateClient(context.Background(), &m2m.Client{
		ID:           "event-registration",
		SecretRounds: []string{"hash1"},
		Audiences:    map[string][]string{"profiles-api": {"m2m:player-profiles"}},
		Active:       true,
	})
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	if len(f.puts) != 1 {
		t.Fatalf("expected 1 PutItem, got %d", len(f.puts))
	}
	req := f.puts[0]
	if got := aws.ToString(req.ConditionExpression); got != "attribute_not_exists(PK)" {
		t.Errorf("ConditionExpression = %q", got)
	}
	item := req.Item
	if got := strAttr(t, item["PK"], "PK"); got != "CLIENT#event-registration" {
		t.Errorf("PK = %q", got)
	}
	if got := strAttr(t, item["GSI1PK"], "GSI1PK"); got != M2MClientsPartition {
		t.Errorf("GSI1PK = %q", got)
	}
	if got := strAttr(t, item["GSI1SK"], "GSI1SK"); got != "CLIENT#event-registration" {
		t.Errorf("GSI1SK = %q", got)
	}
	var audiences map[string][]string
	if err := attributevalue.Unmarshal(item["audiences"], &audiences); err != nil {
		t.Fatalf("unmarshal audiences: %v", err)
	}
	if !reflect.DeepEqual(audiences, map[string][]string{"profiles-api": {"m2m:player-profiles"}}) {
		t.Errorf("audiences = %v", audiences)
	}
	if active, ok := item["active"].(*types.AttributeValueMemberBOOL); !ok || !active.Value {
		t.Errorf("active = %v, want true", item["active"])
	}
}

func TestCreateClientConflict(t *testing.T) {
	f := &fakeProvisionDDB{putCondFail: true}
	store := provisionTestStore(f)

	err := store.CreateClient(context.Background(), &m2m.Client{ID: "a"})
	if !errors.Is(err, m2m.ErrClientExists) {
		t.Fatalf("expected ErrClientExists, got %v", err)
	}
}

func TestCreateClientErrorPropagates(t *testing.T) {
	f := &fakeProvisionDDB{putErr: errors.New("ddb down")}
	store := provisionTestStore(f)

	if err := store.CreateClient(context.Background(), &m2m.Client{ID: "a"}); err == nil {
		t.Fatal("expected error, got nil")
	}
}

func queryPage(t *testing.T, ids []string, lastKey map[string]types.AttributeValue) *dynamodb.QueryOutput {
	t.Helper()
	var items []map[string]types.AttributeValue
	for _, id := range ids {
		items = append(items, clientItemMap(t, MachineClientItem{
			PK:           "CLIENT#" + id,
			SK:           "CLIENT#" + id,
			SecretRounds: []string{"hash"},
			Audiences:    map[string][]string{"profiles-api": {"m2m:player-profiles"}},
			Active:       true,
			GSI1PK:       M2MClientsPartition,
			GSI1SK:       "CLIENT#" + id,
		}))
	}
	return &dynamodb.QueryOutput{Items: items, LastEvaluatedKey: lastKey}
}

func TestListClientsQueriesGSI(t *testing.T) {
	nextKey := map[string]types.AttributeValue{"GSI1PK": &types.AttributeValueMemberS{Value: M2MClientsPartition}}
	f := &fakeProvisionDDB{queryPages: []*dynamodb.QueryOutput{
		queryPage(t, []string{"a-client"}, nextKey),
		queryPage(t, []string{"b-client"}, nil),
	}}
	store := provisionTestStore(f)

	clients, err := store.ListClients(context.Background())
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	if len(clients) != 2 || clients[0].ID != "a-client" || clients[1].ID != "b-client" {
		t.Fatalf("unexpected clients: %+v", clients)
	}
	if len(f.queries) != 2 {
		t.Fatalf("expected 2 paginated queries, got %d", len(f.queries))
	}
	req := f.queries[0]
	if got := aws.ToString(req.IndexName); got != M2MClientsIndex {
		t.Errorf("IndexName = %q, want the GSI (no scan)", got)
	}
	if got := aws.ToString(req.KeyConditionExpression); got != "GSI1PK = :pk" {
		t.Errorf("KeyConditionExpression = %q", got)
	}
	if got := strAttr(t, req.ExpressionAttributeValues[":pk"], ":pk"); got != M2MClientsPartition {
		t.Errorf(":pk = %q", got)
	}
	if !reflect.DeepEqual(clients[0].Audiences, map[string][]string{"profiles-api": {"m2m:player-profiles"}}) || !clients[0].Active {
		t.Errorf("client metadata not mapped: %+v", clients[0])
	}
}

func TestListClientsErrorPropagates(t *testing.T) {
	f := &fakeProvisionDDB{queryErr: errors.New("ddb down")}
	store := provisionTestStore(f)

	if _, err := store.ListClients(context.Background()); err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestDeactivateClient(t *testing.T) {
	f := &fakeProvisionDDB{}
	f.updateResult = &dynamodb.UpdateItemOutput{Attributes: clientItemMap(t, MachineClientItem{
		PK:           "CLIENT#a",
		SK:           "CLIENT#a",
		SecretRounds: []string{"hash"},
		Audiences:    map[string][]string{"b-api": {"m2m:c"}},
		Active:       false,
		GSI1PK:       M2MClientsPartition,
		GSI1SK:       "CLIENT#a",
	})}
	store := provisionTestStore(f)

	client, err := store.DeactivateClient(context.Background(), "a")
	if err != nil {
		t.Fatalf("DeactivateClient: %v", err)
	}
	if client.Active || client.ID != "a" {
		t.Fatalf("unexpected client: %+v", client)
	}
	req := f.updates[0]
	if got := aws.ToString(req.ConditionExpression); got != "attribute_exists(PK)" {
		t.Errorf("ConditionExpression = %q", got)
	}
	if got := aws.ToString(req.UpdateExpression); got != "SET active = :false, updatedAt = :now" {
		t.Errorf("UpdateExpression = %q", got)
	}
}

func TestDeactivateClientNotFound(t *testing.T) {
	f := &fakeProvisionDDB{updateCondFail: true}
	store := provisionTestStore(f)

	if _, err := store.DeactivateClient(context.Background(), "missing"); !errors.Is(err, m2m.ErrClientNotFound) {
		t.Fatalf("expected ErrClientNotFound, got %v", err)
	}
}

func TestUpdateRoundsHappyPath(t *testing.T) {
	f := &fakeProvisionDDB{updateResult: &dynamodb.UpdateItemOutput{Attributes: map[string]types.AttributeValue{}}}
	store := provisionTestStore(f)

	err := store.UpdateRounds(context.Background(), "a", []string{"old"}, []string{"new", "old"})
	if err != nil {
		t.Fatalf("UpdateRounds: %v", err)
	}
	req := f.updates[0]
	if got := aws.ToString(req.ConditionExpression); got != "attribute_exists(PK) AND secretRounds = :expected" {
		t.Errorf("ConditionExpression = %q", got)
	}
	if got := aws.ToString(req.UpdateExpression); got != "SET secretRounds = :next, updatedAt = :now" {
		t.Errorf("UpdateExpression = %q", got)
	}
}

func TestUpdateRoundsConflictVsNotFound(t *testing.T) {
	t.Run("concurrent modification", func(t *testing.T) {
		f := &fakeProvisionDDB{
			updateCondFail: true,
			getResult: &dynamodb.GetItemOutput{Item: clientItemMap(t, MachineClientItem{
				PK: "CLIENT#a", SK: "CLIENT#a", SecretRounds: []string{"other"},
				Active: true, GSI1PK: M2MClientsPartition, GSI1SK: "CLIENT#a",
			})},
		}
		store := provisionTestStore(f)

		err := store.UpdateRounds(context.Background(), "a", []string{"stale"}, []string{"new"})
		if !errors.Is(err, m2m.ErrRoundsConflict) {
			t.Fatalf("expected ErrRoundsConflict, got %v", err)
		}
		if len(f.gets) != 1 {
			t.Fatal("expected a distinguishing re-read on conflict")
		}
	})

	t.Run("missing record", func(t *testing.T) {
		f := &fakeProvisionDDB{updateCondFail: true, getResult: &dynamodb.GetItemOutput{}}
		store := provisionTestStore(f)

		err := store.UpdateRounds(context.Background(), "missing", []string{"stale"}, []string{"new"})
		if !errors.Is(err, m2m.ErrClientNotFound) {
			t.Fatalf("expected ErrClientNotFound, got %v", err)
		}
	})
}

func TestUpdateAudiences(t *testing.T) {
	f := &fakeProvisionDDB{}
	f.updateResult = &dynamodb.UpdateItemOutput{Attributes: clientItemMap(t, MachineClientItem{
		PK:           "CLIENT#a",
		SK:           "CLIENT#a",
		SecretRounds: []string{"hash"},
		Audiences:    map[string][]string{"x-api": {"m2m:y"}},
		Active:       true,
		GSI1PK:       M2MClientsPartition,
		GSI1SK:       "CLIENT#a",
	})}
	store := provisionTestStore(f)

	client, err := store.UpdateAudiences(context.Background(), "a",
		map[string][]string{"x-api": {"m2m:y"}})
	if err != nil {
		t.Fatalf("UpdateAudiences: %v", err)
	}
	if !reflect.DeepEqual(client.Audiences, map[string][]string{"x-api": {"m2m:y"}}) {
		t.Fatalf("unexpected audiences: %+v", client)
	}
	req := f.updates[0]
	if got := aws.ToString(req.ConditionExpression); got != "attribute_exists(PK)" {
		t.Errorf("ConditionExpression = %q", got)
	}
	if got := aws.ToString(req.UpdateExpression); got != "SET audiences = :audiences, updatedAt = :now" {
		t.Errorf("UpdateExpression = %q", got)
	}
	if _, ok := req.ExpressionAttributeValues[":audiences"].(*types.AttributeValueMemberM); !ok {
		t.Errorf(":audiences = %T, want M (map replace, secrets untouched)", req.ExpressionAttributeValues[":audiences"])
	}
}

func TestUpdateAudiencesNotFound(t *testing.T) {
	f := &fakeProvisionDDB{updateCondFail: true}
	store := provisionTestStore(f)

	if _, err := store.UpdateAudiences(context.Background(), "missing", map[string][]string{}); !errors.Is(err, m2m.ErrClientNotFound) {
		t.Fatalf("expected ErrClientNotFound, got %v", err)
	}
}
