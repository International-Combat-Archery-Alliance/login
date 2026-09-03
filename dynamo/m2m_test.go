package dynamo

import (
	"context"
	"fmt"
	"strconv"
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

// fakeDDB intercepts UpdateItem calls at the middleware layer (no HTTP, no
// AWS): each call consumes the next scripted outcome, and every input is
// recorded so tests can assert the exact expressions sent to DynamoDB.
type fakeDDB struct {
	mu sync.Mutex

	// Per UpdateItem call (in order):
	condFail []bool                      // return ConditionalCheckFailedException
	results  []*dynamodb.UpdateItemOutput // Attributes to return (when not condFail)
	errs     []error                     // generic error to return (overrides both)

	calls []*dynamodb.UpdateItemInput
}

func newFakeDDB() *fakeDDB {
	return &fakeDDB{}
}

// client returns a *dynamodb.Client wired to this fake.
func (f *fakeDDB) client() *dynamodb.Client {
	cfg := aws.Config{
		Region:      "us-east-1",
		Credentials: aws.AnonymousCredentials{},
	}
	return dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
		o.APIOptions = append(o.APIOptions, func(stack *middleware.Stack) error {
			return stack.Initialize.Add(
				middleware.InitializeMiddlewareFunc("fake-dynamo", func(
					ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler,
				) (middleware.InitializeOutput, middleware.Metadata, error) {
					f.mu.Lock()
					defer f.mu.Unlock()

					req, ok := in.Parameters.(*dynamodb.UpdateItemInput)
					if !ok {
						return next.HandleInitialize(ctx, in)
					}

					step := len(f.calls)
					f.calls = append(f.calls, req)

					if step < len(f.errs) && f.errs[step] != nil {
						return middleware.InitializeOutput{}, middleware.Metadata{}, f.errs[step]
					}
					if step < len(f.condFail) && f.condFail[step] {
						return middleware.InitializeOutput{}, middleware.Metadata{},
							&types.ConditionalCheckFailedException{Message: aws.String("conditional check failed")}
					}
					if step < len(f.results) && f.results[step] != nil {
						return middleware.InitializeOutput{Result: f.results[step]}, middleware.Metadata{}, nil
					}
					return middleware.InitializeOutput{}, middleware.Metadata{},
						fmt.Errorf("no scripted response for UpdateItem call %d", step)
				}), middleware.After)
		})
	})
}

func attrs(t *testing.T, item rateItem) map[string]types.AttributeValue {
	t.Helper()
	m, err := attributevalue.MarshalMap(item)
	if err != nil {
		t.Fatalf("marshal attributes: %v", err)
	}
	return m
}

type manualClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *manualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *manualClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

func newTestStore(t *testing.T, f *fakeDDB, clock m2m.Clock) *M2MStore {
	t.Helper()
	return NewM2MStore(f.client(), "login-api-table", WithClock(clock))
}

func num(t *testing.T, v types.AttributeValue, name string) string {
	t.Helper()
	n, ok := v.(*types.AttributeValueMemberN)
	if !ok {
		t.Fatalf("%s: expected AttributeValueMemberN, got %T", name, v)
	}
	return n.Value
}

func TestBumpWindowStartsFreshWindow(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	clock := &manualClock{}
	clock.Set(now)
	f := newFakeDDB()
	f.results = []*dynamodb.UpdateItemOutput{
		{Attributes: attrs(t, rateItem{
			WindowCount: 1,
			WindowEnd:   now.Add(time.Minute).Unix(),
			TTL:         now.Add(time.Minute).Unix(),
		})},
	}
	store := newTestStore(t, f, clock)

	w, err := store.BumpWindow(context.Background(), "client-1")
	if err != nil {
		t.Fatalf("BumpWindow: %v", err)
	}
	if w.WindowCount != 1 {
		t.Fatalf("unexpected window state: %+v", w)
	}

	req := f.calls[0]
	if got := aws.ToString(req.ConditionExpression); got != "attribute_not_exists(PK) OR attribute_not_exists(windowEnd) OR windowEnd <= :now" {
		t.Errorf("fresh-path ConditionExpression = %q", got)
	}
	if got := aws.ToString(req.UpdateExpression); got != "SET windowCount = :one, windowEnd = :windowEnd, ttl = if_not_exists(ttl, :windowEnd)" {
		t.Errorf("fresh-path UpdateExpression = %q", got)
	}
	if got := num(t, req.ExpressionAttributeValues[":now"], ":now"); got != strconv.FormatInt(now.Unix(), 10) {
		t.Errorf(":now = %q", got)
	}
	if got := num(t, req.ExpressionAttributeValues[":windowEnd"], ":windowEnd"); got != strconv.FormatInt(now.Add(time.Minute).Unix(), 10) {
		t.Errorf(":windowEnd = %q", got)
	}
	if got := num(t, req.ExpressionAttributeValues[":one"], ":one"); got != "1" {
		t.Errorf(":one = %q", got)
	}
	if req.ReturnValues != types.ReturnValueAllNew {
		t.Errorf("ReturnValues = %q", req.ReturnValues)
	}
	assertRateKey(t, req, "client-1")
}

func TestBumpWindowCountsWithinActiveWindow(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	clock := &manualClock{}
	clock.Set(now)
	f := newFakeDDB()
	f.condFail = []bool{true}
	f.results = []*dynamodb.UpdateItemOutput{
		nil,
		{Attributes: attrs(t, rateItem{
			WindowCount: 2,
			WindowEnd:   now.Add(time.Minute).Unix(),
			TTL:         now.Add(time.Minute).Unix(),
		})},
	}
	store := newTestStore(t, f, clock)

	clock.Set(now.Add(30 * time.Second))
	w, err := store.BumpWindow(context.Background(), "client-1")
	if err != nil {
		t.Fatalf("BumpWindow: %v", err)
	}
	if w.WindowCount != 2 {
		t.Fatalf("unexpected window state: %+v", w)
	}

	if got := aws.ToString(f.calls[0].UpdateExpression); got != "SET windowCount = :one, windowEnd = :windowEnd, ttl = if_not_exists(ttl, :windowEnd)" {
		t.Errorf("attempt 1 expression = %q", got)
	}
	req := f.calls[1]
	if got := aws.ToString(req.UpdateExpression); got != "ADD windowCount :one SET windowEnd = if_not_exists(windowEnd, :windowEnd)" {
		t.Errorf("in-window UpdateExpression = %q", got)
	}
	if req.ConditionExpression != nil {
		t.Errorf("in-window call should have no ConditionExpression, got %q", aws.ToString(req.ConditionExpression))
	}
}

func TestBumpWindowRollsOverWhenWindowEnded(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	clock := &manualClock{}
	clock.Set(now)
	f := newFakeDDB()
	f.results = []*dynamodb.UpdateItemOutput{
		{Attributes: attrs(t, rateItem{
			WindowCount: 1,
			WindowEnd:   now.Add(time.Minute).Unix(),
			TTL:         now.Add(time.Minute).Unix(),
		})},
		{Attributes: attrs(t, rateItem{
			WindowCount: 1,
			WindowEnd:   now.Add(2 * time.Minute).Unix(),
			TTL:         now.Add(2 * time.Minute).Unix(),
		})},
	}
	store := newTestStore(t, f, clock)

	if _, err := store.BumpWindow(context.Background(), "client-1"); err != nil {
		t.Fatalf("BumpWindow(1): %v", err)
	}
	clock.Set(now.Add(90 * time.Second))
	w, err := store.BumpWindow(context.Background(), "client-1")
	if err != nil {
		t.Fatalf("BumpWindow(2): %v", err)
	}
	if w.WindowCount != 1 {
		t.Errorf("window did not roll over: WindowCount = %d, want 1", w.WindowCount)
	}
	if got := num(t, f.calls[1].ExpressionAttributeValues[":windowEnd"], ":windowEnd"); got != strconv.FormatInt(now.Add(150*time.Second).Unix(), 10) {
		t.Errorf("new :windowEnd = %q, want %v", got, now.Add(150*time.Second).Unix())
	}
}

func TestBumpWindowErrorPropagates(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	clock := &manualClock{}
	clock.Set(now)
	f := newFakeDDB()
	f.errs = []error{fmt.Errorf("db is on fire")}
	store := newTestStore(t, f, clock)

	if _, err := store.BumpWindow(context.Background(), "client-1"); err == nil {
		t.Fatal("expected error, got nil")
	}
}

func assertRateKey(t *testing.T, req *dynamodb.UpdateItemInput, clientID string) {
	t.Helper()
	want := RatePrefix + clientID
	for _, key := range []string{"PK", "SK"} {
		av, ok := req.Key[key].(*types.AttributeValueMemberS)
		if !ok {
			t.Fatalf("Key[%s] = %T, want AttributeValueMemberS", key, req.Key[key])
		}
		if av.Value != want {
			t.Errorf("Key[%s] = %q, want %q", key, av.Value, want)
		}
	}
}
