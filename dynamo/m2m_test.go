package dynamo

import (
	"context"
	"fmt"
	"strconv"
	"strings"
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
	condFail []bool                       // return ConditionalCheckFailedException
	results  []*dynamodb.UpdateItemOutput // Attributes to return (when not condFail)
	errs     []error                      // generic error to return (overrides both)

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
			FailCount:   0,
			WindowEnd:   now.Add(time.Minute).Unix(),
			TTL:         now.Add(time.Minute).Unix(),
		})},
	}
	store := newTestStore(t, f, clock)

	w, err := store.BumpWindow(context.Background(), "client-1")
	if err != nil {
		t.Fatalf("BumpWindow: %v", err)
	}
	if w.WindowCount != 1 || w.FailCount != 0 || w.LockedUntil != nil {
		t.Fatalf("unexpected window state: %+v", w)
	}

	req := f.calls[0]
	if got := aws.ToString(req.ConditionExpression); got != "attribute_not_exists(PK) OR attribute_not_exists(windowEnd) OR windowEnd <= :now" {
		t.Errorf("fresh-path ConditionExpression = %q", got)
	}
	if got := aws.ToString(req.UpdateExpression); got != "SET windowCount = :one, failCount = :zero, windowEnd = :windowEnd, ttl = if_not_exists(ttl, :windowEnd)" {
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
	if got := num(t, req.ExpressionAttributeValues[":zero"], ":zero"); got != "0" {
		t.Errorf(":zero = %q", got)
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
	// Active window: the start-or-rollover attempt fails its condition, then
	// the in-window ADD succeeds.
	f.condFail = []bool{true}
	f.results = []*dynamodb.UpdateItemOutput{
		nil, // call 0: conditional check failed (result unused)
		{Attributes: attrs(t, rateItem{
			WindowCount: 2,
			FailCount:   1,
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
	if w.WindowCount != 2 || w.FailCount != 1 {
		t.Fatalf("unexpected window state: %+v", w)
	}

	if got := aws.ToString(f.calls[0].UpdateExpression); got != "SET windowCount = :one, failCount = :zero, windowEnd = :windowEnd, ttl = if_not_exists(ttl, :windowEnd)" {
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
	// First call (t0) starts the window; second call (t0+90s) hits the
	// rollover path — both succeed with a fresh window.
	f.results = []*dynamodb.UpdateItemOutput{
		{Attributes: attrs(t, rateItem{
			WindowCount: 1,
			FailCount:   0,
			WindowEnd:   now.Add(time.Minute).Unix(),
			TTL:         now.Add(time.Minute).Unix(),
		})},
		{Attributes: attrs(t, rateItem{
			WindowCount: 1, // reset, not 3
			FailCount:   0, // failure count also resets per window
			WindowEnd:   now.Add(2 * time.Minute).Unix(),
			TTL:         now.Add(2 * time.Minute).Unix(),
		})},
	}
	store := newTestStore(t, f, clock)

	// First request at t0 (window [0, 60s)), then a request at t0+90s: the
	// window must have rolled over.
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
	if w.FailCount != 0 {
		t.Errorf("failCount not reset on rollover: %d, want 0", w.FailCount)
	}
	if got := num(t, f.calls[1].ExpressionAttributeValues[":windowEnd"], ":windowEnd"); got != strconv.FormatInt(now.Add(150*time.Second).Unix(), 10) {
		t.Errorf("new :windowEnd = %q, want %v (request now+90s + window duration)", got, now.Add(150*time.Second).Unix())
	}
}

func TestBumpWindowPreservesLockoutAcrossRollover(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	clock := &manualClock{}
	clock.Set(now)
	f := newFakeDDB()
	// Window ended while the client is still locked: rollover must not clear
	// the lockout.
	f.results = []*dynamodb.UpdateItemOutput{
		{Attributes: attrs(t, rateItem{
			WindowCount:     1,
			FailCount:       0,
			LockedUntilUnix: now.Add(15 * time.Minute).Unix(),
			WindowEnd:       now.Add(time.Minute).Unix(),
			TTL:             now.Add(15*time.Minute + 5*time.Second).Unix(),
		})},
	}
	store := newTestStore(t, f, clock)

	clock.Set(now.Add(2 * time.Minute))
	w, err := store.BumpWindow(context.Background(), "client-1")
	if err != nil {
		t.Fatalf("BumpWindow: %v", err)
	}
	if w.LockedUntil == nil {
		t.Fatal("lockout was cleared by window rollover")
	}
	if want := now.Add(15 * time.Minute).UTC(); !w.LockedUntil.Equal(want) {
		t.Errorf("LockedUntil = %v, want %v", w.LockedUntil, want)
	}
	got := aws.ToString(f.calls[0].UpdateExpression)
	if strings.Contains(got, "lockedUntil") {
		t.Errorf("fresh-window expression must not reference lockedUntil: %q", got)
	}
	if strings.Contains(got, "ttl = :ttl") {
		t.Errorf("fresh-window expression must not unconditionally set ttl: %q", got)
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

func TestRecordFailureBelowThreshold(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	clock := &manualClock{}
	clock.Set(now)
	f := newFakeDDB()
	f.results = []*dynamodb.UpdateItemOutput{
		{Attributes: attrs(t, rateItem{WindowCount: 1, FailCount: 4, WindowEnd: now.Add(time.Minute).Unix()})},
	}
	store := newTestStore(t, f, clock)

	if err := store.RecordFailure(context.Background(), "client-1"); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
	if len(f.calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(f.calls))
	}
	if got := aws.ToString(f.calls[0].UpdateExpression); got != "ADD failCount :one" {
		t.Errorf("UpdateExpression = %q", got)
	}
}

func TestRecordFailureLocksAtThreshold(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	clock := &manualClock{}
	clock.Set(now)
	f := newFakeDDB()
	f.results = []*dynamodb.UpdateItemOutput{
		// ADD failCount lands at the threshold...
		{Attributes: attrs(t, rateItem{WindowCount: 1, FailCount: 5, WindowEnd: now.Add(time.Minute).Unix()})},
		// ...then the conditional lock SET (scripted ALL_NEW state).
		{Attributes: attrs(t, rateItem{
			WindowCount:     1,
			FailCount:       5,
			LockedUntilUnix: now.Add(15 * time.Minute).Unix(),
			WindowEnd:       now.Add(time.Minute).Unix(),
			TTL:             now.Add(15*time.Minute + 5*time.Second).Unix(),
		})},
	}
	store := newTestStore(t, f, clock)

	if err := store.RecordFailure(context.Background(), "client-1"); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
	if len(f.calls) != 2 {
		t.Fatalf("expected 2 calls, got %d", len(f.calls))
	}
	if got := aws.ToString(f.calls[0].UpdateExpression); got != "ADD failCount :one" {
		t.Errorf("fail-ADD UpdateExpression = %q", got)
	}
	lock := f.calls[1]
	if got := aws.ToString(lock.UpdateExpression); got != "SET lockedUntil = :lockUntil, ttl = :lockTtl" {
		t.Errorf("lock UpdateExpression = %q", got)
	}
	if got := aws.ToString(lock.ConditionExpression); got != "attribute_not_exists(lockedUntil) OR lockedUntil < :now" {
		t.Errorf("lock ConditionExpression = %q", got)
	}
	if got := num(t, lock.ExpressionAttributeValues[":lockUntil"], ":lockUntil"); got != strconv.FormatInt(now.Add(15*time.Minute).Unix(), 10) {
		t.Errorf(":lockUntil = %q, want %v (now+15m)", got, now.Add(15*time.Minute).Unix())
	}
	if got := num(t, lock.ExpressionAttributeValues[":lockTtl"], ":lockTtl"); got != strconv.FormatInt(now.Add(15*time.Minute+5*time.Second).Unix(), 10) {
		t.Errorf(":lockTtl = %q, want %v (lockUntil+5s)", got, now.Add(15*time.Minute+5*time.Second).Unix())
	}
}

func TestResetFailuresClearsLockAndFailures(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	clock := &manualClock{}
	clock.Set(now)
	f := newFakeDDB()
	f.results = []*dynamodb.UpdateItemOutput{
		{Attributes: attrs(t, rateItem{WindowCount: 1, FailCount: 0, WindowEnd: now.Add(time.Minute).Unix(), TTL: now.Add(time.Minute).Unix()})},
	}
	store := newTestStore(t, f, clock)

	if err := store.ResetFailures(context.Background(), "client-1"); err != nil {
		t.Fatalf("ResetFailures: %v", err)
	}
	if len(f.calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(f.calls))
	}
	req := f.calls[0]
	if got := aws.ToString(req.UpdateExpression); got != "SET failCount = :zero, ttl = :ttl REMOVE lockedUntil" {
		t.Errorf("UpdateExpression = %q", got)
	}
	if got := num(t, req.ExpressionAttributeValues[":ttl"], ":ttl"); got != strconv.FormatInt(now.Add(time.Minute).Unix(), 10) {
		t.Errorf(":ttl = %q", got)
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
