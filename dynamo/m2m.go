package dynamo

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/International-Combat-Archery-Alliance/login/m2m"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

const (
	// MachineClientPrefix prefixes PK/SK of machine-credential records
	// (bcrypt secretRounds[], allowed audience + scopes).
	MachineClientPrefix = "CLIENT#"
	// RatePrefix prefixes PK/SK of the m2m fixed-window rate-limit items.
	RatePrefix = "RATE#"
)

// M2M limiter defaults.
const (
	DefaultM2MWindowLimit    = 30          // requests per window per clientId
	DefaultM2MWindowDuration = time.Minute // fixed window
)

// MachineClientItem is the CLIENT#<clientId> persistence record. Mapped to
// m2m.Client on read; rotation keeps prior rounds until callers recycle.
type MachineClientItem struct {
	PK           string    `dynamodbav:"PK"`
	SK           string    `dynamodbav:"SK"`
	SecretRounds []string  `dynamodbav:"secretRounds"`
	Audience     string    `dynamodbav:"audience"`
	Scopes       []string  `dynamodbav:"scopes"`
	Active       bool      `dynamodbav:"active"`
	CreatedAt    time.Time `dynamodbav:"createdAt"`
	UpdatedAt    time.Time `dynamodbav:"updatedAt"`
}

var _ m2m.Store = (*M2MStore)(nil)

// rateItem mirrors the RATE# item attributes for SDK unmarshalling. windowEnd
// is stored as a Unix epoch (number) so DynamoDB conditions can compare it
// directly.
type rateItem struct {
	WindowCount int64 `dynamodbav:"windowCount"`
	WindowEnd   int64 `dynamodbav:"windowEnd"`
	TTL         int64 `dynamodbav:"ttl"`
}

// M2MStore provides the machine-credential record (CLIENT#) and the
// fixed-window counter (RATE#) in the login-api table.
// windowEnd marks the end of the current fixed window and rolls the counter
// over atomically (see BumpWindow); the ttl attribute is cleanup-only and is
// never used for correctness (DynamoDB TTL deletion is eventually consistent).
type M2MStore struct {
	client         *dynamodb.Client
	tableName      string
	windowLimit    int64
	windowDuration time.Duration
	clock          m2m.Clock
}

// M2MStoreOption configures an M2MStore.
type M2MStoreOption func(*M2MStore)

// WithM2MWindowLimit overrides the max requests per window per clientId.
func WithM2MWindowLimit(n int) M2MStoreOption {
	return func(s *M2MStore) { s.windowLimit = int64(n) }
}

// WithClock overrides the clock (tests).
func WithClock(c m2m.Clock) M2MStoreOption {
	return func(s *M2MStore) { s.clock = c }
}

// NewM2MStore creates the m2m credential + rate-limit store.
func NewM2MStore(client *dynamodb.Client, tableName string, opts ...M2MStoreOption) *M2MStore {
	s := &M2MStore{
		client:         client,
		tableName:      tableName,
		windowLimit:    DefaultM2MWindowLimit,
		windowDuration: DefaultM2MWindowDuration,
		clock:          m2m.SystemClock(),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// WindowLimit returns the max requests per fixed window per clientId.
func (s *M2MStore) WindowLimit() int64 {
	return s.windowLimit
}

// GetClient fetches the CLIENT#<clientId> record. Returns (nil, nil) when the
// item does not exist.
func (s *M2MStore) GetClient(ctx context.Context, clientID string) (*m2m.Client, error) {
	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.tableName),
		Key:       machineClientKey(clientID),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get machine client %q: %w", clientID, err)
	}
	if result.Item == nil {
		return nil, nil
	}

	var item MachineClientItem
	if err := attributevalue.UnmarshalMap(result.Item, &item); err != nil {
		return nil, fmt.Errorf("failed to unmarshal machine client %q: %w", clientID, err)
	}
	return &m2m.Client{
		ID:           clientID,
		SecretRounds: item.SecretRounds,
		Audience:     item.Audience,
		Scopes:       item.Scopes,
		Active:       item.Active,
	}, nil
}

// BumpWindow increments windowCount for the current fixed window and returns
// the stored counter.
//
// The item stores windowEnd (end of the current fixed window). When the stored
// window has ended, a fresh window starts in the same atomic UpdateItem:
// windowCount resets to 1. ttl is only ever set when missing; correctness
// does not depend on DynamoDB TTL deletion.
func (s *M2MStore) BumpWindow(ctx context.Context, clientID string) (*m2m.RateWindow, error) {
	now := s.clock.Now()
	newWindowEnd := now.Add(s.windowDuration).Unix()

	// Start-or-rollover: succeeds only when the item is absent, has no
	// windowEnd yet, or its window has ended. Concurrent rollovers are safe:
	// exactly one call wins the condition, the rest fall through to the ADD.
	out, err := s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(s.tableName),
		Key:       rateLimitKey(clientID),
		ConditionExpression: aws.String(
			"attribute_not_exists(PK) OR attribute_not_exists(windowEnd) OR windowEnd <= :now"),
		UpdateExpression: aws.String(
			"SET windowCount = :one, windowEnd = :windowEnd, ttl = if_not_exists(ttl, :windowEnd)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":one":       &types.AttributeValueMemberN{Value: "1"},
			":now":       &types.AttributeValueMemberN{Value: strconv.FormatInt(now.Unix(), 10)},
			":windowEnd": &types.AttributeValueMemberN{Value: strconv.FormatInt(newWindowEnd, 10)},
		},
		ReturnValues: types.ReturnValueAllNew,
	})
	if err == nil {
		return rateWindowFromAttributes(out.Attributes, clientID)
	}

	var condErr *types.ConditionalCheckFailedException
	if !errors.As(err, &condErr) {
		return nil, fmt.Errorf("failed to bump m2m rate window for %q: %w", clientID, err)
	}

	// A window is still active: increment it atomically. windowEnd is
	// re-installed if the item was created between the condition check and
	// this ADD (e.g. TTL swept it); ttl is left alone.
	out, err = s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(s.tableName),
		Key:       rateLimitKey(clientID),
		UpdateExpression: aws.String(
			"ADD windowCount :one SET windowEnd = if_not_exists(windowEnd, :windowEnd)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":one":       &types.AttributeValueMemberN{Value: "1"},
			":windowEnd": &types.AttributeValueMemberN{Value: strconv.FormatInt(newWindowEnd, 10)},
		},
		ReturnValues: types.ReturnValueAllNew,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to bump m2m rate window for %q: %w", clientID, err)
	}
	return rateWindowFromAttributes(out.Attributes, clientID)
}

// rateWindowFromAttributes unmarshals the ALL_NEW attributes of a RATE# item
// into a core RateWindow.
func rateWindowFromAttributes(attrs map[string]types.AttributeValue, clientID string) (*m2m.RateWindow, error) {
	var item rateItem
	if err := attributevalue.UnmarshalMap(attrs, &item); err != nil {
		return nil, fmt.Errorf("failed to unmarshal m2m rate window for %q: %w", clientID, err)
	}
	return &m2m.RateWindow{
		WindowCount: item.WindowCount,
	}, nil
}

func machineClientKey(clientID string) map[string]types.AttributeValue {
	id := MachineClientPrefix + clientID
	return map[string]types.AttributeValue{
		"PK": &types.AttributeValueMemberS{Value: id},
		"SK": &types.AttributeValueMemberS{Value: id},
	}
}

func rateLimitKey(clientID string) map[string]types.AttributeValue {
	id := RatePrefix + clientID
	return map[string]types.AttributeValue{
		"PK": &types.AttributeValueMemberS{Value: id},
		"SK": &types.AttributeValueMemberS{Value: id},
	}
}
