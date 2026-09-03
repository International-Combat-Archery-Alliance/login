package dynamo

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
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
	// M2MClientsIndex is the GSI backing the admin list (no table scan).
	M2MClientsIndex = "GSI1"
	// M2MClientsPartition is the constant GSI1PK shared by every CLIENT#
	// record; GSI1SK (CLIENT#<clientId>) orders the list by clientId.
	M2MClientsPartition = "M2M_CLIENTS"
)

// M2M limiter defaults.
const (
	DefaultM2MWindowLimit    = 30          // requests per window per clientId
	DefaultM2MWindowDuration = time.Minute // fixed window
)

// MachineClientItem is the CLIENT#<clientId> persistence record. Mapped to
// m2m.Client on read; rotation keeps prior rounds until callers recycle.
// GSI1PK/GSI1SK back the admin list query (constant partition, id-ordered).
type MachineClientItem struct {
	PK           string              `dynamodbav:"PK"`
	SK           string              `dynamodbav:"SK"`
	SecretRounds []string            `dynamodbav:"secretRounds"`
	Audiences    map[string][]string `dynamodbav:"audiences"`
	Active       bool                `dynamodbav:"active"`
	CreatedAt    time.Time           `dynamodbav:"createdAt"`
	UpdatedAt    time.Time           `dynamodbav:"updatedAt"`
	GSI1PK       string              `dynamodbav:"GSI1PK"`
	GSI1SK       string              `dynamodbav:"GSI1SK"`
}

var _ m2m.Store = (*M2MStore)(nil)
var _ m2m.ProvisionStore = (*M2MStore)(nil)

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
	return machineClientFromItem(clientID, item), nil
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

// CreateClient writes a CLIENT#<clientId> record. The condition makes the
// verdict exact: an existing id (including revoked records) surfaces as
// m2m.ErrClientExists.
func (s *M2MStore) CreateClient(ctx context.Context, client *m2m.Client) error {
	now := s.clock.Now()
	item := MachineClientItem{
		PK:           MachineClientPrefix + client.ID,
		SK:           MachineClientPrefix + client.ID,
		SecretRounds: client.SecretRounds,
		Audiences:    client.Audiences,
		Active:       client.Active,
		CreatedAt:    now,
		UpdatedAt:    now,
		GSI1PK:       M2MClientsPartition,
		GSI1SK:       MachineClientPrefix + client.ID,
	}
	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return fmt.Errorf("failed to marshal machine client %q: %w", client.ID, err)
	}

	_, err = s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(s.tableName),
		Item:                av,
		ConditionExpression: aws.String("attribute_not_exists(PK)"),
	})
	if err != nil {
		var condErr *types.ConditionalCheckFailedException
		if errors.As(err, &condErr) {
			return fmt.Errorf("machine client %q already exists: %w", client.ID, m2m.ErrClientExists)
		}
		return fmt.Errorf("failed to put machine client %q: %w", client.ID, err)
	}
	return nil
}

// ListClients returns every CLIENT# record via the GSI (no scan), ordered by
// clientId. Secrets are never exposed — callers only receive metadata, and
// the item holds hashes, never plaintext.
func (s *M2MStore) ListClients(ctx context.Context) ([]*m2m.Client, error) {
	var clients []*m2m.Client
	var startKey map[string]types.AttributeValue

	for {
		out, err := s.client.Query(ctx, &dynamodb.QueryInput{
			TableName:              aws.String(s.tableName),
			IndexName:              aws.String(M2MClientsIndex),
			KeyConditionExpression: aws.String("GSI1PK = :pk"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":pk": &types.AttributeValueMemberS{Value: M2MClientsPartition},
			},
			ExclusiveStartKey: startKey,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list machine clients: %w", err)
		}

		var items []MachineClientItem
		if err := attributevalue.UnmarshalListOfMaps(out.Items, &items); err != nil {
			return nil, fmt.Errorf("failed to unmarshal machine clients: %w", err)
		}
		for _, item := range items {
			clients = append(clients, machineClientFromItem(strings.TrimPrefix(item.PK, MachineClientPrefix), item))
		}

		if out.LastEvaluatedKey == nil {
			break
		}
		startKey = out.LastEvaluatedKey
	}
	return clients, nil
}

// DeactivateClient marks the record inactive (revoke). Caller-side secret
// storage is never touched — removing the caller's copy is an operator step.
// Idempotent: an already-inactive record succeeds.
// A missing id surfaces as m2m.ErrClientNotFound.
func (s *M2MStore) DeactivateClient(ctx context.Context, clientID string) (*m2m.Client, error) {
	out, err := s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:           aws.String(s.tableName),
		Key:                 machineClientKey(clientID),
		ConditionExpression: aws.String("attribute_exists(PK)"),
		UpdateExpression:    aws.String("SET active = :false, updatedAt = :now"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":false": &types.AttributeValueMemberBOOL{Value: false},
			":now":   &types.AttributeValueMemberS{Value: s.clock.Now().UTC().Format(time.RFC3339)},
		},
		ReturnValues: types.ReturnValueAllNew,
	})
	if err != nil {
		var condErr *types.ConditionalCheckFailedException
		if errors.As(err, &condErr) {
			return nil, fmt.Errorf("machine client %q not found: %w", clientID, m2m.ErrClientNotFound)
		}
		return nil, fmt.Errorf("failed to deactivate machine client %q: %w", clientID, err)
	}

	var item MachineClientItem
	if err := attributevalue.UnmarshalMap(out.Attributes, &item); err != nil {
		return nil, fmt.Errorf("failed to unmarshal machine client %q: %w", clientID, err)
	}
	return machineClientFromItem(clientID, item), nil
}

// UpdateRounds swaps secretRounds[] only when it still equals expected
// (optimistic locking — a concurrent rotation surfaces as
// m2m.ErrRoundsConflict instead of silently dropping a round). A missing id
// surfaces as m2m.ErrClientNotFound.
func (s *M2MStore) UpdateRounds(ctx context.Context, clientID string, expected, next []string) error {
	expectedAV, err := attributevalue.MarshalList(expected)
	if err != nil {
		return fmt.Errorf("failed to marshal expected rounds for %q: %w", clientID, err)
	}
	nextAV, err := attributevalue.MarshalList(next)
	if err != nil {
		return fmt.Errorf("failed to marshal next rounds for %q: %w", clientID, err)
	}

	_, err = s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:           aws.String(s.tableName),
		Key:                 machineClientKey(clientID),
		ConditionExpression: aws.String("attribute_exists(PK) AND secretRounds = :expected"),
		UpdateExpression:    aws.String("SET secretRounds = :next, updatedAt = :now"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":expected": &types.AttributeValueMemberL{Value: expectedAV},
			":next":     &types.AttributeValueMemberL{Value: nextAV},
			":now":      &types.AttributeValueMemberS{Value: s.clock.Now().UTC().Format(time.RFC3339)},
		},
	})
	if err == nil {
		return nil
	}
	var condErr *types.ConditionalCheckFailedException
	if !errors.As(err, &condErr) {
		return fmt.Errorf("failed to rotate machine client %q: %w", clientID, err)
	}

	// The condition conflates "missing" with "concurrently modified": one read
	// on the conflict path tells them apart.
	current, getErr := s.GetClient(ctx, clientID)
	if getErr != nil {
		return fmt.Errorf("failed to re-read machine client %q after conflict: %w", clientID, getErr)
	}
	if current == nil {
		return fmt.Errorf("machine client %q not found: %w", clientID, m2m.ErrClientNotFound)
	}
	return fmt.Errorf("machine client %q changed concurrently: %w", clientID, m2m.ErrRoundsConflict)
}

// UpdateAudiences replaces the audiences map (full replace; entries the
// caller omitted are removed). Secrets and active state are untouched, so
// this applies to revoked clients too. A missing id surfaces as
// m2m.ErrClientNotFound.
func (s *M2MStore) UpdateAudiences(ctx context.Context, clientID string, audiences map[string][]string) (*m2m.Client, error) {
	audiencesAV, err := attributevalue.Marshal(audiences)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal audiences for %q: %w", clientID, err)
	}

	out, err := s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:           aws.String(s.tableName),
		Key:                 machineClientKey(clientID),
		ConditionExpression: aws.String("attribute_exists(PK)"),
		UpdateExpression:    aws.String("SET audiences = :audiences, updatedAt = :now"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":audiences": audiencesAV,
			":now":       &types.AttributeValueMemberS{Value: s.clock.Now().UTC().Format(time.RFC3339)},
		},
		ReturnValues: types.ReturnValueAllNew,
	})
	if err != nil {
		var condErr *types.ConditionalCheckFailedException
		if errors.As(err, &condErr) {
			return nil, fmt.Errorf("machine client %q not found: %w", clientID, m2m.ErrClientNotFound)
		}
		return nil, fmt.Errorf("failed to update audiences for %q: %w", clientID, err)
	}

	var item MachineClientItem
	if err := attributevalue.UnmarshalMap(out.Attributes, &item); err != nil {
		return nil, fmt.Errorf("failed to unmarshal machine client %q: %w", clientID, err)
	}
	return machineClientFromItem(clientID, item), nil
}

func machineClientFromItem(clientID string, item MachineClientItem) *m2m.Client {
	return &m2m.Client{
		ID:           clientID,
		SecretRounds: item.SecretRounds,
		Audiences:    item.Audiences,
		Active:       item.Active,
	}
}

func rateLimitKey(clientID string) map[string]types.AttributeValue {
	id := RatePrefix + clientID
	return map[string]types.AttributeValue{
		"PK": &types.AttributeValueMemberS{Value: id},
		"SK": &types.AttributeValueMemberS{Value: id},
	}
}
