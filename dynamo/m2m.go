package dynamo

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

const (
	// MachineClientPrefix prefixes PK/SK of machine-credential records
	// (bcrypt secretRounds[], allowed audience + scopes).
	MachineClientPrefix = "CLIENT#"
	// RatePrefix prefixes PK/SK of the m2m fixed-window rate-limit/lockout
	// items.
	RatePrefix = "RATE#"
)

// M2M limiter defaults.
const (
	DefaultM2MWindowLimit      = 30          // requests per window per clientId
	DefaultM2MWindowDuration   = time.Minute // fixed window
	DefaultM2MLockoutThreshold = 5           // failed attempts before lockout
	DefaultM2MLockoutDuration  = 15 * time.Minute
)

// MachineClientItem is the CLIENT#<clientId> record in the login-api table.
// secretRounds is an array so rotation keeps a grace window: keep the previous
// round until all callers have recycled, then drop it.
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

// RateWindow is the state of a client's current fixed window, returned by
// BumpWindow (ALL_NEW attributes of the RATE#<clientId> item).
type RateWindow struct {
	WindowCount int64
	FailCount   int64
	LockedUntil *time.Time
}

// rateItem mirrors the RATE# item attributes for SDK unmarshalling. lockedUntil
// is stored as a Unix epoch (number) so DynamoDB conditions can compare it
// directly.
type rateItem struct {
	WindowCount     int64 `dynamodbav:"windowCount"`
	FailCount       int64 `dynamodbav:"failCount"`
	LockedUntilUnix int64 `dynamodbav:"lockedUntil"`
	TTL             int64 `dynamodbav:"ttl"`
}

// M2MStore provides the machine-credential record (CLIENT#) and the m2m
// fixed-window limiter + lockout (RATE#) in the login-api table.
// The limiter runs before bcrypt so failed attempts never burn Lambda CPU.
// Window items carry a ttl; locked items' ttl spans the lockout so DynamoDB
// TTL cleans stale items.
type M2MStore struct {
	client           *dynamodb.Client
	tableName        string
	windowLimit      int64
	windowDuration   time.Duration
	lockoutThreshold int64
	lockoutDuration  time.Duration
}

// M2MStoreOption configures an M2MStore.
type M2MStoreOption func(*M2MStore)

// WithM2MWindowLimit overrides the max requests per window per clientId.
func WithM2MWindowLimit(n int) M2MStoreOption {
	return func(s *M2MStore) { s.windowLimit = int64(n) }
}

// WithM2MLockoutThreshold overrides the number of failed attempts that
// triggers a lockout.
func WithM2MLockoutThreshold(n int) M2MStoreOption {
	return func(s *M2MStore) { s.lockoutThreshold = int64(n) }
}

// NewM2MStore creates the m2m credential + rate-limit store.
func NewM2MStore(client *dynamodb.Client, tableName string, opts ...M2MStoreOption) *M2MStore {
	s := &M2MStore{
		client:           client,
		tableName:        tableName,
		windowLimit:      DefaultM2MWindowLimit,
		windowDuration:   DefaultM2MWindowDuration,
		lockoutThreshold: DefaultM2MLockoutThreshold,
		lockoutDuration:  DefaultM2MLockoutDuration,
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
// client does not exist (the caller equalizes timing with a dummy bcrypt
// compare so existence is not a timing oracle).
func (s *M2MStore) GetClient(ctx context.Context, clientID string) (*MachineClientItem, error) {
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
	return &item, nil
}

// BumpWindow counts this request against the client's current fixed window
// (init-or-claim: creates the item on first request of a window, then ADD 1
// atomically — safe across concurrent Lambda instances). It returns the
// window state so the caller can enforce the limit and lockout BEFORE doing
// any crypto work.
func (s *M2MStore) BumpWindow(ctx context.Context, clientID string, now time.Time) (*RateWindow, error) {
	windowEnd := now.Add(s.windowDuration)

	out, err := s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(s.tableName),
		Key:       rateLimitKey(clientID),
		// Init-or-claim: windowCount starts at 1 on create; the ADD is atomic
		// across instances. ttl is refreshed to the end of the current window.
		UpdateExpression: aws.String("SET windowCount = if_not_exists(windowCount, :zero) + :one, failCount = if_not_exists(failCount, :zero), ttl = :ttl"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":one":  &types.AttributeValueMemberN{Value: "1"},
			":zero": &types.AttributeValueMemberN{Value: "0"},
			":ttl":  &types.AttributeValueMemberN{Value: strconv.FormatInt(windowEnd.Unix(), 10)},
		},
		ReturnValues: types.ReturnValueAllNew,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to bump m2m rate window for %q: %w", clientID, err)
	}

	var item rateItem
	if err := attributevalue.UnmarshalMap(out.Attributes, &item); err != nil {
		return nil, fmt.Errorf("failed to unmarshal m2m rate window for %q: %w", clientID, err)
	}
	var lockedUntil *time.Time
	if item.LockedUntilUnix != 0 {
		t := time.Unix(item.LockedUntilUnix, 0).UTC()
		lockedUntil = &t
	}
	return &RateWindow{
		WindowCount: item.WindowCount,
		FailCount:   item.FailCount,
		LockedUntil: lockedUntil,
	}, nil
}

// RecordFailure counts a failed credential attempt (ADD failCount). At the
// lockout threshold the client is locked until now+lockoutDuration; the item's
// ttl is extended across the lockout so DynamoDB TTL does not delete the
// lockout state mid-way. Concurrent failures are safe: the lock SET is
// conditional, so only one of them wins.
func (s *M2MStore) RecordFailure(ctx context.Context, clientID string, now time.Time) error {
	windowEnd := now.Add(s.windowDuration)

	out, err := s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:        aws.String(s.tableName),
		Key:              rateLimitKey(clientID),
		UpdateExpression: aws.String("ADD failCount :one SET ttl = :ttl"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":one": &types.AttributeValueMemberN{Value: "1"},
			":ttl": &types.AttributeValueMemberN{Value: strconv.FormatInt(windowEnd.Unix(), 10)},
		},
		ReturnValues: types.ReturnValueAllNew,
	})
	if err != nil {
		return fmt.Errorf("failed to record m2m failure for %q: %w", clientID, err)
	}

	var item rateItem
	if err := attributevalue.UnmarshalMap(out.Attributes, &item); err != nil {
		return fmt.Errorf("failed to unmarshal m2m rate window for %q: %w", clientID, err)
	}

	if item.FailCount >= s.lockoutThreshold {
		if item.LockedUntilUnix == 0 || time.Unix(item.LockedUntilUnix, 0).Before(now) {
			lockUntil := now.Add(s.lockoutDuration)
			_, lockErr := s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
				TableName:           aws.String(s.tableName),
				Key:                 rateLimitKey(clientID),
				UpdateExpression:    aws.String("SET lockedUntil = :lockUntil, ttl = :lockTtl"),
				ConditionExpression: aws.String("attribute_not_exists(lockedUntil) OR lockedUntil < :now"),
				ExpressionAttributeValues: map[string]types.AttributeValue{
					":lockUntil": &types.AttributeValueMemberN{Value: strconv.FormatInt(lockUntil.Unix(), 10)},
					":lockTtl":   &types.AttributeValueMemberN{Value: strconv.FormatInt(lockUntil.Add(5*time.Second).Unix(), 10)},
					":now":       &types.AttributeValueMemberN{Value: strconv.FormatInt(now.Unix(), 10)},
				},
			})
			if lockErr != nil {
				var condErr *types.ConditionalCheckFailedException
				// Another concurrent failure already locked the client; the
				// lock stands.
				if !errors.As(lockErr, &condErr) {
					return fmt.Errorf("failed to lock m2m client %q: %w", clientID, lockErr)
				}
			}
		}
	}
	return nil
}

// ResetFailures clears failures + lockout after a successful exchange.
func (s *M2MStore) ResetFailures(ctx context.Context, clientID string, now time.Time) error {
	windowEnd := now.Add(s.windowDuration)

	_, err := s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:        aws.String(s.tableName),
		Key:              rateLimitKey(clientID),
		UpdateExpression: aws.String("SET failCount = :zero REMOVE lockedUntil SET ttl = :ttl"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":zero": &types.AttributeValueMemberN{Value: "0"},
			":ttl":  &types.AttributeValueMemberN{Value: strconv.FormatInt(windowEnd.Unix(), 10)},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to reset m2m failures for %q: %w", clientID, err)
	}
	return nil
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
