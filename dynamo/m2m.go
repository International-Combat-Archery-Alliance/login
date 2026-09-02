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
// and windowEnd are stored as Unix epochs (numbers) so DynamoDB conditions can
// compare them directly.
type rateItem struct {
	WindowCount     int64 `dynamodbav:"windowCount"`
	FailCount       int64 `dynamodbav:"failCount"`
	LockedUntilUnix int64 `dynamodbav:"lockedUntil"`
	WindowEnd       int64 `dynamodbav:"windowEnd"`
	TTL             int64 `dynamodbav:"ttl"`
}

// M2MStore provides the machine-credential record (CLIENT#) and the m2m
// fixed-window limiter + lockout (RATE#) in the login-api table.
// The limiter runs before bcrypt so failed attempts never burn Lambda CPU.
// windowEnd marks the end of the current fixed window and rolls the counter
// over atomically (see BumpWindow); the ttl attribute is cleanup-only and is
// never used for correctness (DynamoDB TTL deletion is eventually consistent).
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

// BumpWindow counts this request against the client's current fixed window and
// returns the window state so the caller can enforce the limit and lockout
// BEFORE doing any crypto work.
//
// The item stores windowEnd (end of the current fixed window). When the stored
// window has ended, a fresh window starts in the same atomic UpdateItem:
// windowCount resets to 1 and failCount to 0. A lockout (lockedUntil) is never
// reset by a window rollover — it persists across windows. ttl is only ever
// set when missing (or extended by the lockout path) so it can never shorten
// lockout state; correctness does not depend on DynamoDB TTL deletion.
func (s *M2MStore) BumpWindow(ctx context.Context, clientID string, now time.Time) (*RateWindow, error) {
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
			"SET windowCount = :one, failCount = :zero, windowEnd = :windowEnd, ttl = if_not_exists(ttl, :windowEnd)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":one":       &types.AttributeValueMemberN{Value: "1"},
			":zero":      &types.AttributeValueMemberN{Value: "0"},
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

	// A window is still active: count this request in it atomically (safe
	// across concurrent Lambda instances). windowEnd is re-installed if the
	// item was created between the condition check and this ADD (e.g. TTL
	// swept it); ttl is left alone so lockout state is never shortened.
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
// into the RateWindow the endpoint enforces.
func rateWindowFromAttributes(attrs map[string]types.AttributeValue, clientID string) (*RateWindow, error) {
	var item rateItem
	if err := attributevalue.UnmarshalMap(attrs, &item); err != nil {
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
// lockout threshold the client is locked until now+lockoutDuration. The
// failCount is per-window: BumpWindow resets it to zero when the window rolls
// over, so the threshold is a per-window threshold. Concurrent failures are
// safe: the lock SET is conditional, so only one of them wins.
//
// ttl is only touched when a lock is set (extended across the lockout); the
// fail ADD never touches ttl, so DynamoDB TTL cannot delete lockout state
// mid-lockout (a regular window item is cleaned up by TTL at its window end,
// and recreation is cheap and correct).
func (s *M2MStore) RecordFailure(ctx context.Context, clientID string, now time.Time) error {
	out, err := s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:        aws.String(s.tableName),
		Key:              rateLimitKey(clientID),
		UpdateExpression: aws.String("ADD failCount :one"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":one": &types.AttributeValueMemberN{Value: "1"},
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

// ResetFailures clears failures + lockout after a successful exchange. The
// rate-limit counter (windowCount) is intentionally left untouched: the limit
// applies per window regardless of success. ttl is set to now+windowDuration
// (always >= the current windowEnd, so the item survives to its window
// boundary); with no lock left, TTL cleanup after that is fine.
func (s *M2MStore) ResetFailures(ctx context.Context, clientID string, now time.Time) error {
	windowEnd := now.Add(s.windowDuration)

	_, err := s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:        aws.String(s.tableName),
		Key:              rateLimitKey(clientID),
		UpdateExpression: aws.String("SET failCount = :zero, ttl = :ttl REMOVE lockedUntil"),
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
