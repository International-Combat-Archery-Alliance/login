package dynamo

import (
	"context"
	"fmt"
	"time"

	"github.com/International-Combat-Archery-Alliance/auth"
	"github.com/International-Combat-Archery-Alliance/auth/token"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

const (
	// RefreshTokenPrefix is used for PK and SK of refresh token items
	RefreshTokenPrefix = "REFRESH_TOKEN#"
)

// RefreshTokenItem represents a refresh token stored in DynamoDB
type RefreshTokenItem struct {
	PK        string    `dynamodbav:"PK"`
	SK        string    `dynamodbav:"SK"`
	UserEmail string    `dynamodbav:"userEmail"`
	Picture   string    `dynamodbav:"picture"`
	Roles     []string  `dynamodbav:"roles"`
	ExpiresAt time.Time `dynamodbav:"expiresAt"` // Application-level expiration
	TTL       int64     `dynamodbav:"ttl"`       // DynamoDB TTL attribute (Unix timestamp)
	CreatedAt time.Time `dynamodbav:"createdAt"`
	TokenType string    `dynamodbav:"tokenType"`
}

// DynamoDBRefreshTokenStore implements token.RefreshTokenStore using DynamoDB
type DynamoDBRefreshTokenStore struct {
	client    *dynamodb.Client
	tableName string
}

// NewDynamoDBRefreshTokenStore creates a new DynamoDB refresh token store
func NewDynamoDBRefreshTokenStore(client *dynamodb.Client, tableName string) *DynamoDBRefreshTokenStore {
	return &DynamoDBRefreshTokenStore{
		client:    client,
		tableName: tableName,
	}
}

// Save stores a new refresh token
func (s *DynamoDBRefreshTokenStore) Save(ctx context.Context, tokenID string, data token.RefreshTokenData, expiresAt time.Time) error {
	now := time.Now().UTC()

	// Convert roles to strings for storage
	roleStrings := make([]string, len(data.Roles))
	for i, role := range data.Roles {
		roleStrings[i] = string(role)
	}

	item := RefreshTokenItem{
		PK:        RefreshTokenPrefix + tokenID,
		SK:        RefreshTokenPrefix + tokenID,
		UserEmail: data.UserEmail,
		Picture:   data.Picture,
		Roles:     roleStrings,
		ExpiresAt: expiresAt,
		TTL:       expiresAt.Unix(), // DynamoDB TTL attribute
		CreatedAt: now,
		TokenType: "refresh_token",
	}

	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return fmt.Errorf("failed to marshal refresh token item: %w", err)
	}

	_, err = s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.tableName),
		Item:      av,
	})
	if err != nil {
		return fmt.Errorf("failed to save refresh token: %w", err)
	}

	return nil
}

// Get retrieves the user data associated with a refresh token ID
func (s *DynamoDBRefreshTokenStore) Get(ctx context.Context, tokenID string) (*token.RefreshTokenData, error) {
	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: RefreshTokenPrefix + tokenID},
			"SK": &types.AttributeValueMemberS{Value: RefreshTokenPrefix + tokenID},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get refresh token: %w", err)
	}

	if result.Item == nil {
		return nil, token.ErrTokenNotFound
	}

	var item RefreshTokenItem
	err = attributevalue.UnmarshalMap(result.Item, &item)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal refresh token item: %w", err)
	}

	// Check if token has expired
	if time.Now().UTC().After(item.ExpiresAt) {
		return nil, token.ErrTokenExpired
	}

	// Convert stored role strings back to auth.Role
	roles := make([]auth.Role, len(item.Roles))
	for i, roleStr := range item.Roles {
		roles[i] = auth.Role(roleStr)
	}

	return &token.RefreshTokenData{
		UserEmail: item.UserEmail,
		Picture:   item.Picture,
		Roles:     roles,
	}, nil
}

// Delete removes a refresh token from the store
func (s *DynamoDBRefreshTokenStore) Delete(ctx context.Context, tokenID string) error {
	_, err := s.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: RefreshTokenPrefix + tokenID},
			"SK": &types.AttributeValueMemberS{Value: RefreshTokenPrefix + tokenID},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}

	return nil
}

// Ensure DynamoDBRefreshTokenStore implements token.RefreshTokenStore
var _ token.RefreshTokenStore = (*DynamoDBRefreshTokenStore)(nil)
