package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/International-Combat-Archery-Alliance/auth"
	"github.com/International-Combat-Archery-Alliance/auth/google"
	"github.com/International-Combat-Archery-Alliance/auth/token"
	"github.com/International-Combat-Archery-Alliance/login/api"
	"github.com/International-Combat-Archery-Alliance/login/dynamo"
	"github.com/International-Combat-Archery-Alliance/telemetry"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"go.opentelemetry.io/otel"
)

const (
	dynamoDBTableName      = "login-api"
	jwtSigningKeyEnvVar    = "JWT_SIGNING_KEY"
	jwtSigningKeysSSMPath  = "/jwtSigningKeys"
	adminEmailsEnvVar      = "ADMIN_EMAILS"
	adminEmailsSSMPath     = "/adminEmails"
	newRelicLicenseEnvVar  = "NEW_RELIC_LICENSE_KEY"
	newRelicLicenseSSMPath = "/newrelic-license-key"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	env := getApiEnvironment()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	traceShutdown, flushTraces, err := initTelemetry(ctx, logger)
	if err != nil {
		logger.Error("failed to initialize telemetry", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := traceShutdown(shutdownCtx); err != nil {
			logger.Error("failed to shutdown telemetry", slog.String("error", err.Error()))
		}
	}()

	// Start a root trace span for startup
	tracer := otel.Tracer("github.com/International-Combat-Archery-Alliance/login/cmd")
	ctx, span := tracer.Start(ctx, "startup")

	// Initialize Google token validator (for validating Google OAuth tokens during login)
	var googleTokenValidator auth.Validator
	if err := telemetry.RunWithSpan(ctx, tracer, "init-google-validator", func(ctx context.Context) error {
		var err error
		googleTokenValidator, err = google.NewValidator(ctx)
		return err
	}); err != nil {
		span.RecordError(err)
		logger.Error("error creating google token validator", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// Initialize JWT signing keys
	var signingKeys map[string]token.SigningKey
	var currentKeyID string
	if err := telemetry.RunWithSpan(ctx, tracer, "init-jwt-signing-keys", func(ctx context.Context) error {
		var err error
		signingKeys, currentKeyID, err = getJWTSigningKeys(ctx, env)
		return err
	}); err != nil {
		span.RecordError(err)
		logger.Error("error getting JWT signing keys", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// Initialize token service with all keys for validation and current key for signing
	tokenService := token.NewTokenService(
		signingKeys[currentKeyID],
		token.WithSigningKeys(signingKeys, currentKeyID),
	)

	// Initialize DynamoDB client and refresh token store
	var dynamoClient *dynamodb.Client
	if err := telemetry.RunWithSpan(ctx, tracer, "init-dynamodb-client", func(ctx context.Context) error {
		var err error
		dynamoClient, err = createDynamoClient(ctx, env)
		return err
	}); err != nil {
		span.RecordError(err)
		logger.Error("error creating DynamoDB client", slog.String("error", err.Error()))
		os.Exit(1)
	}
	refreshTokenStore := dynamo.NewDynamoDBRefreshTokenStore(dynamoClient, dynamoDBTableName)

	// Get admin emails
	var adminEmails []string
	if err := telemetry.RunWithSpan(ctx, tracer, "init-admin-emails", func(ctx context.Context) error {
		var err error
		adminEmails, err = getAdminEmails(ctx, env)
		return err
	}); err != nil {
		span.RecordError(err)
		logger.Error("error getting admin emails", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// End startup span after initialization completes
	span.End()

	loginApi := api.NewAPI(api.Config{
		GoogleTokenValidator: googleTokenValidator,
		TokenService:         tokenService,
		RefreshTokenStore:    refreshTokenStore,
		AdminEmails:          adminEmails,
		Logger:               logger,
		Environment:          env,
		FlushTraces:          flushTraces,
	})

	serverSettings := getServerSettingsFromEnv()

	sigCtx, sigStop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer sigStop()

	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- loginApi.ListenAndServe(serverSettings.Host, serverSettings.Port)
	}()

	select {
	case <-sigCtx.Done():
		logger.Info("shutting down gracefully")
	case err := <-serverErrCh:
		logger.Error("error running server", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

type ServerSettings struct {
	Host string
	Port string
}

func getServerSettingsFromEnv() ServerSettings {
	return ServerSettings{
		Host: getEnvOrDefault("HOST", "0.0.0.0"),
		Port: getEnvOrDefault("PORT", "8080"),
	}
}

func getEnvOrDefault(key string, defaultVal string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}

	return defaultVal
}

func isLocal() bool {
	return getEnvOrDefault("AWS_SAM_LOCAL", "false") == "true"
}

func getApiEnvironment() api.Environment {
	if isLocal() {
		return api.LOCAL
	}
	return api.PROD
}

func initTelemetry(ctx context.Context, logger *slog.Logger) (shutdown func(context.Context) error, flush func(context.Context) error, err error) {
	licenseKey, err := getNewRelicLicenseKey(ctx, getApiEnvironment())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get New Relic license key: %w", err)
	}

	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint == "" {
		endpoint = "otlp.nr-data.net:4317"
	}

	return telemetry.Init(ctx, telemetry.Options{
		ServiceName: "login",
		Endpoint:    endpoint,
		APIKey:      licenseKey,
		Lambda:      telemetry.LambdaInfoFromEnv(),
		ErrorHandler: func(err error) {
			logger.Error("otel error", slog.String("error", err.Error()))
		},
	})
}

func createDynamoClient(ctx context.Context, env api.Environment) (*dynamodb.Client, error) {
	if env == api.LOCAL {
		return createLocalDynamoClient(ctx)
	}
	return createProdDynamoClient(ctx)
}

func loadAWSConfig(ctx context.Context, optFns ...func(*config.LoadOptions) error) (aws.Config, error) {
	cfg, err := config.LoadDefaultConfig(ctx, optFns...)
	if err != nil {
		return aws.Config{}, err
	}
	telemetry.InstrumentAWSConfig(&cfg)
	return cfg, nil
}

func createLocalDynamoClient(ctx context.Context) (*dynamodb.Client, error) {
	cfg, err := loadAWSConfig(ctx,
		config.WithRegion("localhost"),
		config.WithCredentialsProvider(credentials.StaticCredentialsProvider{
			Value: aws.Credentials{
				AccessKeyID: "local", SecretAccessKey: "local", SessionToken: "",
				Source: "Mock credentials used above for local instance",
			},
		}),
	)
	if err != nil {
		return nil, err
	}

	return dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
		o.BaseEndpoint = aws.String("http://dynamodb:8000")
	}), nil
}

func createProdDynamoClient(ctx context.Context) (*dynamodb.Client, error) {
	cfg, err := loadAWSConfig(ctx)
	if err != nil {
		return nil, err
	}

	return dynamodb.NewFromConfig(cfg), nil
}

// jwtSigningKeysData represents the JSON structure for signing keys
type jwtSigningKeysData struct {
	CurrentKey string            `json:"currentKey"`
	Keys       map[string]string `json:"keys"`
}

// getJWTSigningKeys retrieves the JWT signing keys from environment variable (local)
// or AWS Parameter Store (production)
// Returns a map of keyID -> SigningKey and the current key ID to use for signing
func getJWTSigningKeys(ctx context.Context, env api.Environment) (map[string]token.SigningKey, string, error) {
	if env == api.LOCAL {
		// Local development: use environment variable
		key := os.Getenv(jwtSigningKeyEnvVar)
		if key == "" {
			// Generate a default key for local development if not set
			// In production, this should always be explicitly set
			key = "local-development-signing-key-minimum-32-characters-long"
		}
		return map[string]token.SigningKey{
			"local": {ID: "local", Key: []byte(key)},
		}, "local", nil
	}

	// Production: retrieve from AWS Parameter Store
	cfg, err := loadAWSConfig(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("unable to load AWS SDK config: %w", err)
	}

	client := ssm.NewFromConfig(cfg)

	result, err := client.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(jwtSigningKeysSSMPath),
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		return nil, "", fmt.Errorf("failed to get JWT signing keys from Parameter Store: %w", err)
	}

	// Parse JSON response
	var data jwtSigningKeysData
	if err := json.Unmarshal([]byte(*result.Parameter.Value), &data); err != nil {
		return nil, "", fmt.Errorf("failed to parse JWT signing keys JSON: %w", err)
	}

	// Convert to map of SigningKey (keys are base64 encoded)
	signingKeys := make(map[string]token.SigningKey)
	for keyID, keyValue := range data.Keys {
		decodedKey, err := base64.StdEncoding.DecodeString(keyValue)
		if err != nil {
			return nil, "", fmt.Errorf("failed to decode base64 key %q: %w", keyID, err)
		}
		signingKeys[keyID] = token.SigningKey{
			ID:  keyID,
			Key: decodedKey,
		}
	}

	// Validate that current key exists
	if _, ok := signingKeys[data.CurrentKey]; !ok {
		return nil, "", fmt.Errorf("current key ID %q not found in keys", data.CurrentKey)
	}

	return signingKeys, data.CurrentKey, nil
}

// getAdminEmails retrieves the list of admin emails from environment variable (local)
// or AWS Parameter Store (production)
func getAdminEmails(ctx context.Context, env api.Environment) ([]string, error) {
	if env == api.LOCAL {
		// Local development: use environment variable
		emailsStr := os.Getenv(adminEmailsEnvVar)
		if emailsStr == "" {
			return nil, nil
		}
		return parseEmailList(emailsStr), nil
	}

	// Production: retrieve from AWS Parameter Store
	cfg, err := loadAWSConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to load AWS SDK config: %w", err)
	}

	client := ssm.NewFromConfig(cfg)

	result, err := client.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(adminEmailsSSMPath),
		WithDecryption: aws.Bool(false), // Admin emails don't need encryption
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get admin emails from Parameter Store: %w", err)
	}

	return parseEmailList(*result.Parameter.Value), nil
}

// getNewRelicLicenseKey retrieves the New Relic license key from environment variable (local)
// or AWS Parameter Store (production)
func getNewRelicLicenseKey(ctx context.Context, env api.Environment) (string, error) {
	if env == api.LOCAL {
		return os.Getenv(newRelicLicenseEnvVar), nil
	}

	cfg, err := loadAWSConfig(ctx)
	if err != nil {
		return "", fmt.Errorf("unable to load AWS SDK config: %w", err)
	}

	client := ssm.NewFromConfig(cfg)

	result, err := client.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(newRelicLicenseSSMPath),
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		return "", fmt.Errorf("failed to get New Relic license key from Parameter Store: %w", err)
	}

	return *result.Parameter.Value, nil
}

// parseEmailList parses a comma-separated list of emails
func parseEmailList(emailsStr string) []string {
	parts := strings.Split(emailsStr, ",")
	var emails []string
	for _, email := range parts {
		email = strings.TrimSpace(email)
		if email != "" {
			emails = append(emails, email)
		}
	}
	return emails
}
