package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/International-Combat-Archery-Alliance/auth/token"
	"github.com/International-Combat-Archery-Alliance/login/api"
	"github.com/International-Combat-Archery-Alliance/telemetry"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"go.opentelemetry.io/otel/codes"
)

const (
	newRelicLicenseEnvVar  = "NEW_RELIC_LICENSE_KEY"
	newRelicLicenseSSMPath = "/newrelic-license-key"
)

var (
	awsCfg     aws.Config
	awsCfgErr  error
	awsCfgOnce sync.Once
)

func loadAWSConfig(ctx context.Context) (aws.Config, error) {
	awsCfgOnce.Do(func() {
		ctx, span := tracer.Start(ctx, "load-aws-config")
		defer span.End()

		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			awsCfgErr = fmt.Errorf("unable to load AWS SDK config: %w", err)
			return
		}
		telemetry.InstrumentAWSConfig(&cfg)
		awsCfg = cfg
	})
	return awsCfg, awsCfgErr
}

func getSSMParameter(ctx context.Context, name string) (string, error) {
	cfg, err := loadAWSConfig(ctx)
	if err != nil {
		return "", err
	}

	client := ssm.NewFromConfig(cfg)
	result, err := client.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(name),
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		return "", fmt.Errorf("failed to get parameter %q: %w", name, err)
	}

	return aws.ToString(result.Parameter.Value), nil
}

func getSSMParameters(ctx context.Context, names []string) (map[string]string, error) {
	if len(names) == 0 {
		return nil, nil
	}

	cfg, err := loadAWSConfig(ctx)
	if err != nil {
		return nil, err
	}

	client := ssm.NewFromConfig(cfg)
	result, err := client.GetParameters(ctx, &ssm.GetParametersInput{
		Names:          names,
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get parameters %v: %w", names, err)
	}

	if len(result.InvalidParameters) > 0 {
		return nil, fmt.Errorf("invalid parameters: %v", result.InvalidParameters)
	}

	params := make(map[string]string, len(result.Parameters))
	for _, p := range result.Parameters {
		params[aws.ToString(p.Name)] = aws.ToString(p.Value)
	}

	return params, nil
}

type AppConfig struct {
	JWTSigningKeys  map[string]token.SigningKey
	JWTCurrentKeyID string
	AdminEmails     []string
}

func fetchAppConfig(ctx context.Context, env api.Environment) (*AppConfig, error) {
	if env == api.LOCAL {
		return localAppConfig()
	}
	return fetchProdAppConfig(ctx)
}

func localAppConfig() (*AppConfig, error) {
	key := os.Getenv("JWT_SIGNING_KEY")
	if key == "" {
		key = "local-development-signing-key-minimum-32-characters-long"
	}

	emailsStr := os.Getenv("ADMIN_EMAILS")

	return &AppConfig{
		JWTSigningKeys: map[string]token.SigningKey{
			"local": {ID: "local", Key: []byte(key)},
		},
		JWTCurrentKeyID: "local",
		AdminEmails:     parseEmailList(emailsStr),
	}, nil
}

func fetchProdAppConfig(ctx context.Context) (*AppConfig, error) {
	ssmNames := []string{
		"/jwtSigningKeys",
		"/adminEmails",
	}

	params, err := getSSMParameters(ctx, ssmNames)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch app config from SSM: %w", err)
	}

	cfg := &AppConfig{}

	if v, ok := params["/jwtSigningKeys"]; ok {
		signingKeys, currentKeyID, err := parseJWTSigningKeysJSON(v)
		if err != nil {
			return nil, fmt.Errorf("failed to parse JWT signing keys: %w", err)
		}
		cfg.JWTSigningKeys = signingKeys
		cfg.JWTCurrentKeyID = currentKeyID
	} else {
		return nil, fmt.Errorf("missing SSM parameter: /jwtSigningKeys")
	}

	if v, ok := params["/adminEmails"]; ok {
		cfg.AdminEmails = parseEmailList(v)
	}

	return cfg, nil
}

type jwtSigningKeysData struct {
	CurrentKey string            `json:"currentKey"`
	Keys       map[string]string `json:"keys"`
}

func parseJWTSigningKeysJSON(raw string) (map[string]token.SigningKey, string, error) {
	var data jwtSigningKeysData
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		return nil, "", fmt.Errorf("failed to parse JWT signing keys JSON: %w", err)
	}

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

	if _, ok := signingKeys[data.CurrentKey]; !ok {
		return nil, "", fmt.Errorf("current key ID %q not found in keys", data.CurrentKey)
	}

	return signingKeys, data.CurrentKey, nil
}

func getNewRelicLicenseKey(ctx context.Context, env api.Environment) (string, error) {
	if env == api.LOCAL {
		return os.Getenv(newRelicLicenseEnvVar), nil
	}
	return getSSMParameter(ctx, newRelicLicenseSSMPath)
}

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

func getApiEnvironment() api.Environment {
	if isLocal() {
		return api.LOCAL
	}
	return api.PROD
}

func isLocal() bool {
	return getEnvOrDefault("AWS_SAM_LOCAL", "false") == "true"
}

func getEnvOrDefault(key, defaultVal string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return defaultVal
}
