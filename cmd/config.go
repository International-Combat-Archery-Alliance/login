package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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
	// UserSigningKeys holds the RS256 user-token private keys (login-only).
	// SSM shape reuses the machine format:
	// {"currentKey": "<kid>", "keys": {"<kid>": "<PEM PKCS#8 RSA private key>"}}.
	// Kids must use the user-* namespace.
	UserSigningKeys     map[string]*rsa.PrivateKey
	UserCurrentKeyID    string
	MachineSigningKeys  map[string]*rsa.PrivateKey
	MachineCurrentKeyID string
	AdminEmails         []string
}

func fetchAppConfig(ctx context.Context, env api.Environment) (*AppConfig, error) {
	if env == api.LOCAL {
		return localAppConfig()
	}
	return fetchProdAppConfig(ctx)
}

func localAppConfig() (*AppConfig, error) {
	emailsStr := os.Getenv("ADMIN_EMAILS")

	// LOCAL dev keypairs (user + machine): generated ephemeral, explicit
	// LOCAL env flag (AWS_SAM_LOCAL), never inferred from hostname.
	userPriv, _, err := token.GenerateUserDevKeypair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate local user dev keypair: %w", err)
	}
	machinePriv, _, err := token.GenerateMachineDevKeypair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate local machine dev keypair: %w", err)
	}

	return &AppConfig{
		UserSigningKeys:     map[string]*rsa.PrivateKey{"user-local": userPriv},
		UserCurrentKeyID:    "user-local",
		MachineSigningKeys:  map[string]*rsa.PrivateKey{"machine-local": machinePriv},
		MachineCurrentKeyID: "machine-local",
		AdminEmails:         parseEmailList(emailsStr),
	}, nil
}

func fetchProdAppConfig(ctx context.Context) (*AppConfig, error) {
	ssmNames := []string{
		"/userJwtSigningKeys",
		"/machineJwtSigningKeys",
		"/adminEmails",
	}

	params, err := getSSMParameters(ctx, ssmNames)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch app config from SSM: %w", err)
	}

	cfg := &AppConfig{}

	if v, ok := params["/userJwtSigningKeys"]; ok {
		userKeys, currentKeyID, err := parseRSAJWTSigningKeysJSON(v)
		if err != nil {
			return nil, fmt.Errorf("failed to parse user JWT signing keys: %w", err)
		}
		cfg.UserSigningKeys = userKeys
		cfg.UserCurrentKeyID = currentKeyID
	} else {
		return nil, fmt.Errorf("missing SSM parameter: /userJwtSigningKeys")
	}

	if v, ok := params["/machineJwtSigningKeys"]; ok {
		machineKeys, currentKeyID, err := parseRSAJWTSigningKeysJSON(v)
		if err != nil {
			return nil, fmt.Errorf("failed to parse machine JWT signing keys: %w", err)
		}
		cfg.MachineSigningKeys = machineKeys
		cfg.MachineCurrentKeyID = currentKeyID
	} else {
		return nil, fmt.Errorf("missing SSM parameter: /machineJwtSigningKeys")
	}

	if v, ok := params["/adminEmails"]; ok {
		cfg.AdminEmails = parseEmailList(v)
	}

	return cfg, nil
}

type rsaJWTKeysData struct {
	CurrentKey string            `json:"currentKey"`
	Keys       map[string]string `json:"keys"`
}

// parseRSAJWTSigningKeysJSON parses a keypair parameter of the form
// {"currentKey": "<kid>", "keys": {"<kid>": "<PEM PKCS#8 RSA private key>"}}.
func parseRSAJWTSigningKeysJSON(raw string) (map[string]*rsa.PrivateKey, string, error) {
	var data rsaJWTKeysData
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		return nil, "", fmt.Errorf("failed to parse RSA JWT signing keys JSON: %w", err)
	}

	keys := make(map[string]*rsa.PrivateKey, len(data.Keys))
	for kid, keyPEM := range data.Keys {
		priv, err := parseRSAPrivateKeyPEM(keyPEM)
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse private key %q: %w", kid, err)
		}
		keys[kid] = priv
	}

	if _, ok := keys[data.CurrentKey]; !ok {
		return nil, "", fmt.Errorf("current key ID %q not found in keys", data.CurrentKey)
	}

	return keys, data.CurrentKey, nil
}

func parseRSAPrivateKeyPEM(keyPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		priv, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not an RSA private key")
		}
		return priv, nil
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("unrecognized private key format")
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

func getApiEnvironment() (api.Environment, error) {
	if isLocal() {
		// Fail closed: LOCAL mode installs ephemeral dev keys (machine keypair
		// + static dev JWKS). AWS_SAM_LOCAL is set by `sam local`, never by
		// the Lambda runtime, so this combination can only be a prod
		// misconfig — refuse to boot with dev key material instead.
		if insideLambdaRuntime() {
			return 0, fmt.Errorf("AWS_SAM_LOCAL=true but running in an AWS Lambda runtime; refusing LOCAL mode")
		}
		return api.LOCAL, nil
	}
	return api.PROD, nil
}

// insideLambdaRuntime reports whether the process is running in a real Lambda
// execution environment (neither is set under `sam local start-api`).
func insideLambdaRuntime() bool {
	return os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != "" || os.Getenv("AWS_EXECUTION_ENVIRONMENT") != ""
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
