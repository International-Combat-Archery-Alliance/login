package main

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"github.com/International-Combat-Archery-Alliance/login/api"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// ssmJWKSProvider serves the public JWKS by deriving it from login's own
// signing-key SSM parameters (/machineJwtSigningKeys, and /userJwtSigningKeys
// once ADR-0007 lands). Rotation is a manual SSM write, so the provider
// re-reads with a short TTL and keeps last-known-good on failure — the JWKS
// endpoint can never serve a half-rotated or stale-empty key set.
type ssmJWKSProvider struct {
	ssm      *ssm.Client
	params   []string
	ttl      time.Duration
	logger   *slog.Logger
	mu       sync.Mutex
	cached   api.JWKS
	cachedAt time.Time
}

// newSSMJWKSProvider builds the provider. /userJwtSigningKeys is included
// once it exists; a missing parameter yields an empty key set, not an error
// (ADR-0007 services the user-* namespace on the same endpoint).
func newSSMJWKSProvider(ctx context.Context, logger *slog.Logger) (*ssmJWKSProvider, error) {
	cfg, err := loadAWSConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	return &ssmJWKSProvider{
		ssm:    ssm.NewFromConfig(cfg),
		params: []string{"/machineJwtSigningKeys", "/userJwtSigningKeys"},
		ttl:    60 * time.Second,
		logger: logger,
	}, nil
}

// PublicJWKS returns the current key set, re-reading SSM when the TTL has
// expired. On a read/parse failure it returns the last-known-good set; only a
// failure with nothing cached surfaces as an error.
func (p *ssmJWKSProvider) PublicJWKS(ctx context.Context) (api.JWKS, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.cachedAt.IsZero() && time.Since(p.cachedAt) < p.ttl {
		return p.cached, nil
	}

	result, err := p.ssm.GetParameters(ctx, &ssm.GetParametersInput{
		Names:          p.params,
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		if !p.cachedAt.IsZero() {
			p.logger.Warn("jwks ssm read failed; serving last-known-good", slog.String("error", err.Error()))
			return p.cached, nil
		}
		return api.JWKS{}, fmt.Errorf("failed to read signing key parameters: %w", err)
	}

	invalid := make(map[string]bool, len(result.InvalidParameters))
	for _, name := range result.InvalidParameters {
		invalid[name] = true
	}

	jwks := api.JWKS{Keys: []api.JWK{}}
	// Order is deterministic: machine keys first, then user keys.
	for _, paramName := range p.params {
		if invalid[paramName] {
			// Not provisioned yet (e.g. /userJwtSigningKeys before ADR-0007).
			continue
		}
		raw := ""
		for _, param := range result.Parameters {
			if aws.ToString(param.Name) == paramName {
				raw = aws.ToString(param.Value)
				break
			}
		}
		if raw == "" {
			if !p.cachedAt.IsZero() {
				return p.cached, nil
			}
			return api.JWKS{}, fmt.Errorf("missing signing key parameter %q", paramName)
		}

		keys, _, err := parseRSAJWTSigningKeysJSON(raw)
		if err != nil {
			if !p.cachedAt.IsZero() {
				p.logger.Warn("jwks parse failed; serving last-known-good", slog.String("param", paramName), slog.String("error", err.Error()))
				return p.cached, nil
			}
			return api.JWKS{}, fmt.Errorf("failed to parse %q: %w", paramName, err)
		}

		for kid, priv := range keys {
			jwks.Keys = append(jwks.Keys, rsaPublicJWK(kid, priv))
		}
	}

	p.cached = jwks
	p.cachedAt = time.Now()
	return jwks, nil
}

// staticJWKSProvider serves a fixed key set (LOCAL dev mode).
type staticJWKSProvider struct {
	jwks api.JWKS
}

func (s staticJWKSProvider) PublicJWKS(context.Context) (api.JWKS, error) {
	return s.jwks, nil
}

// keypairJWKS builds a JWKS from a private-key set.
func keypairJWKS(keys map[string]*rsa.PrivateKey) api.JWKS {
	jwks := api.JWKS{Keys: []api.JWK{}}
	for kid, priv := range keys {
		jwks.Keys = append(jwks.Keys, rsaPublicJWK(kid, priv))
	}
	return jwks
}

// rsaPublicJWK converts an RSA private key's public half into the JWK shape
// served by the JWKS endpoint and mirrored to /jwtPublicKeys SSM (same format,
// same rotation step).
func rsaPublicJWK(kid string, priv *rsa.PrivateKey) api.JWK {
	use := "sig"
	alg := "RS256"
	kty := "RSA"
	return api.JWK{
		Kty: api.JWKKty(kty),
		Kid: kid,
		Use: (*api.JWKUse)(&use),
		Alg: (*api.JWKAlg)(&alg),
		N:   base64.RawURLEncoding.EncodeToString(priv.PublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.PublicKey.E)).Bytes()),
	}
}
