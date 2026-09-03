package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/International-Combat-Archery-Alliance/login/dynamo"
	"github.com/International-Combat-Archery-Alliance/middleware"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/crypto/bcrypt"
)

const (
	// m2mBcryptCost is the bcrypt cost for client-secret hashes so the CPU
	// budget per attempt is known. Provisioned rounds must also use cost 10:
	// the unknown-client dummy compare below runs at this cost, so a cost-12
	// round would make known vs unknown clientIds timing-distinguishable.
	m2mBcryptCost = 10
	// maxM2MSecretLen bounds the clientSecret before any crypto work (bcrypt
	// only uses 72 bytes; capping avoids oversized-parse cost).
	maxM2MSecretLen = 1024
	// maxM2MClientIDLen bounds clientId: DynamoDB partition keys top out at
	// 2048 bytes, and clientIds are short identifiers by construction. A value
	// beyond the cap is rejected before any DDB access.
	maxM2MClientIDLen = 64
	// maxM2MBasicHeaderLen bounds the Authorization header we are willing to
	// decode.
	maxM2MBasicHeaderLen = 4096

	// JWKS cache headers: edge-cacheable for 5 minutes, stale-while-revalidate
	// 1 hour.
	jwksCacheControl = "public, max-age=300, stale-while-revalidate=3600"
)

// M2MStore provides machine-credential lookup plus the fixed-window limiter
// and lockout used by the m2m token exchange.
type M2MStore interface {
	GetClient(ctx context.Context, clientID string) (*dynamo.MachineClientItem, error)
	BumpWindow(ctx context.Context, clientID string, now time.Time) (*dynamo.RateWindow, error)
	RecordFailure(ctx context.Context, clientID string, now time.Time) error
	ResetFailures(ctx context.Context, clientID string, now time.Time) error
	WindowLimit() int64
}

// PostLoginV1M2mTokens is the client-credentials exchange.
//
// Flow:
//  1. Existence first: unknown/inactive clients get a dummy bcrypt + 401 with
//     no RATE# writes (no table fill, no lockout state for fakes). Aggregate
//     CPU abuse of fakes is covered by the Cloudflare per-IP rule (INT-8).
//  2. Known clients: fixed-window limiter + lockout, then bcrypt. Lockout has
//     a valid-secret bypass (throttled by the same window) so an attacker who
//     knows the clientId cannot starve the real service.
//  3. On success a machine JWT is minted with the client's allowed audience +
//     exact scope; ResetFailures is non-fatal.
func (a *API) PostLoginV1M2mTokens(ctx context.Context, request PostLoginV1M2mTokensRequestObject) (PostLoginV1M2mTokensResponseObject, error) {
	ctx, span := a.tracer.Start(ctx, "PostLoginV1M2mTokens")
	defer span.End()

	logger, ok := middleware.GetLoggerFromCtx(ctx)
	if !ok {
		logger = a.logger
	}

	var authHeader string
	if request.Params.Authorization != "" {
		authHeader = request.Params.Authorization
	}

	clientID, clientSecret, ok := parseBasicAuth(authHeader)
	if !ok || len(clientSecret) > maxM2MSecretLen {
		return PostLoginV1M2mTokens400JSONResponse{
			Message: "missing or malformed Basic credentials",
			Code:    InputValidationError,
		}, nil
	}

	now := time.Now()

	// Existence first so fake IDs never create RATE# items. Dummy compare
	// preserves timing so existence is not an oracle.
	client, err := a.m2mStore.GetClient(ctx, clientID)
	if err != nil {
		span.RecordError(err)
		logger.Error("failed to get machine client", slog.String("clientId", clientID), slog.String("error", err.Error()))
		return PostLoginV1M2mTokens500JSONResponse{
			Message: "internal error",
			Code:    InternalError,
		}, nil
	}

	if client == nil || len(client.SecretRounds) == 0 || !client.Active {
		_ = bcrypt.CompareHashAndPassword(a.dummyClientSecretHash, []byte(clientSecret))
		logger.Warn("m2m invalid_client", slog.String("clientId", clientID))
		return PostLoginV1M2mTokens401JSONResponse{
			Message: "invalid client credentials",
			Code:    AuthError,
		}, nil
	}

	// Known client: fixed-window limiter, before bcrypt (caps bcrypt CPU).
	window, err := a.m2mStore.BumpWindow(ctx, clientID, now)
	if err != nil {
		span.RecordError(err)
		logger.Error("m2m rate window bump failed", slog.String("error", err.Error()))
		return PostLoginV1M2mTokens500JSONResponse{
			Message: "internal error",
			Code:    InternalError,
		}, nil
	}

	if window.WindowCount > a.m2mStore.WindowLimit() {
		return PostLoginV1M2mTokens429JSONResponse{
			Message: "Rate limit exceeded",
			Code:    RateLimited,
		}, nil
	}

	// Lockout with valid-secret bypass: a prover of the secret always gets
	// through (and clears), throttled by the same window above (max 30
	// bcrypt/min/ID). Invalid while locked stays 429 with no RecordFailure
	// so the lock is not sticky under spam.
	if window.LockedUntil != nil && window.LockedUntil.After(now) {
		if verifyM2MSecret(client.SecretRounds, clientSecret) {
			return a.issueM2MToken(ctx, span, clientID, client, now, logger)
		}
		logger.Warn("m2m lockout", slog.String("clientId", clientID), slog.Time("lockedUntil", *window.LockedUntil))
		return PostLoginV1M2mTokens429JSONResponse{
			Message: "Too many failed attempts; try again later",
			Code:    RateLimited,
		}, nil
	}

	// Constant-time compare against any active round (rotation grace window).
	if !verifyM2MSecret(client.SecretRounds, clientSecret) {
		a.recordM2MFailure(ctx, clientID, now, logger)
		return PostLoginV1M2mTokens401JSONResponse{
			Message: "invalid client credentials",
			Code:    AuthError,
		}, nil
	}

	return a.issueM2MToken(ctx, span, clientID, client, now, logger)
}

// verifyM2MSecret compares against any active round (rotation grace).
func verifyM2MSecret(rounds []string, secret string) bool {
	for _, round := range rounds {
		if bcrypt.CompareHashAndPassword([]byte(round), []byte(secret)) == nil {
			return true
		}
	}
	return false
}

func (a *API) issueM2MToken(ctx context.Context, span trace.Span, clientID string, client *dynamo.MachineClientItem, now time.Time, logger *slog.Logger) (PostLoginV1M2mTokensResponseObject, error) {
	// Mint first so a transient DDB failure on the non-security clear cannot
	// 500 a valid credential.
	signed, err := a.machineTokenSigner.Sign(clientID, client.Audience, client.Scopes)
	if err != nil {
		span.RecordError(err)
		logger.Error("failed to sign machine token", slog.String("clientId", clientID), slog.String("error", err.Error()))
		return PostLoginV1M2mTokens500JSONResponse{
			Message: "internal error",
			Code:    InternalError,
		}, nil
	}

	// Non-fatal clear: token already valid, next success retries.
	if err := a.m2mStore.ResetFailures(ctx, clientID, now); err != nil {
		span.RecordError(err)
		logger.Error("failed to reset m2m failures", slog.String("clientId", clientID), slog.String("error", err.Error()))
	}

	logger.Info("m2m token issued", slog.String("clientId", clientID))
	return PostLoginV1M2mTokens200JSONResponse{
		AccessToken: signed,
		TokenType:   "Bearer",
		ExpiresIn:   int(a.machineTokenLifetime.Seconds()),
	}, nil
}

// recordM2MFailure counts the failed attempt and emits the "m2m invalid_client"
// marker that the CloudWatch metric filter + alarm watch for.
func (a *API) recordM2MFailure(ctx context.Context, clientID string, now time.Time, logger *slog.Logger) {
	if err := a.m2mStore.RecordFailure(ctx, clientID, now); err != nil {
		logger.Error("failed to record m2m failure", slog.String("clientId", clientID), slog.String("error", err.Error()))
	}
	logger.Warn("m2m invalid_client", slog.String("clientId", clientID))
}

// parseBasicAuth extracts clientId:clientSecret from an HTTP Basic
// Authorization header. clientIds longer than maxM2MClientIDLen are rejected
// up front so an attacker-controlled clientId can never reach DynamoDB
// (partition keys > 2048 bytes fail with a ValidationException → 500).
func parseBasicAuth(header string) (clientID string, clientSecret string, ok bool) {
	if header == "" || len(header) > maxM2MBasicHeaderLen || !strings.HasPrefix(header, "Basic ") {
		return "", "", false
	}

	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(header, "Basic "))
	if err != nil {
		return "", "", false
	}

	val := string(raw)
	if len(val) > maxM2MBasicHeaderLen {
		return "", "", false
	}

	clientID, clientSecret, found := strings.Cut(val, ":")
	if !found || clientID == "" || clientSecret == "" || len(clientID) > maxM2MClientIDLen {
		return "", "", false
	}
	return clientID, clientSecret, true
}

// makeDummyClientSecretHash precomputes a bcrypt hash of random bytes used to
// equalize the unknown-client timing path. The hash input is irrelevant; only
// the compare cost matters.
func makeDummyClientSecretHash() []byte {
	randomSecret := make([]byte, 32)
	if _, err := rand.Read(randomSecret); err != nil {
		panic(fmt.Sprintf("failed to read random bytes for dummy client hash: %v", err))
	}
	hash, err := bcrypt.GenerateFromPassword(randomSecret, m2mBcryptCost)
	if err != nil {
		panic(fmt.Sprintf("failed to precompute dummy client hash: %v", err))
	}
	return hash
}
