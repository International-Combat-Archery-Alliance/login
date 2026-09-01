package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/International-Combat-Archery-Alliance/auth/token"
	"github.com/International-Combat-Archery-Alliance/login/dynamo"
	"github.com/International-Combat-Archery-Alliance/middleware"
	"golang.org/x/crypto/bcrypt"
)

const (
	// m2mBcryptCost is the documented bcrypt cost for client-secret hashes
	// (ADR-0006: 10-12) so the CPU budget per attempt is known.
	m2mBcryptCost = 10
	// maxM2MSecretLen bounds the clientSecret before any crypto work (bcrypt
	// only uses 72 bytes; capping avoids oversized-parse cost).
	maxM2MSecretLen = 1024
	// maxM2MBasicHeaderLen bounds the Authorization header we are willing to
	// decode.
	maxM2MBasicHeaderLen = 4096

	// JWKS cache headers (ADR-0006/0007): edge-cacheable for 5 minutes,
	// stale-while-revalidate 1 hour. The SSM floor, not this header, is the
	// availability mechanism.
	jwksCacheControl = "public, max-age=300, stale-while-revalidate=3600"
)

// M2MStore provides machine-credential lookup (CLIENT#) and the m2m
// fixed-window limiter + lockout (RATE#), ADR-0006 hardening.
type M2MStore interface {
	GetClient(ctx context.Context, clientID string) (*dynamo.MachineClientItem, error)
	BumpWindow(ctx context.Context, clientID string, now time.Time) (*dynamo.RateWindow, error)
	RecordFailure(ctx context.Context, clientID string, now time.Time) error
	ResetFailures(ctx context.Context, clientID string, now time.Time) error
	WindowLimit() int64
}

// PostLoginV1M2mTokens is the client-credentials exchange (ADR-0006).
//
// Flow (per the m2m endpoint hardening section):
//  1. DDB RATE# fixed-window + lockout — BEFORE bcrypt, so failed attempts
//     never burn Lambda CPU.
//  2. bcrypt verify of the client secret (constant-time), with a dummy
//     compare so unknown clientIds are not a timing oracle.
//  3. On success a 5-minute RS256 machine JWT is minted with the client's
//     allowed audience + exact scope.
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

	// Layer 2 (ADR-0006): DDB RATE# fixed-window limiter + lockout.
	window, err := a.m2mStore.BumpWindow(ctx, clientID, now)
	if err != nil {
		span.RecordError(err)
		logger.Error("m2m rate window bump failed", slog.String("error", err.Error()))
		return PostLoginV1M2mTokens500JSONResponse{
			Message: "internal error",
			Code:    InternalError,
		}, nil
	}

	// Lockout: any request while locked -> 429. Logs the alarm marker.
	if window.LockedUntil != nil && window.LockedUntil.After(now) {
		logger.Warn("m2m lockout", slog.String("clientId", clientID), slog.Time("lockedUntil", *window.LockedUntil))
		return PostLoginV1M2mTokens429JSONResponse{
			Message: "Too many failed attempts; try again later",
			Code:    RateLimited,
		}, nil
	}

	if window.WindowCount > a.m2mStore.WindowLimit() {
		return PostLoginV1M2mTokens429JSONResponse{
			Message: "Rate limit exceeded",
			Code:    RateLimited,
		}, nil
	}

	// Client verification: bcrypt + constant-time compare. Unknown/inactive
	// clients short-circuit with a dummy compare so clientId existence is not
	// a timing oracle (ADR-0006 appendix).
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
		// Equalize timing with the unknown-client path.
		_ = bcrypt.CompareHashAndPassword(a.dummyClientSecretHash, []byte(clientSecret))
		a.recordM2MFailure(ctx, clientID, now, logger)
		return PostLoginV1M2mTokens401JSONResponse{
			Message: "invalid client credentials",
			Code:    AuthError,
		}, nil
	}

	// Constant-time compare against any active round (rotation grace window).
	valid := false
	for _, round := range client.SecretRounds {
		if bcrypt.CompareHashAndPassword([]byte(round), []byte(clientSecret)) == nil {
			valid = true
			break
		}
	}
	if !valid {
		a.recordM2MFailure(ctx, clientID, now, logger)
		return PostLoginV1M2mTokens401JSONResponse{
			Message: "invalid client credentials",
			Code:    AuthError,
		}, nil
	}

	// Success clears failures + any lockout.
	if err := a.m2mStore.ResetFailures(ctx, clientID, now); err != nil {
		span.RecordError(err)
		logger.Error("failed to reset m2m failures", slog.String("clientId", clientID), slog.String("error", err.Error()))
		return PostLoginV1M2mTokens500JSONResponse{
			Message: "internal error",
			Code:    InternalError,
		}, nil
	}

	// Mint the machine token with the client's allowed audience + exact scope.
	signed, err := a.machineTokenSigner.Sign(clientID, client.Audience, client.Scopes)
	if err != nil {
		span.RecordError(err)
		logger.Error("failed to sign machine token", slog.String("clientId", clientID), slog.String("error", err.Error()))
		return PostLoginV1M2mTokens500JSONResponse{
			Message: "internal error",
			Code:    InternalError,
		}, nil
	}

	logger.Info("m2m token issued", slog.String("clientId", clientID))
	return PostLoginV1M2mTokens200JSONResponse{
		AccessToken: signed,
		TokenType:   "Bearer",
		ExpiresIn:   int(token.DefaultMachineTokenLifetime.Seconds()),
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
// Authorization header.
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
	if !found || clientID == "" || clientSecret == "" {
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
