package api

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"strings"

	"github.com/International-Combat-Archery-Alliance/login/m2m"
	"github.com/International-Combat-Archery-Alliance/middleware"
)

const (
	// maxM2MSecretLen bounds the clientSecret before any crypto work (bcrypt
	// only uses 72 bytes; capping avoids oversized-parse cost).
	maxM2MSecretLen = 1024
	// maxM2MClientIDLen bounds clientId: DynamoDB partition keys top out at
	// 2048 bytes, and clientIds are short identifiers by construction. A value
	// beyond the cap is rejected before any store access.
	maxM2MClientIDLen = 64
	// maxM2MBasicHeaderLen bounds the Authorization header we are willing to
	// decode.
	maxM2MBasicHeaderLen = 4096

	// JWKS cache headers: edge-cacheable for 5 minutes, stale-while-revalidate
	// 1 hour.
	jwksCacheControl = "public, max-age=300, stale-while-revalidate=3600"
)

// PostLoginV1M2mTokens is the client-credentials exchange adapter. Transport
// only: parses Basic auth, delegates to the core service, maps verdicts to
// HTTP responses.
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

	signed, err := a.m2mService.Exchange(ctx, clientID, clientSecret, logger)
	if err == nil {
		return PostLoginV1M2mTokens200JSONResponse{
			AccessToken: signed,
			TokenType:   "Bearer",
			ExpiresIn:   int(a.m2mService.Lifetime().Seconds()),
		}, nil
	}

	switch {
	case errors.Is(err, m2m.ErrInvalidCredentials):
		return PostLoginV1M2mTokens401JSONResponse{
			Message: "invalid client credentials",
			Code:    AuthError,
		}, nil
	case errors.Is(err, m2m.ErrLockedOut):
		return PostLoginV1M2mTokens429JSONResponse{
			Message: "Too many failed attempts; try again later",
			Code:    RateLimited,
		}, nil
	case errors.Is(err, m2m.ErrRateLimited):
		return PostLoginV1M2mTokens429JSONResponse{
			Message: "Rate limit exceeded",
			Code:    RateLimited,
		}, nil
	default:
		span.RecordError(err)
		logger.Error("m2m exchange failed", slog.String("error", err.Error()))
		return PostLoginV1M2mTokens500JSONResponse{
			Message: "internal error",
			Code:    InternalError,
		}, nil
	}
}

// parseBasicAuth extracts clientId:clientSecret from an HTTP Basic
// Authorization header. clientIds longer than maxM2MClientIDLen are rejected
// up front so an attacker-controlled clientId can never reach the store
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
