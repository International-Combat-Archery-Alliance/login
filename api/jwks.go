package api

import (
	"context"
	"log/slog"

	"github.com/International-Combat-Archery-Alliance/middleware"
)

// JWKSProvider serves the public key set used to verify ICAA JWTs. login
// derives it once at startup from the same signing keys the signer uses.
type JWKSProvider interface {
	PublicJWKS(ctx context.Context) (JWKS, error)
}

// GetLoginWellKnownJwksJson serves GET /login/.well-known/jwks.json
// (security: []) with long-lived cache headers.
func (a *API) GetLoginWellKnownJwksJson(ctx context.Context, request GetLoginWellKnownJwksJsonRequestObject) (GetLoginWellKnownJwksJsonResponseObject, error) {
	ctx, span := a.tracer.Start(ctx, "GetLoginWellKnownJwksJson")
	defer span.End()

	logger, ok := middleware.GetLoggerFromCtx(ctx)
	if !ok {
		logger = a.logger
	}

	jwks, err := a.jwksProvider.PublicJWKS(ctx)
	if err != nil {
		span.RecordError(err)
		logger.Error("failed to load jwks", slog.String("error", err.Error()))
		return GetLoginWellKnownJwksJson500JSONResponse{
			Message: "failed to load signing keys",
			Code:    InternalError,
		}, nil
	}

	return GetLoginWellKnownJwksJson200JSONResponse{
		Body: jwks,
		Headers: GetLoginWellKnownJwksJson200ResponseHeaders{
			CacheControl: jwksCacheControl,
		},
	}, nil
}
