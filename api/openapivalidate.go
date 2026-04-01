package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/International-Combat-Archery-Alliance/auth"
	"github.com/International-Combat-Archery-Alliance/auth/token"
	"github.com/International-Combat-Archery-Alliance/middleware"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	nethttpMiddleware "github.com/oapi-codegen/nethttp-middleware"
)

var scopeValidators map[string]func(token auth.AuthToken) error = map[string]func(token auth.AuthToken) error{
	"admin": func(token auth.AuthToken) error {
		if !slices.Contains(token.Roles(), auth.RoleAdmin) {
			return fmt.Errorf("user is not an admin")
		}
		return nil
	},
}

func validateScopes(tok auth.AuthToken, scopes []string) error {
	for _, scope := range scopes {
		validator, ok := scopeValidators[scope]
		if !ok {
			return fmt.Errorf("unknown scope: %q", scope)
		}

		err := validator(tok)
		if err != nil {
			return fmt.Errorf("user does not have scope %q", scope)
		}
	}

	return nil
}

func (a *API) openapiValidateMiddleware(swagger *openapi3.T) middleware.MiddlewareFunc {
	return nethttpMiddleware.OapiRequestValidatorWithOptions(swagger, &nethttpMiddleware.Options{
		Options: openapi3filter.Options{
			AuthenticationFunc: func(ctx context.Context, ai *openapi3filter.AuthenticationInput) error {
				logger, ok := middleware.GetLoggerFromCtx(ctx)
				if !ok {
					logger = slog.Default()
				}

				switch ai.SecuritySchemeName {
				case "icaaCookieAuth":
					return a.validateAccessTokenCookie(ctx, ai, logger)
				case "icaaBearerAuth":
					return a.validateAccessTokenBearer(ctx, ai, logger)
				case "icaaRefreshCookieAuth":
					return a.validateRefreshTokenCookie(ctx, ai, logger)
				default:
					return fmt.Errorf("unsupported security scheme: %s", ai.SecuritySchemeName)
				}
			},
		},
		ErrorHandlerWithOpts: func(ctx context.Context, err error, w http.ResponseWriter, r *http.Request, opts nethttpMiddleware.ErrorHandlerOpts) {
			logger, ok := middleware.GetLoggerFromCtx(ctx)
			if !ok {
				logger = slog.Default()
			}

			var e Error

			var requestErr *openapi3filter.RequestError
			var secErr *openapi3filter.SecurityRequirementsError
			if errors.As(err, &requestErr) {
				e = Error{
					Message: err.Error(),
					Code:    InputValidationError,
				}
			} else if errors.As(err, &secErr) {
				e = Error{
					Message: err.Error(),
					Code:    AuthError,
				}
			} else {
				e = Error{
					Message: err.Error(),
					Code:    InternalError,
				}
			}
			jsonBody, err := json.Marshal(&e)
			if err != nil {
				logger.Error("failed to marshal input validation error resp", "error", err)
				jsonBody = []byte("{\"message\": \"input is invalid\", \"code\": \"InputValidationError\"")
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(opts.StatusCode)
			w.Write(jsonBody)
		},
	})
}

func (a *API) validateAccessTokenCookie(ctx context.Context, ai *openapi3filter.AuthenticationInput, logger *slog.Logger) error {
	authCookie, err := ai.RequestValidationInput.Request.Cookie(accessTokenCookieKey)
	if err != nil {
		return fmt.Errorf("auth token was not found in cookie %q", accessTokenCookieKey)
	}

	return a.validateAndSetAccessToken(ctx, ai, authCookie.Value, logger)
}

func (a *API) validateAccessTokenBearer(ctx context.Context, ai *openapi3filter.AuthenticationInput, logger *slog.Logger) error {
	authHeader := ai.RequestValidationInput.Request.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return fmt.Errorf("auth token was not found in Authorization header")
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")

	return a.validateAndSetAccessToken(ctx, ai, token, logger)
}

func (a *API) validateAndSetAccessToken(ctx context.Context, ai *openapi3filter.AuthenticationInput, tokenString string, logger *slog.Logger) error {
	claims, err := a.tokenService.ValidateAccessToken(tokenString)
	if err != nil {
		return fmt.Errorf("token is not valid: %w", err)
	}

	// Create auth token from claims
	authToken := token.NewICAAAuthToken(claims)

	err = validateScopes(authToken, ai.Scopes)
	if err != nil {
		logger.Error("user attempted to hit an authenticated API without permissions", slog.String("error", err.Error()))
		return fmt.Errorf("user does not have permissions")
	}

	loggerWithJwt := logger.With(slog.String("user-email", authToken.UserEmail()))
	ctx = middleware.CtxWithJWT(ctx, authToken)
	ctx = middleware.CtxWithLogger(ctx, loggerWithJwt)

	*ai.RequestValidationInput.Request = *ai.RequestValidationInput.Request.WithContext(ctx)

	return nil
}

func (a *API) validateRefreshTokenCookie(ctx context.Context, ai *openapi3filter.AuthenticationInput, logger *slog.Logger) error {
	refreshCookie, err := ai.RequestValidationInput.Request.Cookie(refreshTokenCookieKey)
	if err != nil {
		return fmt.Errorf("refresh token was not found in cookie %q", refreshTokenCookieKey)
	}

	tokenID, err := a.tokenService.ValidateRefreshToken(refreshCookie.Value)
	if err != nil {
		return fmt.Errorf("refresh token is not valid: %w", err)
	}

	// Store token ID in context for the handler to use
	ctx = middleware.CtxWithRefreshTokenID(ctx, tokenID)
	loggerWithToken := logger.With(slog.String("refresh-token-id", tokenID[:8]+"..."))
	ctx = middleware.CtxWithLogger(ctx, loggerWithToken)

	*ai.RequestValidationInput.Request = *ai.RequestValidationInput.Request.WithContext(ctx)

	return nil
}
