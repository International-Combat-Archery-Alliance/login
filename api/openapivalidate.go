package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/International-Combat-Archery-Alliance/auth"
	"github.com/International-Combat-Archery-Alliance/middleware"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	nethttpMiddleware "github.com/oapi-codegen/nethttp-middleware"
)

var scopeValidators map[string]func(token auth.AuthToken) error = map[string]func(token auth.AuthToken) error{
	"admin": func(token auth.AuthToken) error {
		if !token.IsAdmin() {
			return fmt.Errorf("user is not an admin")
		}
		return nil
	},
}

func validateScopes(token auth.AuthToken, scopes []string) error {
	for _, scope := range scopes {
		validator, ok := scopeValidators[scope]
		if !ok {
			return fmt.Errorf("unknown scope: %q", scope)
		}

		err := validator(token)
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

				var token string

				switch ai.SecuritySchemeName {
				case "googleCookieAuth":
					authCookie, err := ai.RequestValidationInput.Request.Cookie(googleAuthJWTCookieKey)
					if err != nil {
						return fmt.Errorf("Auth token was not found in cookie %q", googleAuthJWTCookieKey)
					}
					token = authCookie.Value
				case "googleBearerAuth":
					authHeader := ai.RequestValidationInput.Request.Header.Get("Authorization")
					if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
						return fmt.Errorf("Auth token was not found in Authorization header")
					}
					token = strings.TrimPrefix(authHeader, "Bearer ")
				default:
					return fmt.Errorf("unsupported security scheme")
				}

				jwt, err := a.tokenValidator.Validate(ctx, token, googleAudience)
				if err != nil {
					return fmt.Errorf("token is not valid")
				}

				err = validateScopes(jwt, ai.Scopes)
				if err != nil {
					logger.Error("user attempted to hit an authenticated API without permissions", slog.String("error", err.Error()))

					return fmt.Errorf("user does not have permissions")
				}

				loggerWithJwt := logger.With(slog.Any("user-email", jwt.UserEmail()))
				ctx = middleware.CtxWithJWT(ctx, jwt)
				ctx = middleware.CtxWithLogger(ctx, loggerWithJwt)

				*ai.RequestValidationInput.Request = *ai.RequestValidationInput.Request.WithContext(ctx)

				return nil
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
