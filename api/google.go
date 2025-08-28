package api

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/International-Combat-Archery-Alliance/middleware"
)

const (
	googleAudience         = "1008624351875-q36btbijttq83bogn9f8a4srgji0g3qg.apps.googleusercontent.com"
	googleAuthJWTCookieKey = "GOOGLE_AUTH_JWT"
)

func (a *API) GetLoginGoogleUserInfo(ctx context.Context, request GetLoginGoogleUserInfoRequestObject) (GetLoginGoogleUserInfoResponseObject, error) {
	logger, ok := middleware.GetLoggerFromCtx(ctx)
	if !ok {
		a.logger.Error("no logger in context")
		logger = a.logger
	}

	token, ok := middleware.GetJWTFromCtx(ctx)
	if !ok {
		logger.Error("JWT not found in context")
		return GetLoginGoogleUserInfo401JSONResponse{
			Message: "User is not logged in",
			Code:    AuthError,
		}, nil
	}

	return GetLoginGoogleUserInfo200JSONResponse{
		IsAdmin:       token.IsAdmin(),
		ExpiresAt:     token.ExpiresAt(),
		ProfilePicURL: token.ProfilePicURL(),
		UserEmail:     token.UserEmail(),
	}, nil
}

func (a *API) PostLoginGoogle(ctx context.Context, request PostLoginGoogleRequestObject) (PostLoginGoogleResponseObject, error) {
	logger, ok := middleware.GetLoggerFromCtx(ctx)
	if !ok {
		a.logger.Error("no logger in context")
		logger = a.logger
	}

	token, err := a.tokenValidator.Validate(ctx, request.Body.GoogleJWT, googleAudience)
	if err != nil {
		logger.Error("invalid user jwt", slog.String("error", err.Error()))
		return PostLoginGoogle401JSONResponse{
			Message: "Invalid JWT",
			Code:    AuthError,
		}, nil
	}

	logger.Info("successful login", slog.String("email", token.UserEmail()))

	domain := "icaa.world"
	if a.env == LOCAL {
		domain = ""
	}

	cookie := &http.Cookie{
		Name:     googleAuthJWTCookieKey,
		Value:    request.Body.GoogleJWT,
		Expires:  token.ExpiresAt(),
		Domain:   domain,
		Path:     "/",
		HttpOnly: true,
		Secure:   a.env == PROD,
		SameSite: http.SameSiteStrictMode,
	}

	return PostLoginGoogle200Response{
		Headers: PostLoginGoogle200ResponseHeaders{
			SetCookie: cookie.String(),
		},
	}, nil
}

func (a *API) DeleteLoginGoogle(ctx context.Context, request DeleteLoginGoogleRequestObject) (DeleteLoginGoogleResponseObject, error) {
	logger, ok := middleware.GetLoggerFromCtx(ctx)
	if !ok {
		a.logger.Error("no logger in context")
		logger = a.logger
	}

	token, ok := middleware.GetJWTFromCtx(ctx)
	if !ok {
		logger.Info("non logged in user called logout API")
		return DeleteLoginGoogle200Response{}, nil
	}

	logger.Info("logging out user", slog.String("user-email", token.UserEmail()))

	domain := "icaa.world"
	if a.env == LOCAL {
		domain = ""
	}

	cookie := &http.Cookie{
		Name:     googleAuthJWTCookieKey,
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		Domain:   domain,
		Secure:   a.env == PROD,
		SameSite: http.SameSiteStrictMode,
	}

	return DeleteLoginGoogle200Response{
		Headers: DeleteLoginGoogle200ResponseHeaders{
			SetCookie: cookie.String(),
		},
	}, nil
}
