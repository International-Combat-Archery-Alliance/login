package api

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/International-Combat-Archery-Alliance/middleware"
)

// DeleteLoginSession logs the user out
func (a *API) DeleteLoginSession(ctx context.Context, request DeleteLoginSessionRequestObject) (DeleteLoginSessionResponseObject, error) {
	ctx, span := a.tracer.Start(ctx, "DeleteLoginSession")
	defer span.End()

	logger, ok := middleware.GetLoggerFromCtx(ctx)
	if !ok {
		a.logger.Error("no logger in context")
		logger = a.logger
	}

	tok, ok := middleware.GetJWTFromCtx(ctx)
	if !ok {
		logger.Info("non logged in user called logout API")
		return DeleteLoginSession200Response{}, nil
	}

	logger.Info("logging out user", slog.String("user-email", tok.UserEmail()))

	// Get refresh token ID from context and delete from store
	if refreshTokenID, ok := middleware.GetRefreshTokenIDFromCtx(ctx); ok {
		err := a.refreshTokenStore.Delete(ctx, refreshTokenID)
		if err != nil {
			span.RecordError(err)
			logger.Error("failed to delete refresh token from store", slog.String("error", err.Error()))
			// Continue anyway - we still want to clear the cookies
		} else {
			logger.Info("deleted refresh token from store")
		}
	}

	domain := a.getCookieDomain()

	accessCookie := &http.Cookie{
		Name:     accessTokenCookieKey,
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		Domain:   domain,
		Secure:   a.env == PROD,
		SameSite: http.SameSiteStrictMode,
	}

	refreshCookie := &http.Cookie{
		Name:     refreshTokenCookieKey,
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		Domain:   domain,
		Secure:   a.env == PROD,
		SameSite: http.SameSiteStrictMode,
	}

	return DeleteLoginSession200Response{
		Headers: DeleteLoginSession200ResponseHeaders{
			SetCookie: []string{accessCookie.String(), refreshCookie.String()},
		},
	}, nil
}

// GetLoginSession returns info about the current session/user
func (a *API) GetLoginSession(ctx context.Context, request GetLoginSessionRequestObject) (GetLoginSessionResponseObject, error) {
	ctx, span := a.tracer.Start(ctx, "GetLoginSession")
	defer span.End()

	logger, ok := middleware.GetLoggerFromCtx(ctx)
	if !ok {
		a.logger.Error("no logger in context")
		logger = a.logger
	}

	tok, ok := middleware.GetJWTFromCtx(ctx)
	if !ok {
		logger.Error("JWT not found in context")
		return GetLoginSession401JSONResponse{
			Message: "User is not logged in",
			Code:    AuthError,
		}, nil
	}

	return GetLoginSession200JSONResponse{
		ExpiresAt:     tok.ExpiresAt(),
		ProfilePicURL: tok.ProfilePicURL(),
		UserEmail:     tok.UserEmail(),
		Roles:         rolesToUserInfoRoles(tok.Roles()),
	}, nil
}
