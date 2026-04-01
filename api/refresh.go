package api

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/International-Combat-Archery-Alliance/middleware"
)

func (a *API) PostLoginRefresh(ctx context.Context, request PostLoginRefreshRequestObject) (PostLoginRefreshResponseObject, error) {
	logger, ok := middleware.GetLoggerFromCtx(ctx)
	if !ok {
		a.logger.Error("no logger in context")
		logger = a.logger
	}

	// Get refresh token ID from context (validated by middleware)
	tokenID, ok := middleware.GetRefreshTokenIDFromCtx(ctx)
	if !ok {
		logger.Error("refresh token ID not found in context")
		return PostLoginRefresh401JSONResponse{
			Message: "Refresh token not found",
			Code:    AuthError,
		}, nil
	}

	// Look up the refresh token in the store
	userData, err := a.refreshTokenStore.Get(ctx, tokenID)
	if err != nil {
		logger.Error("refresh token not found in store", slog.String("error", err.Error()))
		return PostLoginRefresh401JSONResponse{
			Message: "Invalid refresh token",
			Code:    AuthError,
		}, nil
	}

	// Delete the old refresh token (token rotation)
	err = a.refreshTokenStore.Delete(ctx, tokenID)
	if err != nil {
		logger.Error("failed to delete old refresh token", slog.String("error", err.Error()))
		// Continue anyway - we'll generate a new one
	}

	// Generate new access token using stored picture and roles
	accessToken, err := a.tokenService.GenerateAccessToken(userData.UserEmail, userData.Picture, userData.Roles)
	if err != nil {
		logger.Error("failed to generate access token", slog.String("error", err.Error()))
		return PostLoginRefresh401JSONResponse{
			Message: "Failed to generate authentication tokens",
			Code:    AuthError,
		}, nil
	}

	// Generate new refresh token
	newRefreshTokenID, newRefreshToken, newRefreshExpiresAt, err := a.tokenService.GenerateRefreshToken()
	if err != nil {
		logger.Error("failed to generate refresh token", slog.String("error", err.Error()))
		return PostLoginRefresh401JSONResponse{
			Message: "Failed to generate authentication tokens",
			Code:    AuthError,
		}, nil
	}

	// Store new refresh token with same user data
	err = a.refreshTokenStore.Save(ctx, newRefreshTokenID, *userData, newRefreshExpiresAt)
	if err != nil {
		logger.Error("failed to save refresh token", slog.String("error", err.Error()))
		return PostLoginRefresh401JSONResponse{
			Message: "Failed to store authentication tokens",
			Code:    AuthError,
		}, nil
	}

	logger.Info("token refresh successful", slog.String("email", userData.UserEmail))

	domain := a.getCookieDomain()

	// Get access token expiration
	accessClaims, err := a.tokenService.ValidateAccessToken(accessToken)
	if err != nil {
		logger.Error("somehow generated a bad access token", slog.String("error", err.Error()))
		return PostLoginRefresh401JSONResponse{
			Message: "Bad access token",
			Code:    AuthError,
		}, nil
	}
	accessExpiresAt := accessClaims.ExpiresAt()

	// Create new access token cookie
	accessCookie := &http.Cookie{
		Name:     accessTokenCookieKey,
		Value:    accessToken,
		Expires:  accessExpiresAt,
		Domain:   domain,
		Path:     "/",
		HttpOnly: true,
		Secure:   a.env == PROD,
		SameSite: http.SameSiteStrictMode,
	}

	// Create new refresh token cookie
	refreshCookie := &http.Cookie{
		Name:     refreshTokenCookieKey,
		Value:    newRefreshToken,
		Expires:  newRefreshExpiresAt,
		Domain:   domain,
		Path:     "/",
		HttpOnly: true,
		Secure:   a.env == PROD,
		SameSite: http.SameSiteStrictMode,
	}

	return PostLoginRefresh200JSONResponse{
		Headers: PostLoginRefresh200ResponseHeaders{
			SetCookie: []string{accessCookie.String(), refreshCookie.String()},
		},
		Body: UserInfo{
			ExpiresAt:     accessExpiresAt,
			ProfilePicURL: userData.Picture,
			UserEmail:     userData.UserEmail,
			Roles:         rolesToUserInfoRoles(userData.Roles),
		},
	}, nil
}
