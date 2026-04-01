package api

import (
	"context"
	"log/slog"
	"net/http"
	"slices"

	"github.com/International-Combat-Archery-Alliance/auth"
	"github.com/International-Combat-Archery-Alliance/auth/token"
	"github.com/International-Combat-Archery-Alliance/middleware"
)

const (
	googleAudience = "1008624351875-q36btbijttq83bogn9f8a4srgji0g3qg.apps.googleusercontent.com"

	// Cookie names for ICAA tokens
	accessTokenCookieKey  = "ICAA_ACCESS_TOKEN"
	refreshTokenCookieKey = "ICAA_REFRESH_TOKEN"
)

func (a *API) GetLoginGoogleUserInfo(ctx context.Context, request GetLoginGoogleUserInfoRequestObject) (GetLoginGoogleUserInfoResponseObject, error) {
	logger, ok := middleware.GetLoggerFromCtx(ctx)
	if !ok {
		a.logger.Error("no logger in context")
		logger = a.logger
	}

	tok, ok := middleware.GetJWTFromCtx(ctx)
	if !ok {
		logger.Error("JWT not found in context")
		return GetLoginGoogleUserInfo401JSONResponse{
			Message: "User is not logged in",
			Code:    AuthError,
		}, nil
	}

	return GetLoginGoogleUserInfo200JSONResponse{
		IsAdmin:       tok.IsAdmin(),
		ExpiresAt:     tok.ExpiresAt(),
		ProfilePicURL: tok.ProfilePicURL(),
		UserEmail:     tok.UserEmail(),
		Roles:         rolesToUserInfoRoles(tok.Roles()),
	}, nil
}

func (a *API) PostLoginGoogle(ctx context.Context, request PostLoginGoogleRequestObject) (PostLoginGoogleResponseObject, error) {
	logger, ok := middleware.GetLoggerFromCtx(ctx)
	if !ok {
		a.logger.Error("no logger in context")
		logger = a.logger
	}

	// Validate the Google JWT
	googleToken, err := a.googleTokenValidator.Validate(ctx, request.Body.GoogleJWT, googleAudience)
	if err != nil {
		logger.Error("invalid user jwt", slog.String("error", err.Error()))
		return PostLoginGoogle401JSONResponse{
			Message: "Invalid JWT",
			Code:    AuthError,
		}, nil
	}

	email := googleToken.UserEmail()
	picture := googleToken.ProfilePicURL()
	roles := a.getRoles(email)

	logger.Info("successful login", slog.String("email", email))

	// Generate ICAA access token
	accessToken, err := a.tokenService.GenerateAccessToken(email, picture, roles)
	if err != nil {
		logger.Error("failed to generate access token", slog.String("error", err.Error()))
		return PostLoginGoogle401JSONResponse{
			Message: "Failed to generate authentication tokens",
			Code:    AuthError,
		}, nil
	}

	// Generate ICAA refresh token
	refreshTokenID, refreshToken, refreshExpiresAt, err := a.tokenService.GenerateRefreshToken()
	if err != nil {
		logger.Error("failed to generate refresh token", slog.String("error", err.Error()))
		return PostLoginGoogle401JSONResponse{
			Message: "Failed to generate authentication tokens",
			Code:    AuthError,
		}, nil
	}

	// Store refresh token in DynamoDB
	if a.refreshTokenStore != nil {
		refreshData := token.RefreshTokenData{
			UserEmail: email,
			Picture:   picture,
			Roles:     roles,
		}
		err = a.refreshTokenStore.Save(ctx, refreshTokenID, refreshData, refreshExpiresAt)
		if err != nil {
			logger.Error("failed to save refresh token", slog.String("error", err.Error()))
			return PostLoginGoogle401JSONResponse{
				Message: "Failed to store authentication tokens",
				Code:    AuthError,
			}, nil
		}
	}

	domain := a.getCookieDomain()

	// Get access token expiration for cookie
	accessClaims, err := a.tokenService.ValidateAccessToken(accessToken)
	if err != nil {
		logger.Error("failed to validate generated token somehow", slog.String("error", err.Error()))
		return PostLoginGoogle401JSONResponse{
			Message: "Failed to generate authentication token",
			Code:    AuthError,
		}, nil

	}

	accessExpiresAt := accessClaims.ExpiresAt()

	// Create access token cookie
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

	// Create refresh token cookie
	refreshCookie := &http.Cookie{
		Name:     refreshTokenCookieKey,
		Value:    refreshToken,
		Expires:  refreshExpiresAt,
		Domain:   domain,
		Path:     "/",
		HttpOnly: true,
		Secure:   a.env == PROD,
		SameSite: http.SameSiteStrictMode,
	}

	return PostLoginGoogle200JSONResponse{
		Headers: PostLoginGoogle200ResponseHeaders{
			SetCookie: accessCookie.String() + ", " + refreshCookie.String(),
		},
		Body: UserInfo{
			IsAdmin:       slices.Contains(roles, auth.RoleAdmin),
			ExpiresAt:     accessExpiresAt,
			ProfilePicURL: picture,
			UserEmail:     email,
			Roles:         rolesToUserInfoRoles(roles),
		},
	}, nil
}

func (a *API) DeleteLoginGoogle(ctx context.Context, request DeleteLoginGoogleRequestObject) (DeleteLoginGoogleResponseObject, error) {
	logger, ok := middleware.GetLoggerFromCtx(ctx)
	if !ok {
		a.logger.Error("no logger in context")
		logger = a.logger
	}

	tok, ok := middleware.GetJWTFromCtx(ctx)
	if !ok {
		logger.Info("non logged in user called logout API")
		return DeleteLoginGoogle200Response{}, nil
	}

	logger.Info("logging out user", slog.String("user-email", tok.UserEmail()))

	// Get refresh token ID from context and delete from store
	if a.refreshTokenStore != nil {
		if refreshTokenID, ok := middleware.GetRefreshTokenIDFromCtx(ctx); ok {
			err := a.refreshTokenStore.Delete(ctx, refreshTokenID)
			if err != nil {
				logger.Error("failed to delete refresh token from store", slog.String("error", err.Error()))
				// Continue anyway - we still want to clear the cookies
			} else {
				logger.Info("deleted refresh token from store")
			}
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

	return DeleteLoginGoogle200Response{
		Headers: DeleteLoginGoogle200ResponseHeaders{
			SetCookie: accessCookie.String() + ", " + refreshCookie.String(),
		},
	}, nil
}

// getCookieDomain returns the appropriate cookie domain based on environment
func (a *API) getCookieDomain() string {
	if a.env == LOCAL {
		return ""
	}
	return "icaa.world"
}

// getRoles returns the roles for a user based on admin email list
func (a *API) getRoles(email string) []auth.Role {
	if a.isAdmin(email) {
		return []auth.Role{auth.RoleAdmin}
	}
	return nil
}

// rolesToUserInfoRoles converts auth.Role slice to UserInfoRoles slice
func rolesToUserInfoRoles(roles []auth.Role) []UserInfoRoles {
	if roles == nil {
		return nil
	}
	result := make([]UserInfoRoles, len(roles))
	for i, role := range roles {
		result[i] = UserInfoRoles(role)
	}
	return result
}

// GetLoginMe returns info about the logged in user (new endpoint)
func (a *API) GetLoginMe(ctx context.Context, request GetLoginMeRequestObject) (GetLoginMeResponseObject, error) {
	// Reuse the same logic as GetLoginGoogleUserInfo
	logger, ok := middleware.GetLoggerFromCtx(ctx)
	if !ok {
		a.logger.Error("no logger in context")
		logger = a.logger
	}

	tok, ok := middleware.GetJWTFromCtx(ctx)
	if !ok {
		logger.Error("JWT not found in context")
		return GetLoginMe401JSONResponse{
			Message: "User is not logged in",
			Code:    AuthError,
		}, nil
	}

	return GetLoginMe200JSONResponse{
		IsAdmin:       tok.IsAdmin(),
		ExpiresAt:     tok.ExpiresAt(),
		ProfilePicURL: tok.ProfilePicURL(),
		UserEmail:     tok.UserEmail(),
		Roles:         rolesToUserInfoRoles(tok.Roles()),
	}, nil
}

// DeleteLoginSession logs the user out (new endpoint)
func (a *API) DeleteLoginSession(ctx context.Context, request DeleteLoginSessionRequestObject) (DeleteLoginSessionResponseObject, error) {
	// Reuse the same logic as DeleteLoginGoogle
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
	if a.refreshTokenStore != nil {
		if refreshTokenID, ok := middleware.GetRefreshTokenIDFromCtx(ctx); ok {
			err := a.refreshTokenStore.Delete(ctx, refreshTokenID)
			if err != nil {
				logger.Error("failed to delete refresh token from store", slog.String("error", err.Error()))
				// Continue anyway - we still want to clear the cookies
			} else {
				logger.Info("deleted refresh token from store")
			}
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
			SetCookie: accessCookie.String() + ", " + refreshCookie.String(),
		},
	}, nil
}
