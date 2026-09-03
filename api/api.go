//go:generate go tool oapi-codegen --config openapi-codegen-config.yaml ../spec/api.yaml
package api

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/International-Combat-Archery-Alliance/auth"
	"github.com/International-Combat-Archery-Alliance/auth/token"
	"github.com/International-Combat-Archery-Alliance/login/m2m"
	"github.com/International-Combat-Archery-Alliance/middleware"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

type Environment int

const (
	LOCAL Environment = iota
	PROD
)

// UserTokenIssuer mints user tokens.
type UserTokenIssuer interface {
	GenerateAccessToken(email string, picture string, roles []auth.Role) (string, error)
	GenerateRefreshToken() (tokenID string, signedToken string, expiresAt time.Time, err error)
}

// UserTokenValidator verifies user tokens.
type UserTokenValidator interface {
	ValidateUserAccessToken(ctx context.Context, tokenString string) (*token.ICAAClaims, error)
	ValidateUserRefreshToken(ctx context.Context, tokenString string) (string, error)
}

// UserTokens signs and validates user tokens with locally held keys.
type UserTokens interface {
	UserTokenIssuer
	UserTokenValidator
}

// Config holds all dependencies for the API
type Config struct {
	GoogleTokenValidator auth.Validator
	UserTokens           UserTokens
	RefreshTokenStore    token.RefreshTokenStore
	MachineTokenSigner   m2m.TokenSigner
	// MachineTokenLifetime must match the lifetime the signer was built with;
	// zero defaults to token.DefaultMachineTokenLifetime.
	MachineTokenLifetime time.Duration
	M2MStore             m2m.Store
	JWKSProvider         JWKSProvider
	AdminEmails          []string
	Logger               *slog.Logger
	Environment          Environment
	FlushTraces          func(context.Context) error
}

var _ StrictServerInterface = (*API)(nil)

type API struct {
	logger               *slog.Logger
	env                  Environment
	tracer               trace.Tracer
	googleTokenValidator auth.Validator
	userTokens           UserTokens
	refreshTokenStore    token.RefreshTokenStore
	m2mService           *m2m.Service
	jwksProvider         JWKSProvider
	adminEmails          map[string]bool
	flushTraces          func(context.Context) error
}

func NewAPI(config Config) *API {
	// Convert admin emails slice to map for O(1) lookup
	adminMap := make(map[string]bool)
	for _, email := range config.AdminEmails {
		adminMap[strings.ToLower(email)] = true
	}

	lifetime := config.MachineTokenLifetime
	if lifetime == 0 {
		lifetime = token.DefaultMachineTokenLifetime
	}

	return &API{
		logger:               config.Logger,
		env:                  config.Environment,
		tracer:               otel.Tracer("github.com/International-Combat-Archery-Alliance/login/api"),
		googleTokenValidator: config.GoogleTokenValidator,
		userTokens:           config.UserTokens,
		refreshTokenStore:    config.RefreshTokenStore,
		m2mService:           m2m.NewService(config.M2MStore, config.MachineTokenSigner, lifetime),
		jwksProvider:         config.JWKSProvider,
		adminEmails:          adminMap,
		flushTraces:          config.FlushTraces,
	}
}

// isAdmin checks if an email is in the admin list
func (a *API) isAdmin(email string) bool {
	// If local env, everyone is an admin
	if a.env == LOCAL {
		return true
	}

	return a.adminEmails[strings.ToLower(email)]
}

func (a *API) ListenAndServe(host string, port string) error {
	swagger, err := GetSwagger()
	if err != nil {
		return fmt.Errorf("Error loading swagger spec: %w", err)
	}

	swagger.Servers = nil

	strictHandler := NewStrictHandler(a, []StrictMiddlewareFunc{})

	r := http.NewServeMux()

	HandlerFromMux(strictHandler, r)

	swaggerUIMiddleware, err := middleware.HostSwaggerUI("/login", swagger)
	if err != nil {
		return fmt.Errorf("failed to create swagger ui middleware: %w", err)
	}

	// Setup CORS middleware
	corsConfig := middleware.DefaultCorsConfig()
	corsConfig.IsProduction = a.env == PROD
	corsMiddleware := middleware.CorsMiddleware(corsConfig)

	middlewares := []middleware.MiddlewareFunc{
		// Executes from the bottom up
		a.openapiValidateMiddleware(swagger),
		corsMiddleware,
		swaggerUIMiddleware,
		middleware.AccessLogging(a.logger),
		middleware.OTELHandler,
		middleware.FlushTraces(a.flushTraces, a.logger, 3*time.Second),
	}

	if a.env == PROD {
		middlewares = append(middlewares, middleware.BaseNamePrefix(a.logger, "/login"))
	}

	h := middleware.UseMiddlewares(r, middlewares...)

	s := &http.Server{
		Handler: h,
		Addr:    net.JoinHostPort(host, port),
	}

	return s.ListenAndServe()
}
