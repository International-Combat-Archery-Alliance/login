//go:generate go tool oapi-codegen --config openapi-codegen-config.yaml ../spec/api.yaml
package api

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/International-Combat-Archery-Alliance/auth"
	"github.com/International-Combat-Archery-Alliance/auth/token"
	"github.com/International-Combat-Archery-Alliance/middleware"
)

type Environment int

const (
	LOCAL Environment = iota
	PROD
)

// Config holds all dependencies for the API
type Config struct {
	GoogleTokenValidator auth.Validator
	TokenService         *token.TokenService
	RefreshTokenStore    token.RefreshTokenStore
	AdminEmails          []string
	Logger               *slog.Logger
	Environment          Environment
}

var _ StrictServerInterface = (*API)(nil)

type API struct {
	logger               *slog.Logger
	env                  Environment
	googleTokenValidator auth.Validator
	tokenService         *token.TokenService
	refreshTokenStore    token.RefreshTokenStore
	adminEmails          map[string]bool
}

func NewAPI(config Config) *API {
	// Convert admin emails slice to map for O(1) lookup
	adminMap := make(map[string]bool)
	for _, email := range config.AdminEmails {
		adminMap[strings.ToLower(email)] = true
	}

	return &API{
		logger:               config.Logger,
		env:                  config.Environment,
		googleTokenValidator: config.GoogleTokenValidator,
		tokenService:         config.TokenService,
		refreshTokenStore:    config.RefreshTokenStore,
		adminEmails:          adminMap,
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
