package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/International-Combat-Archery-Alliance/auth"
	"github.com/International-Combat-Archery-Alliance/auth/google"
	"github.com/International-Combat-Archery-Alliance/auth/token"
	"github.com/International-Combat-Archery-Alliance/login/api"
	"github.com/International-Combat-Archery-Alliance/login/dynamo"
	"github.com/International-Combat-Archery-Alliance/telemetry"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"go.opentelemetry.io/otel"
	"golang.org/x/sync/errgroup"
)

var tracer = otel.Tracer("github.com/International-Combat-Archery-Alliance/login/cmd")

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	logger.Info("starting up")
	if err := run(logger); err != nil {
		logger.Error("startup failed", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	loginAPI, traceShutdown, err := setupApi(logger)
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := traceShutdown(shutdownCtx); err != nil {
			logger.Error("failed to shutdown telemetry", "error", err)
		}
	}()
	if err != nil {
		return err
	}

	serverSettings := getServerSettingsFromEnv()

	sigCtx, sigStop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer sigStop()

	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- loginAPI.ListenAndServe(serverSettings.Host, serverSettings.Port)
	}()

	select {
	case <-sigCtx.Done():
		logger.Info("shutting down gracefully")
		return nil
	case err := <-serverErrCh:
		if err != nil {
			logger.Error("error running server", "error", err)
			return err
		}
		return nil
	}
}

func setupApi(logger *slog.Logger) (*api.API, func(context.Context) error, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	env := getApiEnvironment()

	// -----------------------------------------------------------------------
	// Phase 1: New Relic license key → telemetry init (sequential dependency)
	// -----------------------------------------------------------------------

	licenseKey, err := getNewRelicLicenseKey(ctx, env)
	if err != nil {
		return nil, func(context.Context) error { return nil }, fmt.Errorf("new relic license key: %w", err)
	}

	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint == "" {
		endpoint = "otlp.nr-data.net:4317"
	}

	traceShutdown, flushTraces, err := telemetry.Init(ctx, telemetry.Options{
		ServiceName: "login",
		Endpoint:    endpoint,
		APIKey:      licenseKey,
		Lambda:      telemetry.LambdaInfoFromEnv(),
		ErrorHandler: func(err error) {
			logger.Error("otel error", slog.String("error", err.Error()))
		},
	})
	if err != nil {
		return nil, traceShutdown, fmt.Errorf("telemetry init: %w", err)
	}

	ctx, startupSpan := tracer.Start(ctx, "startup")
	defer startupSpan.End()

	// -----------------------------------------------------------------------
	// Phase 2: Fetch app config and create DB in parallel
	// -----------------------------------------------------------------------

	var (
		cfg *AppConfig
		db  *dynamodb.Client
	)

	g, gCtx := errgroup.WithContext(ctx)
	g.Go(func() error {
		ctx, span := tracer.Start(gCtx, "init-config")
		defer span.End()

		var err error
		cfg, err = fetchAppConfig(ctx, env)
		if err != nil {
			span.RecordError(err)
		}
		return err
	})

	g.Go(func() error {
		ctx, span := tracer.Start(gCtx, "init-db")
		defer span.End()

		var err error
		db, err = makeDB(ctx)
		if err != nil {
			span.RecordError(err)
		}
		return err
	})

	if err := g.Wait(); err != nil {
		startupSpan.RecordError(err)
		startupSpan.End()
		return nil, traceShutdown, err
	}

	// -----------------------------------------------------------------------
	// Phase 3: Wire up services (all instant after config is loaded)
	// -----------------------------------------------------------------------

	var googleTokenValidator auth.Validator
	googleTokenValidator, err = google.NewValidator(ctx)
	if err != nil {
		startupSpan.RecordError(err)
		startupSpan.End()
		return nil, traceShutdown, fmt.Errorf("google token validator: %w", err)
	}

	tokenService := token.NewTokenService(
		cfg.JWTSigningKeys[cfg.JWTCurrentKeyID],
		token.WithSigningKeys(cfg.JWTSigningKeys, cfg.JWTCurrentKeyID),
	)

	refreshTokenStore := dynamo.NewDynamoDBRefreshTokenStore(db, dynamoDBTableName)

	loginAPI := api.NewAPI(api.Config{
		GoogleTokenValidator: googleTokenValidator,
		TokenService:         tokenService,
		RefreshTokenStore:    refreshTokenStore,
		AdminEmails:          cfg.AdminEmails,
		Logger:               logger,
		Environment:          env,
		FlushTraces:          flushTraces,
	})

	return loginAPI, traceShutdown, nil
}

type ServerSettings struct {
	Host string
	Port string
}

func getServerSettingsFromEnv() ServerSettings {
	return ServerSettings{
		Host: getEnvOrDefault("HOST", "0.0.0.0"),
		Port: getEnvOrDefault("PORT", "8080"),
	}
}
