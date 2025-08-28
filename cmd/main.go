package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/International-Combat-Archery-Alliance/auth/google"
	"github.com/International-Combat-Archery-Alliance/login/api"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	googleTokenValidator, err := google.NewValidator(ctx)
	if err != nil {
		logger.Error("error creating google token validator", slog.String("error", err.Error()))
		os.Exit(1)
	}

	loginApi := api.NewAPI(googleTokenValidator, logger, getApiEnvironment())

	serverSettings := getServerSettingsFromEnv()
	err = loginApi.ListenAndServe(serverSettings.Host, serverSettings.Port)
	if err != nil {
		logger.Error("error running server", "error", err)
		os.Exit(1)
	}
	logger.Info("shutting down")
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

func getEnvOrDefault(key string, defaultVal string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}

	return defaultVal
}

func isLocal() bool {
	return getEnvOrDefault("AWS_SAM_LOCAL", "false") == "true"
}

func getApiEnvironment() api.Environment {
	if isLocal() {
		return api.LOCAL
	}
	return api.PROD
}
