package api

import (
	"net/http"

	"github.com/International-Combat-Archery-Alliance/middleware"
	"github.com/rs/cors"
)

func (a *API) corsMiddleware() middleware.MiddlewareFunc {
	var serverCors *cors.Cors

	switch a.env {
	case LOCAL:
		serverCors = cors.New(cors.Options{
			AllowedOrigins: []string{"http://localhost:4173", "http://localhost:5173"},
			AllowedMethods: []string{
				http.MethodHead,
				http.MethodGet,
				http.MethodPost,
				http.MethodPut,
				http.MethodPatch,
				http.MethodDelete,
			},
			AllowedHeaders:   []string{"*"},
			AllowCredentials: true,
		})
	case PROD:
		serverCors = cors.New(cors.Options{
			AllowedOrigins: []string{"https://www.icaa.world", "https://icaa.world", "https://www.*-icaa-world.curly-sound-f2cd.workers.dev", "https://*-icaa-world.curly-sound-f2cd.workers.dev"},
			AllowedMethods: []string{
				http.MethodHead,
				http.MethodGet,
				http.MethodPost,
				http.MethodPut,
				http.MethodPatch,
				http.MethodDelete,
			},
			// TODO: revisit this
			AllowedHeaders:   []string{"*"},
			MaxAge:           300,
			AllowCredentials: true,
		})
	}

	return serverCors.Handler
}
