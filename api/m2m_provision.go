package api

import (
	"context"
	"errors"
	"log/slog"

	"github.com/International-Combat-Archery-Alliance/login/m2m"
	"github.com/International-Combat-Archery-Alliance/middleware"
)

// PostLoginV1M2mClients provisions a new machine client credential.
func (a *API) PostLoginV1M2mClients(ctx context.Context, request PostLoginV1M2mClientsRequestObject) (PostLoginV1M2mClientsResponseObject, error) {
	ctx, span := a.tracer.Start(ctx, "PostLoginV1M2mClients")
	defer span.End()

	logger := a.provisionLogger(ctx)

	if request.Body == nil {
		return PostLoginV1M2mClients400JSONResponse{Message: "request body is required", Code: InputValidationError}, nil
	}

	secret, err := a.provisioner.CreateClient(ctx, request.Body.ClientId, request.Body.Audiences, logger)
	if err != nil {
		switch {
		case errors.Is(err, m2m.ErrInvalidClientID),
			errors.Is(err, m2m.ErrInvalidAudience),
			errors.Is(err, m2m.ErrInvalidScopes):
			return PostLoginV1M2mClients400JSONResponse{Message: err.Error(), Code: InputValidationError}, nil
		case errors.Is(err, m2m.ErrClientExists):
			return PostLoginV1M2mClients409JSONResponse{Message: "machine client already exists", Code: Conflict}, nil
		default:
			span.RecordError(err)
			logger.Error("m2m client provisioning failed", slog.String("clientId", request.Body.ClientId))
			return PostLoginV1M2mClients500JSONResponse{Message: "internal error", Code: InternalError}, nil
		}
	}

	return PostLoginV1M2mClients201JSONResponse{
		ClientId:     request.Body.ClientId,
		ClientSecret: secret,
	}, nil
}

// GetLoginV1M2mClients lists provisioned machine clients (metadata only).
func (a *API) GetLoginV1M2mClients(ctx context.Context, request GetLoginV1M2mClientsRequestObject) (GetLoginV1M2mClientsResponseObject, error) {
	ctx, span := a.tracer.Start(ctx, "GetLoginV1M2mClients")
	defer span.End()

	logger := a.provisionLogger(ctx)

	clients, err := a.provisioner.ListClients(ctx)
	if err != nil {
		span.RecordError(err)
		logger.Error("m2m client listing failed", slog.String("error", err.Error()))
		return GetLoginV1M2mClients500JSONResponse{Message: "internal error", Code: InternalError}, nil
	}

	out := make([]M2MClient, 0, len(clients))
	for _, c := range clients {
		out = append(out, provisionClientToModel(c))
	}
	return GetLoginV1M2mClients200JSONResponse{Clients: out}, nil
}

// DeleteLoginV1M2mClientsClientId revokes a machine client (active=false).
func (a *API) DeleteLoginV1M2mClientsClientId(ctx context.Context, request DeleteLoginV1M2mClientsClientIdRequestObject) (DeleteLoginV1M2mClientsClientIdResponseObject, error) {
	ctx, span := a.tracer.Start(ctx, "DeleteLoginV1M2mClientsClientId")
	defer span.End()

	logger := a.provisionLogger(ctx)

	client, err := a.provisioner.RevokeClient(ctx, request.ClientId, logger)
	if err != nil {
		switch {
		case errors.Is(err, m2m.ErrInvalidClientID):
			return DeleteLoginV1M2mClientsClientId400JSONResponse{Message: err.Error(), Code: InputValidationError}, nil
		case errors.Is(err, m2m.ErrClientNotFound):
			return DeleteLoginV1M2mClientsClientId404JSONResponse{Message: "machine client not found", Code: NotFound}, nil
		default:
			span.RecordError(err)
			logger.Error("m2m client revocation failed", slog.String("clientId", request.ClientId))
			return DeleteLoginV1M2mClientsClientId500JSONResponse{Message: "internal error", Code: InternalError}, nil
		}
	}

	return DeleteLoginV1M2mClientsClientId200JSONResponse(provisionClientToModel(client)), nil
}

// PostLoginV1M2mClientsClientIdRotate rotates a machine client secret.
func (a *API) PostLoginV1M2mClientsClientIdRotate(ctx context.Context, request PostLoginV1M2mClientsClientIdRotateRequestObject) (PostLoginV1M2mClientsClientIdRotateResponseObject, error) {
	ctx, span := a.tracer.Start(ctx, "PostLoginV1M2mClientsClientIdRotate")
	defer span.End()

	logger := a.provisionLogger(ctx)

	secret, err := a.provisioner.RotateClient(ctx, request.ClientId, logger)
	if err != nil {
		switch {
		case errors.Is(err, m2m.ErrInvalidClientID):
			return PostLoginV1M2mClientsClientIdRotate400JSONResponse{Message: err.Error(), Code: InputValidationError}, nil
		case errors.Is(err, m2m.ErrClientNotFound):
			return PostLoginV1M2mClientsClientIdRotate404JSONResponse{Message: "machine client not found", Code: NotFound}, nil
		case errors.Is(err, m2m.ErrClientInactive):
			return PostLoginV1M2mClientsClientIdRotate409JSONResponse{Message: "machine client is revoked", Code: Conflict}, nil
		case errors.Is(err, m2m.ErrRoundsConflict):
			return PostLoginV1M2mClientsClientIdRotate409JSONResponse{Message: "machine client changed concurrently; retry", Code: Conflict}, nil
		default:
			span.RecordError(err)
			logger.Error("m2m client rotation failed", slog.String("clientId", request.ClientId))
			return PostLoginV1M2mClientsClientIdRotate500JSONResponse{Message: "internal error", Code: InternalError}, nil
		}
	}

	return PostLoginV1M2mClientsClientIdRotate200JSONResponse{
		ClientId:     request.ClientId,
		ClientSecret: secret,
	}, nil
}

func provisionClientToModel(c *m2m.Client) M2MClient {
	audiences := c.Audiences
	if audiences == nil {
		audiences = map[string][]string{}
	}
	return M2MClient{
		ClientId:  c.ID,
		Audiences: audiences,
		Active:    c.Active,
	}
}

// provisionLogger returns the request logger enriched with the acting admin's
// email for the audit trail (who/what/when — never the secret).
func (a *API) provisionLogger(ctx context.Context) *slog.Logger {
	logger, ok := middleware.GetLoggerFromCtx(ctx)
	if !ok {
		logger = a.logger
	}
	if tok, ok := middleware.GetJWTFromCtx(ctx); ok {
		return logger.With(slog.String("admin-email", tok.UserEmail()))
	}
	return logger
}

func (a *API) PatchLoginV1M2mClientsClientId(ctx context.Context, request PatchLoginV1M2mClientsClientIdRequestObject) (PatchLoginV1M2mClientsClientIdResponseObject, error) {
	return PatchLoginV1M2mClientsClientId500JSONResponse{
		Message: "not implemented",
		Code:    InternalError,
	}, nil
}
