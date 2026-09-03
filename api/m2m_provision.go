package api

import (
	"context"
)

// Admin m2m-client provisioning handlers (INT-42).
//
// PR1 (spec) provides these stubs so the generated StrictServerInterface is
// satisfied and the spec change stays a buildable, reviewable unit. PR2
// replaces each body with the store/SSM-backed implementation; the response
// shapes and status codes are already fixed by spec/api.yaml.

func (a *API) GetLoginV1M2mClients(ctx context.Context, request GetLoginV1M2mClientsRequestObject) (GetLoginV1M2mClientsResponseObject, error) {
	return GetLoginV1M2mClients500JSONResponse{
		Message: "not implemented",
		Code:    InternalError,
	}, nil
}

func (a *API) PostLoginV1M2mClients(ctx context.Context, request PostLoginV1M2mClientsRequestObject) (PostLoginV1M2mClientsResponseObject, error) {
	return PostLoginV1M2mClients500JSONResponse{
		Message: "not implemented",
		Code:    InternalError,
	}, nil
}

func (a *API) DeleteLoginV1M2mClientsClientId(ctx context.Context, request DeleteLoginV1M2mClientsClientIdRequestObject) (DeleteLoginV1M2mClientsClientIdResponseObject, error) {
	return DeleteLoginV1M2mClientsClientId500JSONResponse{
		Message: "not implemented",
		Code:    InternalError,
	}, nil
}

func (a *API) PostLoginV1M2mClientsClientIdRotate(ctx context.Context, request PostLoginV1M2mClientsClientIdRotateRequestObject) (PostLoginV1M2mClientsClientIdRotateResponseObject, error) {
	return PostLoginV1M2mClientsClientIdRotate500JSONResponse{
		Message: "not implemented",
		Code:    InternalError,
	}, nil
}

func (a *API) PatchLoginV1M2mClientsClientId(ctx context.Context, request PatchLoginV1M2mClientsClientIdRequestObject) (PatchLoginV1M2mClientsClientIdResponseObject, error) {
	return PatchLoginV1M2mClientsClientId500JSONResponse{
		Message: "not implemented",
		Code:    InternalError,
	}, nil
}
