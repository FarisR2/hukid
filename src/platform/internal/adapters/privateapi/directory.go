package privateapi

import (
	"context"
	"errors"
	"hukid.local/platform/internal/authentication"
	"hukid.local/platform/internal/tenancy"
	"net/http"
	"time"
)

type DirectoryHandler struct {
	Operators *Handler
	Directory *tenancy.Directory
}

func (h *DirectoryHandler) Register(mux *http.ServeMux) {
	for _, kind := range []string{"memberships", "invitations"} {
		mux.HandleFunc("/v1/operator/tenants/{tenantId}/"+kind, func(w http.ResponseWriter, r *http.Request) {
			if !Prepare(w, r) {
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			token, err := Bearer(r)
			if err != nil {
				DirectoryProblem(w, err, true)
				return
			}
			operator, err := h.Operators.Verifier.VerifyOperator(ctx, token)
			if err != nil {
				DirectoryProblem(w, err, true)
				return
			}
			identity, err := h.Operators.Tenancy.Me(ctx, operator)
			if err != nil {
				DirectoryProblem(w, err, true)
				return
			}
			h.Serve(w, r.WithContext(ctx), identity.ActorID, kind, true)
		})
	}
}
func (h *DirectoryHandler) Serve(w http.ResponseWriter, r *http.Request, actor, kind string, bearer bool) {
	page, err := h.Directory.List(r.Context(), actor, r.PathValue("tenantId"), kind, r.URL.RawQuery)
	if err != nil {
		DirectoryProblem(w, err, bearer)
		return
	}
	JSON(w, page)
}
func DirectoryProblem(w http.ResponseWriter, err error, bearer bool) {
	switch {
	case errors.Is(err, tenancy.ErrDirectoryRequest):
		writeProblem(w, 400, "invalid_request", "Solicitud inválida")
	case errors.Is(err, tenancy.ErrDirectoryCursor):
		writeProblem(w, 400, "invalid_cursor", "Cursor inválido")
	case errors.Is(err, tenancy.ErrMemberInput):
		writeProblem(w, 422, "invalid_input", "Filtros inválidos")
	case errors.Is(err, tenancy.ErrDirectoryForbidden):
		writeProblem(w, 403, "forbidden", "Acceso no permitido")
	case errors.Is(err, authentication.ErrTenant):
		writeProblem(w, 404, "resource_not_found", "Recurso no encontrado")
	case errors.Is(err, authentication.ErrSession), errors.Is(err, authentication.ErrCredential):
		if bearer {
			w.Header().Set("WWW-Authenticate", "Bearer")
		}
		writeProblem(w, 401, "invalid_credential", "Autenticación requerida")
	default:
		Problem(w, err, bearer)
	}
}
