package privateapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	a "hukid.local/platform/internal/authentication"
	"hukid.local/platform/internal/tenancy"
)

type InvitationVerifier interface {
	VerifyInvitationOperator(context.Context, string) (a.Operator, time.Time, error)
}
type InvitationHandler struct {
	Operators *Handler
	Verifier  InvitationVerifier
	Service   *tenancy.InvitationService
}

func (h *InvitationHandler) Register(mux *http.ServeMux) {
	for _, path := range []string{"/v1/operator/tenants/{tenantId}/invitations", "/v1/operator/tenants/{tenantId}/invitations/{invitationId}/revocations"} {
		pattern := path
		if !strings.HasSuffix(path, "/revocations") {
			pattern = "POST " + path
		}
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			if !PrepareMethod(w, r, http.MethodPost) {
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			raw, err := Bearer(r)
			if err != nil {
				InvitationProblem(w, err, true)
				return
			}
			h.Authenticate(w, r.WithContext(ctx), raw, "", true)
		})
	}
}

// A BFF passes its server-held access token and binds the authenticated actor to
// the session. Both surfaces share decoding, authorization and mutation logic.
func (h *InvitationHandler) Authenticate(w http.ResponseWriter, r *http.Request, raw, sessionActor string, bearer bool) {
	operator, deadline, err := h.Verifier.VerifyInvitationOperator(r.Context(), raw)
	if err != nil {
		InvitationProblem(w, err, bearer)
		return
	}
	identity, err := h.Operators.Tenancy.Me(r.Context(), operator)
	if err != nil {
		InvitationProblem(w, err, bearer)
		return
	}
	if sessionActor != "" && identity.ActorID != sessionActor {
		InvitationProblem(w, a.ErrSession, bearer)
		return
	}
	c := tenancy.InvitationCommand{Actor: identity.ActorID, Tenant: r.PathValue("tenantId"), InvitationID: r.PathValue("invitationId"), PrivilegeDeadline: deadline, Operation: "invitation.create"}
	keys := r.Header.Values("Idempotency-Key")
	if len(keys) != 1 {
		InvitationProblem(w, tenancy.ErrDirectoryRequest, bearer)
		return
	}
	c.Key = keys[0]
	if c.InvitationID != "" {
		c.Operation = "invitation.revoke"
		revisions := r.Header.Values("If-Match")
		if len(revisions) == 0 {
			writeProblem(w, 428, "precondition_required", "Se requiere revisión")
			return
		}
		if len(revisions) != 1 || !regexp.MustCompile(`^"[1-9][0-9]{0,15}"$`).MatchString(revisions[0]) {
			InvitationProblem(w, tenancy.ErrDirectoryRequest, bearer)
			return
		}
		c.Revision, err = strconv.ParseInt(revisions[0][1:len(revisions[0])-1], 10, 64)
		if err != nil || c.Revision > 9007199254740991 {
			InvitationProblem(w, tenancy.ErrDirectoryRequest, bearer)
			return
		}
		var input tenancy.RevokeInput
		if !decodeInvitation(w, r, &input, []string{"reasonCode"}) {
			return
		}
		c.Reason = input.ReasonCode
	} else {
		if !decodeInvitation(w, r, &c.Input, []string{"email", "roles", "issuerIds"}) {
			return
		}
	}
	result, err := h.Service.Execute(r.Context(), c)
	if err != nil {
		InvitationProblem(w, err, bearer)
		return
	}
	w.Header().Set("ETag", `"`+strconv.FormatInt(result.Revision, 10)+`"`)
	w.Header().Set("Content-Type", "application/json")
	status := http.StatusOK
	if c.Operation == "invitation.create" {
		status = http.StatusCreated
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(result)
}
func decodeInvitation(w http.ResponseWriter, r *http.Request, dest any, fields []string) bool {
	media, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || len(params) > 0 {
		writeProblem(w, 415, "unsupported_media_type", "Se requiere JSON")
		return false
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		writeProblem(w, 400, "invalid_request", "Solicitud inválida")
		return false
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		writeProblem(w, 400, "invalid_request", "JSON inválido")
		return false
	}
	seen := map[string]json.RawMessage{}
	for d.More() {
		token, err = d.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			writeProblem(w, 400, "invalid_request", "JSON inválido")
			return false
		}
		if _, exists := seen[key]; exists {
			writeProblem(w, 400, "invalid_request", "JSON inválido")
			return false
		}
		allowed := false
		for _, field := range fields {
			if key == field {
				allowed = true
			}
		}
		if !allowed {
			writeProblem(w, 422, "invalid_input", "Campos inválidos")
			return false
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			writeProblem(w, 400, "invalid_request", "JSON inválido")
			return false
		}
		seen[key] = value
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') || d.Decode(new(any)) != io.EOF {
		writeProblem(w, 400, "invalid_request", "JSON inválido")
		return false
	}
	if len(seen) != len(fields) {
		writeProblem(w, 422, "invalid_input", "Campos inválidos")
		return false
	}
	for _, value := range seen {
		if string(value) == "null" {
			writeProblem(w, 422, "invalid_input", "Campos inválidos")
			return false
		}
	}
	data, _ := json.Marshal(seen)
	if json.Unmarshal(data, dest) != nil {
		writeProblem(w, 422, "invalid_input", "Campos inválidos")
		return false
	}
	return true
}
func InvitationProblem(w http.ResponseWriter, err error, bearer bool) {
	switch {
	case errors.Is(err, tenancy.ErrInvitationBusy):
		w.Header().Set("Retry-After", "1")
		writeProblem(w, 409, "operation_in_progress", "Operación en curso")
	case errors.Is(err, tenancy.ErrInvitationConflict):
		writeProblem(w, 409, "idempotency_conflict", "Clave reutilizada")
	case errors.Is(err, tenancy.ErrInvitationState):
		writeProblem(w, 409, "invitation_not_pending", "Invitación no pendiente")
	case errors.Is(err, tenancy.ErrInvitationRevision):
		writeProblem(w, 412, "revision_mismatch", "Revisión obsoleta")
	case errors.Is(err, a.ErrStepUp), errors.Is(err, a.ErrMFA):
		writeProblem(w, 403, "mfa_required", "Se requiere MFA reciente")
	default:
		DirectoryProblem(w, err, bearer)
	}
}
