package oid4vcihttp

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"hukid.local/platform/internal/issuance"
)

const (
	maxIntegrationBody = 64 << 10
	maxCredentialBody  = 32 << 10
	maxTokenBody       = 8 << 10
)

// IssuanceHandler serves the Phase 3 surface: the private Integration API
// (/v1/issuance-requests), the shared token endpoint and the wallet-facing
// OpenID4VCI endpoints. Each surface accepts exactly one token class; mixing
// them is rejected before any scope is evaluated.
type IssuanceHandler struct {
	Service *issuance.Service
}

// Routes registers the Phase 3 endpoints on mux.
func (h *IssuanceHandler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/issuance-requests", h.createRequest)
	mux.HandleFunc("GET /v1/issuance-requests/{id}", h.getRequest)
	mux.HandleFunc("POST /v1/credentials/{id}/suspensions", h.suspendCredential)
	mux.HandleFunc("DELETE /v1/credentials/{id}/suspension", h.reactivateCredential)
	mux.HandleFunc("POST /v1/credentials/{id}/revocations", h.revokeCredential)
	mux.HandleFunc("POST /oauth2/token", h.token)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", h.authorizationServer)
	mux.HandleFunc("GET /{slug}/offers/{ref}", h.offer)
	mux.HandleFunc("GET /{slug}/status/{purpose}/{listId}", h.statusList)
	mux.HandleFunc("POST /{slug}/nonce", h.nonce)
	mux.HandleFunc("POST /{slug}/credential", h.credential)
}

func (h *IssuanceHandler) ready() bool { return h != nil && h.Service != nil }

func bearer(r *http.Request) (string, bool) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return "", false
	}
	scheme, token, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" || strings.ContainsAny(token, " \t") {
		return "", false
	}
	return token, true
}

func writeJSON(w http.ResponseWriter, status int, contentType string, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		fail(w, http.StatusInternalServerError, "server_error")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

type problemBody struct {
	Type   string                `json:"type"`
	Title  string                `json:"title"`
	Status int                   `json:"status"`
	Code   string                `json:"code"`
	Errors []issuance.FieldError `json:"errors,omitempty"`
}

func problem(w http.ResponseWriter, status int, code, title string, fields []issuance.FieldError) {
	writeJSON(w, status, "application/problem+json", problemBody{
		Type: "https://docs.hukid.pe/problems/" + code, Title: title, Status: status, Code: code, Errors: fields,
	})
}

func oauthError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, "application/json", map[string]string{"error": code})
}

func invalidIntegrationToken(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	problem(w, http.StatusUnauthorized, "invalid_token", "Authentication is missing or invalid", nil)
}

func decodeBody(w http.ResponseWriter, r *http.Request, limit int64, dst any, strict bool) error {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	decoder := json.NewDecoder(r.Body)
	if strict {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}

func isJSON(r *http.Request) bool {
	return strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json")
}

func (h *IssuanceHandler) createRequest(w http.ResponseWriter, r *http.Request) {
	if !h.ready() {
		problem(w, http.StatusServiceUnavailable, "server_error", "Service unavailable", nil)
		return
	}
	raw, ok := bearer(r)
	if !ok {
		invalidIntegrationToken(w)
		return
	}
	token, err := h.Service.AuthenticateIntegration(raw)
	if err != nil {
		invalidIntegrationToken(w)
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if key == "" {
		problem(w, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key header is required", nil)
		return
	}
	var in issuance.IssuanceRequestInput
	if !isJSON(r) || decodeBody(w, r, maxIntegrationBody, &in, true) != nil {
		problem(w, http.StatusBadRequest, "malformed_request", "The request body is not valid", nil)
		return
	}
	result, replay, err := h.Service.CreateIssuanceRequest(token, key, in)
	if err != nil {
		writeIntegrationError(w, err)
		return
	}
	status := http.StatusCreated
	if replay {
		status = http.StatusOK
	}
	w.Header().Set("Location", "/v1/issuance-requests/"+result.ID)
	writeJSON(w, status, "application/json", result)
}

func (h *IssuanceHandler) getRequest(w http.ResponseWriter, r *http.Request) {
	if !h.ready() {
		problem(w, http.StatusServiceUnavailable, "server_error", "Service unavailable", nil)
		return
	}
	raw, ok := bearer(r)
	if !ok {
		invalidIntegrationToken(w)
		return
	}
	token, err := h.Service.AuthenticateIntegration(raw)
	if err != nil {
		invalidIntegrationToken(w)
		return
	}
	result, err := h.Service.GetRequest(token, r.PathValue("id"))
	if err != nil {
		writeIntegrationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, "application/json", result)
}

func (h *IssuanceHandler) requireIntegrationCommand(w http.ResponseWriter, r *http.Request) (issuance.IntegrationToken, string, bool) {
	if !h.ready() {
		problem(w, http.StatusServiceUnavailable, "server_error", "Service unavailable", nil)
		return issuance.IntegrationToken{}, "", false
	}
	raw, ok := bearer(r)
	if !ok {
		invalidIntegrationToken(w)
		return issuance.IntegrationToken{}, "", false
	}
	token, err := h.Service.AuthenticateIntegration(raw)
	if err != nil {
		invalidIntegrationToken(w)
		return issuance.IntegrationToken{}, "", false
	}
	key := r.Header.Get("Idempotency-Key")
	if key == "" {
		problem(w, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key header is required", nil)
		return issuance.IntegrationToken{}, "", false
	}
	return token, key, true
}

func (h *IssuanceHandler) suspendCredential(w http.ResponseWriter, r *http.Request) {
	h.mutateStatus(w, r, "suspend")
}

func (h *IssuanceHandler) reactivateCredential(w http.ResponseWriter, r *http.Request) {
	h.mutateStatus(w, r, "reactivate")
}

func (h *IssuanceHandler) revokeCredential(w http.ResponseWriter, r *http.Request) {
	h.mutateStatus(w, r, "revoke")
}

func (h *IssuanceHandler) mutateStatus(w http.ResponseWriter, r *http.Request, op string) {
	token, key, ok := h.requireIntegrationCommand(w, r)
	if !ok {
		return
	}
	var in issuance.StatusChangeInput
	if op != "reactivate" {
		if !isJSON(r) || decodeBody(w, r, maxTokenBody, &in, true) != nil {
			problem(w, http.StatusBadRequest, "malformed_request", "The request body is not valid", nil)
			return
		}
	}
	id := r.PathValue("id")
	var (
		res    issuance.StatusChangeResult
		replay bool
		err    error
	)
	switch op {
	case "suspend":
		res, replay, err = h.Service.SuspendCredential(token, key, id, in)
	case "reactivate":
		res, replay, err = h.Service.ReactivateCredential(token, key, id)
	case "revoke":
		res, replay, err = h.Service.RevokeCredential(token, key, id, in)
	}
	if err != nil {
		writeIntegrationError(w, err)
		return
	}
	status := http.StatusOK
	if !replay {
		status = http.StatusAccepted
	}
	writeJSON(w, status, "application/json", res)
}

func writeIntegrationError(w http.ResponseWriter, err error) {
	var claims *issuance.ClaimValidationError
	switch {
	case errors.As(err, &claims):
		problem(w, http.StatusUnprocessableEntity, "claim_validation_failed", "The claims do not satisfy the definition", claims.Errors)
	case errors.Is(err, issuance.ErrResourceNotFound):
		problem(w, http.StatusNotFound, "resource_not_found", "Resource not found", nil)
	case errors.Is(err, issuance.ErrClientUnauthorized):
		problem(w, http.StatusForbidden, "grant_denied", "The client is not authorized for this operation", nil)
	case errors.Is(err, issuance.ErrIdempotencyConflict):
		problem(w, http.StatusConflict, "idempotency_key_reused", "The Idempotency-Key was used with a different request", nil)
	case errors.Is(err, issuance.ErrInvalidStatusTransition):
		problem(w, http.StatusConflict, "invalid_state_transition", "The requested credential status transition is not permitted", nil)
	case errors.Is(err, issuance.ErrDefinitionNotFound):
		problem(w, http.StatusUnprocessableEntity, "definition_not_found", "The credential definition does not exist", nil)
	case errors.Is(err, issuance.ErrDefinitionUnavailable):
		problem(w, http.StatusUnprocessableEntity, "definition_not_published", "The credential definition cannot issue", nil)
	case errors.Is(err, issuance.ErrUnsupportedDelivery):
		problem(w, http.StatusUnprocessableEntity, "delivery_not_supported", "The delivery option is not supported", nil)
	case errors.Is(err, issuance.ErrNoActiveKey):
		problem(w, http.StatusServiceUnavailable, "server_error", "No active signing key", nil)
	case errors.Is(err, issuance.ErrInvalidRequest):
		problem(w, http.StatusBadRequest, "malformed_request", "The request is not valid", nil)
	default:
		problem(w, http.StatusInternalServerError, "server_error", "Internal error", nil)
	}
}

func (h *IssuanceHandler) token(w http.ResponseWriter, r *http.Request) {
	if !h.ready() {
		oauthError(w, http.StatusServiceUnavailable, "server_error")
		return
	}
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/x-www-form-urlencoded") {
		oauthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTokenBody)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	for _, values := range r.PostForm {
		if len(values) != 1 {
			oauthError(w, http.StatusBadRequest, "invalid_request")
			return
		}
	}
	switch r.PostForm.Get("grant_type") {
	case "client_credentials":
		var scopes []string
		if scope := strings.TrimSpace(r.PostForm.Get("scope")); scope != "" {
			scopes = strings.Fields(scope)
		}
		resp, err := h.Service.ClientCredentialsToken(r.PostForm.Get("client_id"), r.PostForm.Get("client_secret"), scopes)
		switch {
		case errors.Is(err, issuance.ErrClientUnauthorized):
			oauthError(w, http.StatusUnauthorized, "invalid_client")
		case err != nil:
			oauthError(w, http.StatusBadRequest, "invalid_request")
		default:
			writeJSON(w, http.StatusOK, "application/json", resp)
		}
	case issuance.PreAuthorizedGrantType:
		resp, err := h.Service.PreAuthorizedToken(r.PostForm.Get("pre-authorized_code"))
		switch {
		case errors.Is(err, issuance.ErrInvalidGrant):
			oauthError(w, http.StatusBadRequest, "invalid_grant")
		case err != nil:
			oauthError(w, http.StatusBadRequest, "invalid_request")
		default:
			writeJSON(w, http.StatusOK, "application/json", resp)
		}
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type")
	}
}

func (h *IssuanceHandler) authorizationServer(w http.ResponseWriter, _ *http.Request) {
	if !h.ready() {
		oauthError(w, http.StatusServiceUnavailable, "server_error")
		return
	}
	body, err := json.Marshal(h.Service.AuthorizationServer())
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error")
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

func (h *IssuanceHandler) validSlug(w http.ResponseWriter, r *http.Request) (string, bool) {
	if !h.ready() {
		oauthError(w, http.StatusServiceUnavailable, "server_error")
		return "", false
	}
	slug := r.PathValue("slug")
	if issuance.ValidateIssuerIdentifier(issuance.IssuerPrefix+slug) != nil {
		oauthError(w, http.StatusNotFound, "not_found")
		return "", false
	}
	return slug, true
}

func (h *IssuanceHandler) offer(w http.ResponseWriter, r *http.Request) {
	slug, ok := h.validSlug(w, r)
	if !ok {
		return
	}
	offer, err := h.Service.ResolveOffer(slug, r.PathValue("ref"))
	if err != nil {
		oauthError(w, http.StatusNotFound, "not_found")
		return
	}
	writeJSON(w, http.StatusOK, "application/json", offer)
}

func (h *IssuanceHandler) statusList(w http.ResponseWriter, r *http.Request) {
	slug, ok := h.validSlug(w, r)
	if !ok {
		return
	}
	jwt, err := h.Service.ResolveStatusList(slug, r.PathValue("purpose"), r.PathValue("listId"))
	if err != nil {
		oauthError(w, http.StatusNotFound, "not_found")
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=60")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", issuance.CredentialFormat)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(jwt))
}

func (h *IssuanceHandler) nonce(w http.ResponseWriter, r *http.Request) {
	slug, ok := h.validSlug(w, r)
	if !ok {
		return
	}
	nonce, err := h.Service.IssueNonce(slug)
	if err != nil {
		oauthError(w, http.StatusNotFound, "not_found")
		return
	}
	writeJSON(w, http.StatusOK, "application/json", map[string]string{"c_nonce": nonce})
}

func (h *IssuanceHandler) credential(w http.ResponseWriter, r *http.Request) {
	slug, ok := h.validSlug(w, r)
	if !ok {
		return
	}
	raw, ok := bearer(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		oauthError(w, http.StatusUnauthorized, "invalid_token")
		return
	}
	var req issuance.CredentialRequest
	// OpenID4VCI may add parameters, so unknown members are tolerated here.
	if !isJSON(r) || decodeBody(w, r, maxCredentialBody, &req, false) != nil {
		oauthError(w, http.StatusBadRequest, "invalid_credential_request")
		return
	}
	jws, err := h.Service.IssueCredential(slug, raw, req)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, "application/json", map[string]any{
			"credentials": []map[string]string{{"credential": jws}},
		})
	case errors.Is(err, issuance.ErrInvalidToken):
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		oauthError(w, http.StatusUnauthorized, "invalid_token")
	case errors.Is(err, issuance.ErrUnknownCredentialIdentifier):
		oauthError(w, http.StatusBadRequest, "unknown_credential_identifier")
	case errors.Is(err, issuance.ErrProofInvalid):
		oauthError(w, http.StatusBadRequest, "invalid_proof")
	case errors.Is(err, issuance.ErrInvalidNonce):
		oauthError(w, http.StatusBadRequest, "invalid_nonce")
	case errors.Is(err, issuance.ErrInvalidRequest),
		errors.Is(err, issuance.ErrDefinitionUnavailable),
		errors.Is(err, issuance.ErrDefinitionNotFound):
		oauthError(w, http.StatusBadRequest, "invalid_credential_request")
	case errors.Is(err, issuance.ErrResourceNotFound):
		oauthError(w, http.StatusNotFound, "not_found")
	case errors.Is(err, issuance.ErrNoActiveKey):
		oauthError(w, http.StatusServiceUnavailable, "server_error")
	default:
		oauthError(w, http.StatusInternalServerError, "server_error")
	}
}
