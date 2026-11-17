package privateapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"hukid.local/platform/internal/audit"
	a "hukid.local/platform/internal/authentication"
	"hukid.local/platform/internal/issuance"
	"hukid.local/platform/internal/tenancy"
)

var adminIdempotencyRe = regexp.MustCompile(`^[A-Za-z0-9._:-]{16,128}$`)

// IssuanceAdminHandler exposes Bearer-protected Phase 1–2 administrative HTTP
// APIs under /v1/operator/tenants/{tenantId}/... gated by capabilities.json
// and step-up MFA for mutations.
type IssuanceAdminHandler struct {
	Operators *Handler
	Verifier  InvitationVerifier
	Service   *issuance.Service
	Now       func() time.Time
}

type adminIssuerDTO struct {
	IssuerID    string               `json:"issuerId"`
	TenantID    string               `json:"tenantId"`
	Slug        string               `json:"slug"`
	IssuerURI   string               `json:"issuerUri"`
	DisplayName string               `json:"displayName"`
	State       issuance.IssuerState `json:"state"`
	CreatedAt   time.Time            `json:"createdAt"`
}

type adminDefinitionDTO struct {
	TenantID               string                        `json:"tenantId"`
	IssuerID               string                        `json:"issuerId"`
	ID                     string                        `json:"id"`
	Version                string                        `json:"version"`
	ConfigurationID        string                        `json:"configurationId"`
	DisplayName            string                        `json:"displayName"`
	Locale                 string                        `json:"locale"`
	Contexts               []string                      `json:"contexts"`
	Types                  []string                      `json:"types"`
	Fields                 map[string]issuance.FieldSpec `json:"fields"`
	DefaultValiditySeconds int64                         `json:"defaultValiditySeconds"`
	StatusPurposes         []string                      `json:"statusPurposes,omitempty"`
	PublishSchema          bool                          `json:"publishSchema,omitempty"`
	State                  issuance.DefinitionState      `json:"state"`
	Hash                   string                        `json:"hash,omitempty"`
	ETag                   string                        `json:"etag"`
	CreatedAt              time.Time                     `json:"createdAt"`
	PublishedAt            *time.Time                    `json:"publishedAt,omitempty"`
	RetiredAt              *time.Time                    `json:"retiredAt,omitempty"`
}

type adminAuditDTO struct {
	EventID       string    `json:"eventId"`
	TenantID      string    `json:"tenantId"`
	ActorID       string    `json:"actorId"`
	Action        string    `json:"action"`
	TargetID      string    `json:"targetId"`
	Outcome       string    `json:"outcome"`
	CorrelationID string    `json:"correlationId"`
	OccurredAt    time.Time `json:"occurredAt"`
}

// Register wires all administrative issuance routes into mux.
func (h *IssuanceAdminHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/v1/operator/tenants/{tenantId}/issuers", h.serveIssuers)
	mux.HandleFunc("/v1/operator/tenants/{tenantId}/issuance-requests", h.serveOperatorRequests)
	mux.HandleFunc("/v1/operator/tenants/{tenantId}/credentials", h.serveOperatorCredentials)
	mux.HandleFunc("/v1/operator/tenants/{tenantId}/issuers/{issuerId}/keys/rotate", h.serveRotateKey)
	mux.HandleFunc("/v1/operator/tenants/{tenantId}/issuers/{issuerId}/keys/{kid}/compromise", h.serveCompromiseKey)
	mux.HandleFunc("/v1/operator/tenants/{tenantId}/issuers/{issuerId}/credential-definitions", h.serveDefinitions)
	mux.HandleFunc("/v1/operator/tenants/{tenantId}/issuers/{issuerId}/credential-definitions/{definitionId}/versions/{version}", h.serveDefinitionVersion)
	mux.HandleFunc("/v1/operator/tenants/{tenantId}/issuers/{issuerId}/credential-definitions/{definitionId}/versions/{version}/publish", h.servePublishDefinition)
	mux.HandleFunc("/v1/operator/tenants/{tenantId}/issuers/{issuerId}/credential-definitions/{definitionId}/versions/{version}/retire", h.serveRetireDefinition)
	mux.HandleFunc("/v1/operator/tenants/{tenantId}/clients", h.serveClients)
	mux.HandleFunc("/v1/operator/tenants/{tenantId}/clients/{clientId}/rotate-secret", h.serveRotateClientSecret)
	mux.HandleFunc("/v1/operator/tenants/{tenantId}/clients/{clientId}/revoke", h.serveRevokeClient)
	mux.HandleFunc("/v1/operator/tenants/{tenantId}/audit", h.serveAudit)
	mux.HandleFunc("/v1/operator/tenants/{tenantId}/issuance-audit", h.serveAudit)
}

func (h *IssuanceAdminHandler) operatorListFilter(w http.ResponseWriter, r *http.Request, opCtx tenancy.Context) (issuance.AdminListFilter, bool) {
	q := r.URL.Query()
	for k, values := range q {
		if (k != "issuerId" && k != "limit" && k != "offset") || len(values) != 1 {
			writeProblem(w, http.StatusBadRequest, "invalid_request", "Parámetro de consulta no soportado o duplicado")
			return issuance.AdminListFilter{}, false
		}
	}
	filter := issuance.AdminListFilter{Limit: 50}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 100 {
			writeProblem(w, http.StatusUnprocessableEntity, "invalid_input", "limit debe estar entre 1 y 100")
			return filter, false
		}
		filter.Limit = n
	}
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 1_000_000 {
			writeProblem(w, http.StatusUnprocessableEntity, "invalid_input", "offset fuera de rango")
			return filter, false
		}
		filter.Offset = n
	}
	filter.IssuerID = q.Get("issuerId")
	if slices.Contains(opCtx.Roles, "issuer_operator") && !slices.Contains(opCtx.Capabilities, "issuance:read") {
		writeProblem(w, http.StatusForbidden, "forbidden", "No autorizado")
		return filter, false
	}
	if slices.Contains(opCtx.Roles, "issuer_operator") {
		if filter.IssuerID == "" || !slices.Contains(opCtx.IssuerIDs, filter.IssuerID) {
			writeProblem(w, http.StatusForbidden, "forbidden", "No autorizado para este emisor")
			return filter, false
		}
	}
	return filter, true
}

func (h *IssuanceAdminHandler) serveOperatorRequests(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		prepareAdminHeaders(w, r)
		rejectMethod(w, http.MethodGet)
		return
	}
	_, _, opCtx, _, ok := h.authRead(w, r)
	if !ok {
		return
	}
	if !slices.Contains(opCtx.Capabilities, "issuance:read") {
		issuanceAdminProblem(w, tenancy.ErrDirectoryForbidden)
		return
	}
	filter, ok := h.operatorListFilter(w, r, opCtx)
	if !ok {
		return
	}
	items, err := h.Service.ListOperatorRequests(opCtx.TenantID, filter)
	if err != nil {
		issuanceAdminProblem(w, err)
		return
	}
	JSON(w, map[string]any{"items": items, "limit": filter.Limit, "offset": filter.Offset})
}

func (h *IssuanceAdminHandler) serveOperatorCredentials(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		prepareAdminHeaders(w, r)
		rejectMethod(w, http.MethodGet)
		return
	}
	_, _, opCtx, _, ok := h.authRead(w, r)
	if !ok {
		return
	}
	if !slices.Contains(opCtx.Capabilities, "issuance:read") {
		issuanceAdminProblem(w, tenancy.ErrDirectoryForbidden)
		return
	}
	filter, ok := h.operatorListFilter(w, r, opCtx)
	if !ok {
		return
	}
	items, err := h.Service.ListOperatorCredentials(opCtx.TenantID, filter)
	if err != nil {
		issuanceAdminProblem(w, err)
		return
	}
	JSON(w, map[string]any{"items": items, "limit": filter.Limit, "offset": filter.Offset})
}

func (h *IssuanceAdminHandler) now() time.Time {
	if h.Now != nil {
		return h.Now().UTC()
	}
	return time.Now().UTC()
}

func (h *IssuanceAdminHandler) stepUpVerifier() InvitationVerifier {
	if h.Verifier != nil {
		return h.Verifier
	}
	if h.Operators != nil && h.Operators.Verifier != nil {
		if v, ok := h.Operators.Verifier.(InvitationVerifier); ok {
			return v
		}
	}
	return nil
}

func prepareAdminHeaders(w http.ResponseWriter, r *http.Request) (string, bool) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	id := audit.Correlation(r.Context())
	if id == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			InvitationProblem(w, a.ErrDependency, true)
			return "", false
		}
		id = hex.EncodeToString(b)
	}
	w.Header().Set("X-Correlation-Id", id)
	return id, true
}

func rejectMethod(w http.ResponseWriter, allow ...string) {
	w.Header().Set("Allow", strings.Join(allow, ", "))
	writeProblem(w, http.StatusMethodNotAllowed, "invalid_request", "Método no permitido")
}

func (h *IssuanceAdminHandler) authRead(w http.ResponseWriter, r *http.Request) (context.Context, tenancy.Identity, tenancy.Context, string, bool) {
	corrID, ok := prepareAdminHeaders(w, r)
	if !ok {
		return nil, tenancy.Identity{}, tenancy.Context{}, "", false
	}
	if h.Operators == nil || h.Operators.Verifier == nil || h.Operators.Tenancy == nil || h.Service == nil {
		InvitationProblem(w, a.ErrDependency, true)
		return nil, tenancy.Identity{}, tenancy.Context{}, "", false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	raw, err := Bearer(r)
	if err != nil {
		cancel()
		issuanceAdminProblem(w, err)
		return nil, tenancy.Identity{}, tenancy.Context{}, "", false
	}
	operator, err := h.Operators.Verifier.VerifyOperator(ctx, raw)
	if err != nil {
		cancel()
		issuanceAdminProblem(w, err)
		return nil, tenancy.Identity{}, tenancy.Context{}, "", false
	}
	identity, opCtx, err := h.resolveContext(ctx, operator, r.PathValue("tenantId"))
	if err != nil {
		cancel()
		issuanceAdminProblem(w, err)
		return nil, tenancy.Identity{}, tenancy.Context{}, "", false
	}
	ctx = audit.WithCorrelation(ctx, corrID)
	goCancelOnDone(ctx, cancel)
	return ctx, identity, opCtx, corrID, true
}

func (h *IssuanceAdminHandler) authWrite(w http.ResponseWriter, r *http.Request, capability string, requireIdem bool) (context.Context, tenancy.Identity, tenancy.Context, string, bool) {
	corrID, ok := prepareAdminHeaders(w, r)
	if !ok {
		return nil, tenancy.Identity{}, tenancy.Context{}, "", false
	}
	verifier := h.stepUpVerifier()
	if verifier == nil || h.Operators == nil || h.Operators.Tenancy == nil || h.Service == nil {
		InvitationProblem(w, a.ErrDependency, true)
		return nil, tenancy.Identity{}, tenancy.Context{}, "", false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	raw, err := Bearer(r)
	if err != nil {
		cancel()
		issuanceAdminProblem(w, err)
		return nil, tenancy.Identity{}, tenancy.Context{}, "", false
	}
	operator, deadline, err := verifier.VerifyInvitationOperator(ctx, raw)
	if err != nil {
		cancel()
		issuanceAdminProblem(w, err)
		return nil, tenancy.Identity{}, tenancy.Context{}, "", false
	}
	if !h.now().Before(deadline) {
		cancel()
		issuanceAdminProblem(w, a.ErrStepUp)
		return nil, tenancy.Identity{}, tenancy.Context{}, "", false
	}
	identity, opCtx, err := h.resolveContext(ctx, operator, r.PathValue("tenantId"))
	if err != nil {
		cancel()
		issuanceAdminProblem(w, err)
		return nil, tenancy.Identity{}, tenancy.Context{}, "", false
	}
	if !slices.Contains(opCtx.Capabilities, capability) {
		cancel()
		issuanceAdminProblem(w, tenancy.ErrDirectoryForbidden)
		return nil, tenancy.Identity{}, tenancy.Context{}, "", false
	}
	if requireIdem {
		keys := r.Header.Values("Idempotency-Key")
		if len(keys) != 1 || !adminIdempotencyRe.MatchString(keys[0]) {
			cancel()
			writeProblem(w, http.StatusBadRequest, "invalid_request", "Idempotency-Key inválido o ausente")
			return nil, tenancy.Identity{}, tenancy.Context{}, "", false
		}
	}
	ctx = audit.WithCorrelation(ctx, corrID)
	goCancelOnDone(ctx, cancel)
	return ctx, identity, opCtx, corrID, true
}

func goCancelOnDone(ctx context.Context, cancel context.CancelFunc) {
	context.AfterFunc(ctx, cancel)
}

func (h *IssuanceAdminHandler) resolveContext(ctx context.Context, operator a.Operator, tenantID string) (tenancy.Identity, tenancy.Context, error) {
	identity, err := h.Operators.Tenancy.Me(ctx, operator)
	if err != nil {
		return tenancy.Identity{}, tenancy.Context{}, err
	}
	opCtx, err := h.Operators.Tenancy.Context(ctx, identity.ActorID, tenantID)
	if err != nil {
		return tenancy.Identity{}, tenancy.Context{}, err
	}
	return identity, opCtx, nil
}

func decodeStrictAdminJSON(w http.ResponseWriter, r *http.Request, dest any, maxBytes int64) bool {
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "Solicitud inválida")
		return false
	}
	media, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || len(params) > 0 {
		writeProblem(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "Se requiere JSON")
		return false
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBytes))
	d.DisallowUnknownFields()
	if err := d.Decode(dest); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "JSON inválido")
		return false
	}
	if err := d.Decode(new(any)); err != io.EOF {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "JSON inválido")
		return false
	}
	return true
}

func (h *IssuanceAdminHandler) serveIssuers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		_, _, opCtx, _, ok := h.authRead(w, r)
		if !ok {
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			writeProblem(w, http.StatusBadRequest, "invalid_request", "Solicitud inválida")
			return
		}
		canManage := slices.Contains(opCtx.Capabilities, "issuers:manage")
		isIssuerOp := slices.Contains(opCtx.Roles, "issuer_operator") && len(opCtx.IssuerIDs) > 0
		if !canManage && !isIssuerOp {
			issuanceAdminProblem(w, tenancy.ErrDirectoryForbidden)
			return
		}
		all, err := h.Service.ListIssuers(opCtx.TenantID)
		if err != nil {
			issuanceAdminProblem(w, err)
			return
		}
		items := make([]adminIssuerDTO, 0, len(all))
		for _, rec := range all {
			if !canManage && !slices.Contains(opCtx.IssuerIDs, rec.IssuerID) {
				continue
			}
			items = append(items, toIssuerDTO(rec))
		}
		JSON(w, map[string]any{"items": items})

	case http.MethodPost:
		_, identity, opCtx, corrID, ok := h.authWrite(w, r, "issuers:manage", true)
		if !ok {
			return
		}
		var req struct {
			IssuerID    string `json:"issuerId"`
			Slug        string `json:"slug"`
			DisplayName string `json:"displayName"`
			InitialKID  string `json:"initialKid"`
		}
		if !decodeStrictAdminJSON(w, r, &req, 16<<10) {
			return
		}
		rec, jwk, err := h.Service.CreateIssuer(opCtx.TenantID, req.IssuerID, req.Slug, req.DisplayName, req.InitialKID, identity.ActorID, corrID)
		if err != nil {
			issuanceAdminProblem(w, err)
			return
		}
		resp := map[string]any{"issuer": toIssuerDTO(rec)}
		if req.InitialKID != "" {
			resp["activeKey"] = jwk
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(resp)

	default:
		prepareAdminHeaders(w, r)
		rejectMethod(w, http.MethodGet, http.MethodPost)
	}
}

func (h *IssuanceAdminHandler) serveRotateKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		prepareAdminHeaders(w, r)
		rejectMethod(w, http.MethodPost)
		return
	}
	_, identity, opCtx, corrID, ok := h.authWrite(w, r, "issuers:manage", true)
	if !ok {
		return
	}
	var req struct {
		KID string `json:"kid"`
	}
	if !decodeStrictAdminJSON(w, r, &req, 8<<10) {
		return
	}
	jwk, err := h.Service.ProvisionAndRotateIssuerKey(opCtx.TenantID, r.PathValue("issuerId"), req.KID, identity.ActorID, corrID)
	if err != nil {
		issuanceAdminProblem(w, err)
		return
	}
	JSON(w, map[string]any{"activeKey": jwk})
}

func (h *IssuanceAdminHandler) serveCompromiseKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		prepareAdminHeaders(w, r)
		rejectMethod(w, http.MethodPost)
		return
	}
	_, identity, opCtx, corrID, ok := h.authWrite(w, r, "issuers:manage", true)
	if !ok {
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "Solicitud inválida")
		return
	}
	report, err := h.Service.CompromiseIssuerKey(opCtx.TenantID, r.PathValue("issuerId"), r.PathValue("kid"), identity.ActorID, corrID)
	if err != nil {
		issuanceAdminProblem(w, err)
		return
	}
	JSON(w, report)
}

type adminDefinitionBody struct {
	ID                     string                        `json:"id"`
	Version                string                        `json:"version"`
	ConfigurationID        string                        `json:"configurationId"`
	DisplayName            string                        `json:"displayName"`
	Locale                 string                        `json:"locale"`
	Contexts               []string                      `json:"contexts"`
	Types                  []string                      `json:"types"`
	Fields                 map[string]issuance.FieldSpec `json:"fields"`
	DefaultValiditySeconds int64                         `json:"defaultValiditySeconds"`
	StatusPurposes         []string                      `json:"statusPurposes"`
	PublishSchema          bool                          `json:"publishSchema"`
}

func (h *IssuanceAdminHandler) serveDefinitions(w http.ResponseWriter, r *http.Request) {
	issuerID := r.PathValue("issuerId")
	switch r.Method {
	case http.MethodGet:
		_, _, opCtx, _, ok := h.authRead(w, r)
		if !ok {
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			writeProblem(w, http.StatusBadRequest, "invalid_request", "Solicitud inválida")
			return
		}
		if !canAccessIssuerDefinitions(opCtx, issuerID) {
			issuanceAdminProblem(w, tenancy.ErrDirectoryForbidden)
			return
		}
		defs, err := h.Service.ListDefinitions(opCtx.TenantID, issuerID)
		if err != nil {
			issuanceAdminProblem(w, err)
			return
		}
		items := make([]adminDefinitionDTO, 0, len(defs))
		for _, d := range defs {
			items = append(items, toDefinitionDTO(d))
		}
		JSON(w, map[string]any{"items": items})

	case http.MethodPost:
		_, identity, opCtx, corrID, ok := h.authWrite(w, r, "definitions:manage", true)
		if !ok {
			return
		}
		var req adminDefinitionBody
		if !decodeStrictAdminJSON(w, r, &req, 64<<10) {
			return
		}
		if req.DefaultValiditySeconds < 0 {
			issuanceAdminProblem(w, issuance.ErrInvalidFoundationInput)
			return
		}
		def := issuance.Definition{
			TenantID:        opCtx.TenantID,
			IssuerID:        issuerID,
			ID:              req.ID,
			Version:         req.Version,
			ConfigurationID: req.ConfigurationID,
			DisplayName:     req.DisplayName,
			Locale:          req.Locale,
			Contexts:        req.Contexts,
			Types:           req.Types,
			Fields:          req.Fields,
			DefaultValidity: time.Duration(req.DefaultValiditySeconds) * time.Second,
			StatusPurposes:  req.StatusPurposes,
			PublishSchema:   req.PublishSchema,
		}
		created, err := h.Service.CreateDraftDefinition(def, identity.ActorID, corrID)
		if err != nil {
			issuanceAdminProblem(w, err)
			return
		}
		dto := toDefinitionDTO(created)
		w.Header().Set("ETag", dto.ETag)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(dto)

	default:
		prepareAdminHeaders(w, r)
		rejectMethod(w, http.MethodGet, http.MethodPost)
	}
}

func (h *IssuanceAdminHandler) serveDefinitionVersion(w http.ResponseWriter, r *http.Request) {
	issuerID := r.PathValue("issuerId")
	defID := r.PathValue("definitionId")
	version := r.PathValue("version")
	switch r.Method {
	case http.MethodGet:
		_, _, opCtx, _, ok := h.authRead(w, r)
		if !ok {
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			writeProblem(w, http.StatusBadRequest, "invalid_request", "Solicitud inválida")
			return
		}
		if !canAccessIssuerDefinitions(opCtx, issuerID) {
			issuanceAdminProblem(w, tenancy.ErrDirectoryForbidden)
			return
		}
		d, err := h.Service.GetDefinition(opCtx.TenantID, issuerID, defID, version)
		if err != nil {
			issuanceAdminProblem(w, err)
			return
		}
		dto := toDefinitionDTO(d)
		w.Header().Set("ETag", dto.ETag)
		JSON(w, dto)

	case http.MethodPut:
		_, identity, opCtx, corrID, ok := h.authWrite(w, r, "definitions:manage", false)
		if !ok {
			return
		}
		ifMatch := r.Header.Values("If-Match")
		if len(ifMatch) == 0 {
			writeProblem(w, http.StatusPreconditionRequired, "precondition_required", "Se requiere ETag en If-Match")
			return
		}
		if len(ifMatch) != 1 || strings.TrimSpace(ifMatch[0]) == "" {
			issuanceAdminProblem(w, issuance.ErrETagMismatch)
			return
		}
		var req adminDefinitionBody
		if !decodeStrictAdminJSON(w, r, &req, 64<<10) {
			return
		}
		if req.DefaultValiditySeconds < 0 ||
			(req.ID != "" && req.ID != defID) ||
			(req.Version != "" && req.Version != version) {
			issuanceAdminProblem(w, issuance.ErrInvalidFoundationInput)
			return
		}
		def := issuance.Definition{
			TenantID:        opCtx.TenantID,
			IssuerID:        issuerID,
			ID:              defID,
			Version:         version,
			ConfigurationID: req.ConfigurationID,
			DisplayName:     req.DisplayName,
			Locale:          req.Locale,
			Contexts:        req.Contexts,
			Types:           req.Types,
			Fields:          req.Fields,
			DefaultValidity: time.Duration(req.DefaultValiditySeconds) * time.Second,
			StatusPurposes:  req.StatusPurposes,
			PublishSchema:   req.PublishSchema,
		}
		updated, err := h.Service.ReplaceDraftDefinition(def, strings.TrimSpace(ifMatch[0]), identity.ActorID, corrID)
		if err != nil {
			issuanceAdminProblem(w, err)
			return
		}
		dto := toDefinitionDTO(updated)
		w.Header().Set("ETag", dto.ETag)
		JSON(w, dto)

	default:
		prepareAdminHeaders(w, r)
		rejectMethod(w, http.MethodGet, http.MethodPut)
	}
}

func (h *IssuanceAdminHandler) servePublishDefinition(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		prepareAdminHeaders(w, r)
		rejectMethod(w, http.MethodPost)
		return
	}
	_, identity, opCtx, corrID, ok := h.authWrite(w, r, "definitions:manage", true)
	if !ok {
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "Solicitud inválida")
		return
	}
	pub, err := h.Service.PublishDefinition(opCtx.TenantID, r.PathValue("issuerId"), r.PathValue("definitionId"), r.PathValue("version"), identity.ActorID, corrID)
	if err != nil {
		issuanceAdminProblem(w, err)
		return
	}
	dto := toDefinitionDTO(pub)
	w.Header().Set("ETag", dto.ETag)
	JSON(w, dto)
}

func (h *IssuanceAdminHandler) serveRetireDefinition(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		prepareAdminHeaders(w, r)
		rejectMethod(w, http.MethodPost)
		return
	}
	_, identity, opCtx, corrID, ok := h.authWrite(w, r, "definitions:manage", true)
	if !ok {
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "Solicitud inválida")
		return
	}
	ret, err := h.Service.RetireDefinition(opCtx.TenantID, r.PathValue("issuerId"), r.PathValue("definitionId"), r.PathValue("version"), identity.ActorID, corrID)
	if err != nil {
		issuanceAdminProblem(w, err)
		return
	}
	dto := toDefinitionDTO(ret)
	w.Header().Set("ETag", dto.ETag)
	JSON(w, dto)
}

func (h *IssuanceAdminHandler) serveClients(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		_, _, opCtx, _, ok := h.authRead(w, r)
		if !ok {
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			writeProblem(w, http.StatusBadRequest, "invalid_request", "Solicitud inválida")
			return
		}
		if !slices.Contains(opCtx.Capabilities, "clients:manage") {
			issuanceAdminProblem(w, tenancy.ErrDirectoryForbidden)
			return
		}
		items, err := h.Service.ListIntegrationClients(opCtx.TenantID)
		if err != nil {
			issuanceAdminProblem(w, err)
			return
		}
		JSON(w, map[string]any{"items": items})

	case http.MethodPost:
		_, identity, opCtx, corrID, ok := h.authWrite(w, r, "clients:manage", true)
		if !ok {
			return
		}
		var req struct {
			ClientID       string     `json:"clientId"`
			ClientName     string     `json:"clientName"`
			AllowedIssuers []string   `json:"allowedIssuers"`
			Scopes         []string   `json:"scopes"`
			ExpiresAt      *time.Time `json:"expiresAt"`
		}
		if !decodeStrictAdminJSON(w, r, &req, 16<<10) {
			return
		}
		summary, rawSecret, err := h.Service.RegisterIntegrationClient(
			opCtx.TenantID, req.ClientID, req.ClientName, "", req.AllowedIssuers, req.Scopes, req.ExpiresAt, identity.ActorID, corrID,
		)
		if err != nil {
			issuanceAdminProblem(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client":       summary,
			"clientSecret": rawSecret,
		})

	default:
		prepareAdminHeaders(w, r)
		rejectMethod(w, http.MethodGet, http.MethodPost)
	}
}

func (h *IssuanceAdminHandler) serveRotateClientSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		prepareAdminHeaders(w, r)
		rejectMethod(w, http.MethodPost)
		return
	}
	_, identity, opCtx, corrID, ok := h.authWrite(w, r, "clients:manage", true)
	if !ok {
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "Solicitud inválida")
		return
	}
	clientID := r.PathValue("clientId")
	newSecret, err := h.Service.RotateIntegrationClientSecret(opCtx.TenantID, clientID, "", identity.ActorID, corrID)
	if err != nil {
		issuanceAdminProblem(w, err)
		return
	}
	JSON(w, map[string]any{
		"clientId":     clientID,
		"clientSecret": newSecret,
	})
}

func (h *IssuanceAdminHandler) serveRevokeClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		prepareAdminHeaders(w, r)
		rejectMethod(w, http.MethodPost)
		return
	}
	_, identity, opCtx, corrID, ok := h.authWrite(w, r, "clients:manage", true)
	if !ok {
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "Solicitud inválida")
		return
	}
	clientID := r.PathValue("clientId")
	if err := h.Service.RevokeIntegrationClient(opCtx.TenantID, clientID, identity.ActorID, corrID); err != nil {
		issuanceAdminProblem(w, err)
		return
	}
	JSON(w, map[string]any{
		"clientId": clientID,
		"state":    issuance.ClientRevoked,
	})
}

func (h *IssuanceAdminHandler) serveAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		prepareAdminHeaders(w, r)
		rejectMethod(w, http.MethodGet)
		return
	}
	_, _, opCtx, _, ok := h.authRead(w, r)
	if !ok {
		return
	}
	if !slices.Contains(opCtx.Capabilities, "audit:read") {
		issuanceAdminProblem(w, tenancy.ErrDirectoryForbidden)
		return
	}
	q := r.URL.Query()
	for k := range q {
		if k != "action" {
			writeProblem(w, http.StatusBadRequest, "invalid_request", "Parámetro de consulta no soportado")
			return
		}
	}
	actionFilter := ""
	if vals := q["action"]; len(vals) > 1 {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "Parámetro duplicado")
		return
	} else if len(vals) == 1 {
		actionFilter = vals[0]
		if len(actionFilter) > 128 || strings.ContainsAny(actionFilter, " \t\r\n") {
			writeProblem(w, http.StatusUnprocessableEntity, "invalid_input", "Filtro inválido")
			return
		}
	}
	records, err := h.Service.ListAuditEvents(opCtx.TenantID, actionFilter)
	if err != nil {
		issuanceAdminProblem(w, err)
		return
	}
	items := make([]adminAuditDTO, 0, len(records))
	for _, rec := range records {
		items = append(items, adminAuditDTO{
			EventID:       rec.EventID,
			TenantID:      rec.TenantID,
			ActorID:       rec.ActorID,
			Action:        rec.Action,
			TargetID:      rec.TargetID,
			Outcome:       rec.Outcome,
			CorrelationID: rec.CorrelationID,
			OccurredAt:    rec.OccurredAt,
		})
	}
	JSON(w, map[string]any{"items": items})
}

func canAccessIssuerDefinitions(opCtx tenancy.Context, issuerID string) bool {
	if slices.Contains(opCtx.Capabilities, "definitions:manage") {
		return true
	}
	return slices.Contains(opCtx.Roles, "issuer_operator") && slices.Contains(opCtx.IssuerIDs, issuerID)
}

func toIssuerDTO(rec issuance.IssuerRecord) adminIssuerDTO {
	return adminIssuerDTO{
		IssuerID:    rec.IssuerID,
		TenantID:    rec.TenantID,
		Slug:        rec.Slug,
		IssuerURI:   rec.IssuerURI,
		DisplayName: rec.DisplayName,
		State:       rec.State,
		CreatedAt:   rec.CreatedAt,
	}
}

func toDefinitionDTO(d issuance.Definition) adminDefinitionDTO {
	ctxSlice := slices.Clone(d.Contexts)
	if ctxSlice == nil {
		ctxSlice = []string{}
	}
	return adminDefinitionDTO{
		TenantID:               d.TenantID,
		IssuerID:               d.IssuerID,
		ID:                     d.ID,
		Version:                d.Version,
		ConfigurationID:        d.ConfigurationID,
		DisplayName:            d.DisplayName,
		Locale:                 d.Locale,
		Contexts:               ctxSlice,
		Types:                  slices.Clone(d.Types),
		Fields:                 d.Fields,
		DefaultValiditySeconds: int64(d.DefaultValidity / time.Second),
		StatusPurposes:         slices.Clone(d.StatusPurposes),
		PublishSchema:          d.PublishSchema,
		State:                  d.State,
		Hash:                   d.Hash,
		ETag:                   issuance.DefinitionETag(d),
		CreatedAt:              d.CreatedAt,
		PublishedAt:            d.PublishedAt,
		RetiredAt:              d.RetiredAt,
	}
}

func issuanceAdminProblem(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, issuance.ErrETagMismatch):
		writeProblem(w, http.StatusPreconditionFailed, "etag_mismatch", "La versión del recurso ha cambiado")
	case errors.Is(err, issuance.ErrDefinitionImmutable):
		writeProblem(w, http.StatusConflict, "definition_immutable", "La definición publicada o retirada es inmutable")
	case errors.Is(err, issuance.ErrDefinitionConflict):
		writeProblem(w, http.StatusConflict, "definition_conflict", "La definición o configurationId ya existe")
	case errors.Is(err, issuance.ErrKeyConflict):
		writeProblem(w, http.StatusConflict, "key_conflict", "Conflicto con kid de firma")
	case errors.Is(err, issuance.ErrDefinitionNotFound), errors.Is(err, issuance.ErrResourceNotFound):
		writeProblem(w, http.StatusNotFound, "resource_not_found", "Recurso no encontrado")
	case errors.Is(err, issuance.ErrInvalidFoundationInput), errors.Is(err, issuance.ErrInvalidRequest):
		writeProblem(w, http.StatusUnprocessableEntity, "invalid_input", "Datos inválidos")
	case errors.Is(err, issuance.ErrNoActiveKey), errors.Is(err, issuance.ErrSigningFailed):
		w.Header().Set("Retry-After", "1")
		writeProblem(w, http.StatusServiceUnavailable, "signing_unavailable", "Servicio de firma/KMS no disponible")
	default:
		InvitationProblem(w, err, true)
	}
}
