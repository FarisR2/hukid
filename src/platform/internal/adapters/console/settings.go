package console

import (
	"context"
	"net/http"
	"slices"
	"time"

	"hukid.local/platform/internal/adapters/privateapi"
	"hukid.local/platform/internal/authentication"
	"hukid.local/platform/internal/tenancy"
)

// SettingsHandler exposes read-only active tenant metadata and non-sensitive
// console session policy for tenant_admin operators via GET /console/api/settings.
type SettingsHandler struct {
	Auth                   *MeHandler
	IssuanceRuntimeEnabled bool
}

type consoleSettings struct {
	TenantID               string        `json:"tenantId"`
	DisplayName            string        `json:"displayName"`
	Environment            string        `json:"environment"`
	IssuanceRuntimeEnabled bool          `json:"issuanceRuntimeEnabled"`
	SessionPolicy          sessionPolicy `json:"sessionPolicy"`
}

type sessionPolicy struct {
	AccessTokenSeconds     int      `json:"accessTokenSeconds"`
	SessionIdleSeconds     int      `json:"sessionIdleSeconds"`
	SessionAbsoluteSeconds int      `json:"sessionAbsoluteSeconds"`
	StepUpSeconds          int      `json:"stepUpSeconds"`
	RequiredAMR            []string `json:"requiredAmr"`
	AcceptedACR            []string `json:"acceptedAcr"`
}

// Register mounts the read-only settings BFF route.
func (h *SettingsHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/console/api/settings", h.serve)
}

func (h *SettingsHandler) serve(w http.ResponseWriter, r *http.Request) {
	if !privateapi.Prepare(w, r) {
		return
	}
	if h == nil {
		privateapi.Problem(w, authentication.ErrDependency, false)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	cookie, session, identity, err := h.Auth.authenticate(ctx, r)
	if err != nil {
		privateapi.Problem(w, err, false)
		return
	}
	if session.ActiveTenantID == "" {
		privateapi.Problem(w, authentication.ErrTenant, false)
		return
	}
	tenantIdx := slices.IndexFunc(identity.Tenants, func(t tenancy.Tenant) bool {
		return t.ID == session.ActiveTenantID
	})
	if tenantIdx < 0 {
		privateapi.Problem(w, authentication.ErrTenant, false)
		return
	}
	tenantCtx, err := h.Auth.Tenancy.Context(ctx, identity.ActorID, session.ActiveTenantID)
	if err != nil {
		privateapi.Problem(w, err, false)
		return
	}
	if !slices.Contains(tenantCtx.Roles, "tenant_admin") {
		privateapi.WriteProblem(w, http.StatusForbidden, "forbidden", "Acceso restringido a administración de organización")
		return
	}
	if err := h.Auth.Sessions.Touch(ctx, cookie); err != nil {
		privateapi.Problem(w, err, false)
		return
	}

	policy := h.Auth.Sessions.Policy
	tenant := identity.Tenants[tenantIdx]
	privateapi.JSON(w, consoleSettings{
		TenantID:               tenant.ID,
		DisplayName:            tenant.DisplayName,
		Environment:            policy.Environment,
		IssuanceRuntimeEnabled: h.IssuanceRuntimeEnabled,
		SessionPolicy: sessionPolicy{
			AccessTokenSeconds:     policy.AccessTokenSeconds,
			SessionIdleSeconds:     policy.SessionIdleSeconds,
			SessionAbsoluteSeconds: policy.SessionAbsoluteSeconds,
			StepUpSeconds:          policy.StepUpSeconds,
			RequiredAMR:            nonNilStrings(policy.RequiredAMR),
			AcceptedACR:            nonNilStrings(policy.AcceptedACR),
		},
	})
}

func nonNilStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	return slices.Clone(values)
}
