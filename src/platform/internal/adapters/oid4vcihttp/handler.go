// Package oid4vcihttp exposes the public OpenID4VCI issuer discovery and JWKS
// endpoints for Phase 1 (HK-002, HK-020, profile §3 & §8):
//   - GET /{slug}/.well-known/jwks.json
//   - GET /{slug}/.well-known/openid-credential-issuer
//
// It never logs, never imports internal/authentication and delegates issuer
// lookups to the Catalog port.
package oid4vcihttp

import (
	"encoding/json"
	"net/http"

	"hukid.local/platform/internal/issuance"
)

const (
	// JWKSPathPattern matches GET /{slug}/.well-known/jwks.json.
	JWKSPathPattern = "/{slug}/.well-known/jwks.json"
	// MetadataPathPattern matches GET /{slug}/.well-known/openid-credential-issuer.
	MetadataPathPattern = "/{slug}/.well-known/openid-credential-issuer"
)

// Catalog resolves public JWKS and OID4VCI metadata per logical issuer slug.
type Catalog interface {
	IssuerJWKS(slug string) (issuance.JWKS, bool)
	IssuerMetadata(slug string) (issuance.IssuerMetadata, bool)
}

// Handler serves public JWKS and OID4VCI metadata endpoints for registered issuers.
type Handler struct {
	Catalog Catalog
}

// Routes registers the issuer discovery and JWKS routes on mux without
// catching unrelated paths such as /healthz or /console/*.
func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc(JWKSPathPattern, h.jwks)
	mux.HandleFunc(MetadataPathPattern, h.metadata)
}

func (h *Handler) jwks(w http.ResponseWriter, r *http.Request) {
	slug, ok := h.validateRequest(w, r)
	if !ok {
		return
	}
	doc, found := h.Catalog.IssuerJWKS(slug)
	if !found {
		fail(w, http.StatusNotFound, "issuer_not_found")
		return
	}
	writePublicJSON(w, doc)
}

func (h *Handler) metadata(w http.ResponseWriter, r *http.Request) {
	slug, ok := h.validateRequest(w, r)
	if !ok {
		return
	}
	doc, found := h.Catalog.IssuerMetadata(slug)
	if !found {
		fail(w, http.StatusNotFound, "issuer_not_found")
		return
	}
	writePublicJSON(w, doc)
}

func (h *Handler) validateRequest(w http.ResponseWriter, r *http.Request) (string, bool) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		fail(w, http.StatusMethodNotAllowed, "invalid_request")
		return "", false
	}
	if h == nil || h.Catalog == nil {
		fail(w, http.StatusServiceUnavailable, "server_error")
		return "", false
	}
	slug := r.PathValue("slug")
	if r.URL.RawQuery != "" || issuance.ValidateIssuerIdentifier(issuance.IssuerPrefix+slug) != nil {
		fail(w, http.StatusNotFound, "issuer_not_found")
		return "", false
	}
	return slug, true
}

func fail(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":"` + code + `"}`))
}

func writePublicJSON(w http.ResponseWriter, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		fail(w, http.StatusInternalServerError, "server_error")
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
