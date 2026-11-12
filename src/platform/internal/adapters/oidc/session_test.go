package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"

	a "hukid.local/platform/internal/authentication"
)

func TestRefreshValidatesRotatedTokensAndHistoricalIdentity(t *testing.T) {
	s := newSigningFixture(t)
	for _, name := range []string{"valid", "no_id_token", "expired_old_access", "subject", "auth_time", "amr", "nonce", "missing_nonce", "id_subject", "id_audience", "id_signature", "same_refresh", "invalid_grant", "unavailable", "lost_response", "duplicate_json"} {
		t.Run(name, func(t *testing.T) {
			id, access := s.claims()
			_, old := s.claims()
			if name == "expired_old_access" {
				old["iat"] = s.now.Unix() - 300
				old["exp"] = s.now.Unix()
			}
			switch name {
			case "subject":
				access["sub"] = "other"
			case "auth_time":
				access["auth_time"] = s.now.Unix() - 1
			case "amr":
				access["amr"] = []string{"pwd", "otp", "other"}
			case "nonce":
				id["nonce"] = "other"
			case "missing_nonce":
				delete(id, "nonce")
			case "id_subject":
				id["sub"] = "other"
			case "id_audience":
				id["aud"] = []string{s.policy.ClientID, "other"}
			}
			tokens := map[string]string{"access_token": s.sign(t, access, "at+jwt"), "refresh_token": "next-refresh", "token_type": "Bearer", "id_token": s.sign(t, id, "JWT")}
			if name == "no_id_token" {
				delete(tokens, "id_token")
			}
			if name == "id_signature" {
				tokens["id_token"] += "invalid"
			}
			if name == "same_refresh" {
				tokens["refresh_token"] = "previous-refresh"
			}
			var calls atomic.Int32
			s.mu.Lock()
			s.tokenHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				user, password, ok := r.BasicAuth()
				if r.ParseForm() != nil || !ok || user != s.policy.ClientID || password != "ephemeral-test-client" || r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("resource") != s.policy.Audience || r.Form.Get("refresh_token") != "previous-refresh" {
					t.Error("invalid refresh request")
					w.WriteHeader(400)
					return
				}
				switch name {
				case "invalid_grant":
					w.WriteHeader(400)
					json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
				case "unavailable":
					w.WriteHeader(503)
				case "lost_response":
					connection, _, err := w.(http.Hijacker).Hijack()
					if err == nil {
						connection.Close()
					}
				case "duplicate_json":
					w.Write([]byte(`{"access_token":"a","access_token":"b","token_type":"Bearer","refresh_token":"next-refresh"}`))
				default:
					json.NewEncoder(w).Encode(tokens)
				}
			})
			s.mu.Unlock()
			result, err := s.client.Refresh(context.Background(), s.sign(t, old, "at+jwt"), "previous-refresh", a.Digest("expected-nonce"))
			wantSuccess := name == "valid" || name == "no_id_token" || name == "expired_old_access" || name == "missing_nonce"
			if (err == nil) != wantSuccess {
				t.Fatalf("unexpected refresh result: %v", err)
			}
			if err == nil && (result.Subject != "operator-test" || result.AuthTime.Unix() != s.now.Unix()) {
				t.Fatal("refresh changed original authentication")
			}
			if calls.Load() != 1 {
				t.Fatal("exchange retried or not called")
			}
		})
	}
}
