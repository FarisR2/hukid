package privateapi

import (
	"encoding/json"
	a "hukid.local/platform/internal/authentication"
	"hukid.local/platform/internal/tenancy"
	"net/http"
	"strconv"
	"time"
)

func (h *InvitationHandler) accept(w http.ResponseWriter, r *http.Request, raw, sessionActor string, bearer bool) {
	operator, err := h.Operators.Verifier.VerifyOperator(r.Context(), raw)
	if err != nil {
		InvitationProblem(w, err, bearer)
		return
	}
	identity, err := h.Operators.Tenancy.Me(r.Context(), operator)
	if err != nil {
		InvitationProblem(w, err, bearer)
		return
	}
	if sessionActor != "" && sessionActor != identity.ActorID {
		InvitationProblem(w, a.ErrSession, bearer)
		return
	}
	proof, err := h.Recipients.Recipient(r.Context(), raw, identity.ActorID, operator, time.Duration(h.Acceptance.Policy.EmailEvidenceSeconds)*time.Second)
	if err != nil {
		InvitationProblem(w, err, bearer)
		return
	}
	keys := r.Header.Values("Idempotency-Key")
	if len(keys) != 1 {
		InvitationProblem(w, tenancy.ErrDirectoryRequest, bearer)
		return
	}
	var input struct {
		Token string `json:"token"`
	}
	if !decodeInvitation(w, r, &input, []string{"token"}) {
		return
	}
	result, err := h.Acceptance.Execute(r.Context(), tenancy.AcceptanceCommand{Actor: identity.ActorID, Key: keys[0], Token: input.Token, Proof: proof})
	if err != nil {
		InvitationProblem(w, err, bearer)
		return
	}
	w.Header().Set("ETag", `"`+strconv.FormatInt(result.Membership.Revision, 10)+`"`)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(result)
}
