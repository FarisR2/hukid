package privateapi

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"hukid.local/platform/internal/tenancy"
)

func (h *InvitationHandler) changeMembership(w http.ResponseWriter, r *http.Request, actor string, deadline time.Time, bearer bool) {
	c := tenancy.MembershipCommand{Actor: actor, Tenant: r.PathValue("tenantId"), MembershipID: r.PathValue("membershipId"), PrivilegeDeadline: deadline}
	keys := r.Header.Values("Idempotency-Key")
	if len(keys) != 1 {
		InvitationProblem(w, tenancy.ErrDirectoryRequest, bearer)
		return
	}
	c.Key = keys[0]
	revisions := r.Header.Values("If-Match")
	if len(revisions) == 0 {
		writeProblem(w, 428, "precondition_required", "Se requiere revisión")
		return
	}
	if len(revisions) != 1 || !regexp.MustCompile(`^"[1-9][0-9]{0,15}"$`).MatchString(revisions[0]) {
		InvitationProblem(w, tenancy.ErrDirectoryRequest, bearer)
		return
	}
	var err error
	c.Revision, err = strconv.ParseInt(revisions[0][1:len(revisions[0])-1], 10, 64)
	if err != nil || c.Revision > 9007199254740991 {
		InvitationProblem(w, tenancy.ErrDirectoryRequest, bearer)
		return
	}
	if !decodeInvitation(w, r, &c.Input, []string{"roles", "issuerIds", "state", "reasonCode"}) {
		return
	}
	result, err := h.Members.Execute(r.Context(), c)
	if err != nil {
		InvitationProblem(w, err, bearer)
		return
	}
	w.Header().Set("ETag", `"`+strconv.FormatInt(result.Revision, 10)+`"`)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}
