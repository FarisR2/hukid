# Máquinas de estado normativas

Toda transición se ejecuta como comando autenticado, idempotente y auditado. Cualquier arco no listado devuelve `409 invalid_state_transition`; la eliminación física nunca sustituye un estado de negocio.

| Agregado (owner) | Estados | Transiciones válidas principales |
|---|---|---|
| Organization (T1) | provisioning, active, suspended, archived | provisioning→active; active⇄suspended; active/suspended→archived |
| Membership (T1) | invited, active, suspended, revoked, expired | invited→active/expired/revoked; active⇄suspended; active/suspended→revoked |
| Domain (T1) | pending, verifying, active, failed, suspended, released | pending→verifying→active/failed; active⇄suspended; suspended→released |
| Page publication (T1) | draft, published, superseded | draft→published; published→superseded. Rollback crea publicación nueva |
| Projection release (T1/T3/T4 local) | pending, active, failed, superseded | pending→active/failed; active→superseded; failed→pending por replay |
| Event (T2) | draft, published, closed, cancelled, archived | draft→published; published⇄closed; draft/published/closed→cancelled; closed/cancelled→archived |
| Session (T2) | draft, scheduled, cancelled, completed | draft→scheduled; scheduled→cancelled/completed; cambio horario crea revisión |
| Form version (T2) | draft, published, retired | draft→published; published→retired; publicado es inmutable |
| Form binding (T2) | scheduled, open, closed, cancelled | scheduled→open/cancelled; open→closed/cancelled |
| Registration (T3) | pending_verification, pending_review, waitlisted, confirmed, rejected, cancelled | pending_verification→pending_review/confirmed/waitlisted; pending_review→confirmed/waitlisted/rejected; waitlisted→confirmed/cancelled; confirmed→cancelled |
| Ticket (T3) | active, revoked, expired, replaced | active→revoked/expired/replaced; replaced crea ticket activo nuevo |
| Team invitation (T3) | pending, accepted, declined, expired, revoked | pending→accepted/declined/expired/revoked |
| Team membership (T3) | active, left, removed | active→left/removed; siempre queda un leader antes de submit |
| Application (T3) | draft, submitted, needs_changes, resubmitted, admitted, rejected, withdrawn | draft→submitted/withdrawn; submitted→needs_changes/admitted/rejected/withdrawn; needs_changes→resubmitted/withdrawn; resubmitted→needs_changes/admitted/rejected/withdrawn |
| Application file (T3) | uploading, scanning, ready, quarantined, deleted | uploading→scanning; scanning→ready/quarantined; ready/quarantined→deleted |
| Device (T4) | pending, active, suspended, revoked | pending→active/revoked; active⇄suspended; active/suspended→revoked |
| Shift (T4) | open, closed, force_closed | open→closed/force_closed |
| Attendance (T4) | fold de hechos, no fila mutable | check_in, check_out y void; el estado efectivo se deriva en orden servidor |
| Communication job (T4) | scheduled, queued, sending, completed, partially_failed, failed, cancelled | scheduled→queued/cancelled; queued→sending/cancelled; sending→completed/partially_failed/failed |
| Report job (T4) | queued, running, completed, failed, cancelled, expired | queued→running/cancelled; running→completed/failed/cancelled; completed→expired |
| Certificate (T4) | issued, revoked, replaced, expired | issued→revoked/replaced/expired; replacement enlaza nuevo issued |
| HukID delivery local (T4) | pending, submitted, offered, issued, cancelled, failed, exhausted | pending→submitted/failed; submitted→offered/issued/cancelled/failed; offered→issued/cancelled/failed; failed→pending/exhausted según retry policy |

## Invariantes críticas

- No se puede revocar/eliminar al último `org_owner` activo.
- Una release activa sólo puede apuntar a versiones publicadas e inmutables.
- Cupo y promoción waitlist se deciden con lock/constraint en una transacción de Participation.
- Un ticket revocado/reemplazado jamás vuelve a `active`.
- Sólo application leader puede submit; todos los miembros requeridos deben estar `active` y consentidos.
- Un check-in nunca se edita: se agrega un `void` y, si corresponde, un nuevo hecho.
- Certificado e issuance request quedan ligados a versiones exactas de regla, template y datos fuente.
