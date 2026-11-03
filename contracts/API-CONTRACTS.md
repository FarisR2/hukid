# Catálogo canónico de APIs

Este catálogo define la superficie mínima. Cada equipo debe materializarla en OpenAPI 3.1 antes de iniciar implementación; un endpoint no incluido requiere revisión de ownership.

## Convenciones comunes

- JSON `snake_case`, UTC RFC 3339, IDs UUIDv7, cursor opaco.
- Comandos crean `Idempotency-Key`; request hash distinto con la misma key devuelve `409 idempotency_key_reused`.
- Updates usan `If-Match`; revisión obsoleta devuelve `412 stale_revision`.
- Errores `application/problem+json`: `type`, `title`, `status`, `code`, `detail`, `request_id`, `errors[]`.
- Colecciones: `items`, `next_cursor`; límite 1–100.
- Tenant y actor derivan del token/sesión, nunca del payload.
- `202` exige recurso operation/job consultable.

## Headers y semántica transversal

| Elemento | Regla |
|---|---|
| `Authorization` | Bearer con audience exacta; APIs browser pueden usar sesión BFF cookie + CSRF |
| `Idempotency-Key` | UUID/string 16–128; obligatorio en POST comando; retención mínima 24 h, 7 d para pagos/premios/emisión; misma key+hash reproduce status/body, hash distinto `409` |
| `If-Match`/`ETag` | obligatorio para PATCH y comandos dependientes de revisión; mismatch `412` |
| `X-Request-Id` | aceptado sólo si formato válido, de lo contrario regenerado; siempre devuelto |
| `traceparent` | W3C; propagado sin PII |
| `Retry-After` | obligatorio en `429` y `503` recuperable |
| Cache pública | ETag, `Cache-Control`, `Vary` y `Surrogate-Key`; respuestas privadas `no-store` |

## Schemas base de request/response

```json
{
  "problem": {
    "type": "https://errors.example.pe/invalid-state-transition",
    "title": "Invalid state transition",
    "status": 409,
    "code": "invalid_state_transition",
    "detail": "The registration cannot be confirmed from cancelled.",
    "request_id": "019...",
    "errors": [{"pointer": "/status", "code": "transition_not_allowed", "message": "..."}]
  },
  "page": {"items": [], "next_cursor": "opaque-or-null"},
  "operation": {"id": "019...", "state": "queued|running|succeeded|failed|cancelled", "progress": 0, "result_ref": null, "error": null}
}
```

Todo recurso mutable devuelve `id`, `organization_id`, `state`, `revision`, `created_at`, `updated_at` cuando corresponda. Campos de identidad/tenant suministrados por cliente se ignoran o rechazan; nunca sustituyen claims.

### Requests de dominio mínimos

| Schema | Required | Reglas |
|---|---|---|
| `OrganizationCreate` | slug, display_name, timezone, locale, owner_identity | slug DNS-safe; timezone IANA; provisioning compensable |
| `InvitationCreate` | email, roles, expires_at | roles allowlisted; expiry ≤7 d; respuesta nunca incluye token salvo canal de entrega seguro |
| `EventCreate` | site_id, slug, kind, timezone, starts_at, ends_at | rango válido; site del tenant; draft |
| `SessionWrite` | program_id, title, starts_at, ends_at, venue_id | UTC + timezone display; conflictos devuelven recursos/rangos, no PII |
| `FormVersionCreate` | schema, ui_schema, consent, field_policies | JSON Schema 2020-12; sin código; cada campo declara purpose/classification |
| `ReleaseCreate` | expected_event_revision | manifiesto se calcula server-side y devuelve publication/hash/artifacts |
| `RegistrationCreate` | form_version_id, answers, consent_version, attendee | validación por schema; PII cifrada; receipt seguro |
| `ApplicationSubmit` | expected_revision | snapshot server-side de team/answers/files; no acepta payload que reemplace snapshot |
| `AttendanceCommand` | ticket_jws, scope, occurred_at, device_id | actor/device reales derivan de sesión; `occurred_at` dentro de skew permitido |
| `ReportJobCreate` | report_type, filters, as_of, format | autorización se congela; resultado no se entrega inline |
| `CertificateJobCreate` | event_id, rule_version_id, template_version_id, subject_filter | genera operation; inputs/versiones quedan congelados |
| `HukidDeliveryCreate` | certificate_id, issuer_id, credential_definition_id, consent_id | Team 4 traduce a Integration API; claims no se aceptan libremente desde browser |

Los schemas detallados y ejemplos deben materializarse en OpenAPI 3.1 por owner durante Sprint 0. El contrato se considera incompleto hasta que CI valide todos los paths de este catálogo; no puede sustituirse por controladores implementados primero.

## Platform Foundation API

### Auth BFF y sesión actual

| Método y ruta | Auth | Entrada principal | Salida/efecto |
|---|---|---|---|
| `GET /auth/login` | público | `return_to` allowlisted | redirect OIDC con state/nonce/PKCE |
| `GET /auth/callback` | state cookie | code/state | sesión segura o Problem Details |
| `POST /auth/refresh` | cookie + CSRF | — | refresh rotation; cookie nueva; `204` |
| `POST /auth/logout` | cookie + CSRF | — | revocación local idempotente; no-store |
| `POST /auth/logout-all` | sesión + MFA reciente | — | revoca todas las familias |
| `GET /platform/v1/me` | sesión | — | usuario, organización activa, roles/capabilities/auth_time |
| `GET /platform/v1/me/capabilities` | sesión | recurso opcional | permisos efectivos y restricciones |

### Tenant, membresía y workloads

| Método y ruta | Auth | Entrada principal | Salida/efecto |
|---|---|---|---|
| `POST /platform/v1/organizations` | bootstrap/admin | slug, legal/display name, timezone, locale, owner | organización + membership owner |
| `GET /platform/v1/organizations/{id}` | miembro | — | configuración tenant + ETag |
| `PATCH /platform/v1/organizations/{id}` | `organizations:admin` | merge patch + If-Match | organización actualizada |
| `POST /organizations/{id}/suspensions` | platform admin | reason | suspende tenant y sesiones según policy |
| `GET /organizations/{id}/memberships` | `organizations:admin` | filtros/cursor | miembros/roles/estado |
| `POST /organizations/{id}/invitations` | `organizations:admin` | email, roles, expiry | invitación pending; evento comunicación |
| `POST /public/v1/invitations/{token}/acceptance` | OIDC + token | — | membership active |
| `POST /public/v1/invitations/{token}/declination` | token | — | invitation declined |
| `PATCH /memberships/{id}` | `organizations:admin` | roles/status + If-Match | roles/suspensión; revoca sesiones si aplica |
| `GET /platform/v1/me/organizations` | sesión | — | memberships activas |
| `POST /platform/v1/session-context` | sesión | organization_id | rota contexto/session claims |
| `GET /platform/v1/me/sessions` | sesión | — | sesiones/dispositivos masked, TTL y current flag |
| `DELETE /platform/v1/me/sessions/{id}` | titular/admin | — | revoca sesión/familia |
| `POST /organizations/{id}/service-accounts` | security admin + MFA | auth method, scopes, audiences, expiry | client + secreto one-time/ref |
| `POST /service-accounts/{id}/rotations` | security admin + MFA | new key/expiry | nueva credencial, overlap controlado |
| `POST /service-accounts/{id}/revocations` | security admin | reason | revocación inmediata |
| `POST /sites/{id}/domains` | owner | hostname | verification challenge |
| `POST /domains/{id}/verifications` | owner | — | verified/failed; TLS provisioning |

## CMS y Public Content API

| Método y ruta | Auth | Entrada | Salida/efecto |
|---|---|---|---|
| `POST /cms/v1/sites` | `sites:write` | slug/name/kind/locale | site draft |
| `GET/PATCH /cms/v1/sites/{id}` | `sites:write` | patch + ETag | site config |
| `POST /sites/{id}/pages` | `sites:write` | path/title/blocks | page draft |
| `GET/PATCH /pages/{id}` | `sites:write` | patch + ETag | draft/revision |
| `POST /pages/{id}/preview-tokens` | `sites:write` | ttl | preview URL one-use/short |
| `POST /pages/{id}/publications` | `sites:publish` | expected revision | immutable version + event |
| `POST /pages/{id}/restorations` | `sites:publish` | source version | nueva publicación basada en versión |
| `POST /cms/v1/media-uploads` | `sites:write` | name/MIME/size/hash | upload URL + asset pending |
| `POST /media/{id}/completion` | service/user | object metadata | scanning/ready/quarantined |
| `GET /public/v1/sites/{slug}` | público | host/locale | snapshot sitio + ETag |
| `GET /public/v1/sites/{slug}/pages/{path}` | público | publication | página publicada cacheable |
| `GET /public/v1/sites/{slug}/events` | público | filters/cursor | catálogo proyectado |
| `GET /public/v1/sites/{slug}/events/{event_slug}` | público | — | release público coherente |

## Event Configuration API

| Método y ruta | Auth | Entrada | Salida/efecto |
|---|---|---|---|
| `POST /configuration/v1/events` | `events:write` | site, slug, kind, dates, timezone, policy | draft |
| `GET /configuration/v1/events` | `events:write` | filters/cursor | lista |
| `GET/PATCH /events/{id}` | `events:write` | patch + ETag | event revision |
| `POST /events/{id}/duplications` | `events:write` | target dates/site | nuevo draft |
| `POST /events/{id}/closures` | `events:publish` | reason/effective_at | closed policy release |
| `POST /events/{id}/cancellations` | `events:publish` | reason/effective_at | cancelled release/event |
| `POST /events/{id}/archives` | `events:write` | — | archived terminal |
| CRUD `/configuration/v1/venues` | `events:write` | name/location/capacity/exclusive | venue + ETag |
| CRUD `/configuration/v1/speakers` | `events:write` | public profile/media/exclusive | speaker + ETag |
| CRUD `/events/{id}/programs` | `events:write` | slug/name/order | program revision |
| CRUD `/events/{id}/sessions` | `events:write` | program/venue/speakers/range | session or 409 conflict |
| `POST /events/{id}/schedule-validations` | `events:write` | candidate/revision | warnings/conflicts |
| `POST /configuration/v1/forms` | `events:write` | name/purpose | definition draft |
| `POST /forms/{id}/versions` | `events:write` | schema/ui/consent/policies | version draft |
| `POST /form-versions/{id}/validations` | `events:write` | — | errors/warnings/preview schema |
| `POST /form-versions/{id}/publications` | `events:publish` | expected hash | immutable version |
| `POST /events/{id}/form-bindings` | `events:write` | purpose/version/window | binding draft/open |
| `POST /bindings/{id}/closures` | `events:write` | reason | closed |
| `POST /events/{id}/publication-validations` | `events:publish` | expected revision | readiness errors/warnings |
| `POST /events/{id}/releases` | `events:publish` | expected revision, idempotency | publication manifest |
| `GET /releases/{id}/propagation` | `events:read` | — | consumer pending/active/failed/lag |

## Participation API

| Método y ruta | Auth | Entrada | Salida/efecto |
|---|---|---|---|
| `GET /participation/public/v1/sites/{site}/events/{event}/form` | público | purpose | active binding/schema/consent |
| `POST /.../registrations` | público/self | attendee, answers, consent | pending/confirmed/waitlisted receipt |
| `POST /registration-access` | público rate-limited | email/reference | magic-link requested (neutral response) |
| `GET/PATCH /participation/self/v1/registrations/{id}` | session/magic link | allowed fields + ETag | own status/data |
| `POST /self/registrations/{id}/cancellations` | titular | reason | cancelled + ticket revoked/promotion |
| `GET /self/registrations/{id}/ticket` | titular | — | no-store QR/ticket metadata |
| `GET /participation/v1/events/{id}/registrations` | `participation:read` | filters/cursor | masked/full by field policy |
| `POST /registrations/{id}/confirmations` | `participation:manage` | expected state | confirmed/ticket |
| `POST /registrations/{id}/rejections` | `participation:manage` | reason | rejected |
| `POST /events/{id}/registration-imports` | `participation:manage` | object/version/mode | import job |
| `POST /participation/public/v1/.../applications` | leader | venture/members/answers/consent | venture + draft application |
| `GET/PATCH /participation/self/v1/ventures/{id}` | leader/member | allowed fields + ETag | venture |
| `POST /ventures/{id}/invitations` | leader | email/role | invitation |
| `POST /team-invitations/{token}/acceptance|declination` | invited identity | — | membership state |
| `POST /applications/{id}/file-uploads` | leader | field/name/MIME/size/hash | upload URL/file pending |
| `POST /application-files/{id}/completion` | leader/service | object metadata | scan workflow |
| `GET/PATCH /participation/self/v1/applications/{id}` | leader | answers + ETag | draft |
| `POST /applications/{id}/submissions` | leader | expected revision | immutable revision submitted |
| `POST /applications/{id}/withdrawals` | leader | reason | withdrawn |
| `POST /applications/{id}/change-requests` | reviewer | fields/reason/deadline | needs_changes |
| `POST /applications/{id}/resubmissions` | leader | expected base | new immutable revision |
| `GET /participation/v1/events/{id}/applications` | reviewer/manager | filters/cursor | revisions according to scope |
| `POST /applications/{id}/admissions|rejections` | reviewer/manager | revision/reason | status + event |

## Onsite and Operations API

| Método y ruta | Auth | Entrada | Salida/efecto |
|---|---|---|---|
| `POST /onsite/v1/devices` | `onsite:void`/supervisor | label/assignment/public key | device pending/active |
| `GET/PATCH /onsite/v1/devices/{id}` | supervisor | assignment/status + ETag | device/revocation |
| `POST /onsite/v1/shifts` | `onsite:checkin` | event/venue | shift + server-derived device/actor |
| `GET /onsite/v1/readiness` | `onsite:checkin` | event/scope | release/key/revocation/lag/ready state |
| `POST /onsite/v1/attendance/check-ins` | `onsite:checkin` | ticket, scope, occurred_at | append-only fact/effective status |
| `POST /attendance/check-outs` | `onsite:checkin` | ticket/scope/time | check-out fact |
| `POST /attendance/facts/{id}/voids` | `onsite:void` | reason | compensating fact |
| `GET /onsite/v1/tickets/search` | `onsite:checkin` | exact minimized query | masked candidates |
| CRUD `/operations/v1/message-templates` | `communications:send` | locale/schema/content | draft/version/publish/retire |
| `POST /operations/v1/messages` | `communications:send` | template/audience/schedule | communication job |
| `GET/POST /messages/{id}/cancellations` | sender | — | state/cancellation |
| `POST /operations/v1/report-jobs` | `reports:read` | type/filters/as_of/format | 202 job |
| `GET /report-jobs/{id}` | requestor/authorized | — | state/progress/error |
| `POST /report-jobs/{id}/cancellations` | requestor | — | cancelled |
| `POST /report-jobs/{id}/download-links` | required scope/MFA | — | one-use URL |
| CRUD `/operations/v1/certificate-templates` | `certificates:issue` | template/assets/schema | versions |
| CRUD `/operations/v1/eligibility-rules` | `certificates:issue` | rule/version | dry-run/count/version |
| `POST /operations/v1/certificate-jobs` | `certificates:issue` | event/rule/template/filter | 202 job |
| `GET /operations/v1/certificates/{id}` | authorized/holder link | — | metadata/status/verification |
| `POST /certificates/{id}/revocations|replacements` | `certificates:revoke` | reason/new template | lifecycle event |
| `POST /certificates/{id}/hukid-deliveries` | `certificates:issue` | issuer config/consent | async delivery status |

## Errores estables mínimos

`invalid_state_transition`, `stale_revision`, `tenant_forbidden`, `publication_incomplete`, `release_gap`, `schedule_conflict`, `resource_in_use`, `binding_not_open`, `form_version_mismatch`, `consent_version_mismatch`, `already_registered`, `capacity_exhausted`, `waitlisted`, `invitation_expired`, `leader_required`, `application_closed`, `file_not_ready`, `file_quarantined`, `ticket_invalid`, `ticket_revoked`, `ticket_expired`, `wrong_scope`, `revocation_stale`, `device_revoked`, `already_present`, `not_present`, `idempotency_key_reused`.
