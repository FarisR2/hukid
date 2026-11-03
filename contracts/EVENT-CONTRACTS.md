# Contratos de eventos asíncronos

## Envelope canónico v1

```json
{
  "message_id": "019...",
  "domain_event_id": "019...",
  "topic": "participation.registration.confirmed.v1",
  "schema_version": 1,
  "producer": "participation",
  "organization_id": "019...",
  "business_event_id": "019...",
  "occurred_at": "2026-11-03T15:00:00Z",
  "published_at": "2026-11-03T15:00:01Z",
  "actor": {"type": "user|service|system", "id": "opaque-id"},
  "traceparent": "00-...",
  "correlation_id": "019...",
  "causation_id": "019...",
  "aggregate": {"type": "registration", "id": "019...", "version": 4},
  "partition_key": "organization_id:business_event_id",
  "data": {}
}
```

`message_id` identifica una publicación; `domain_event_id` identifica el hecho y permanece estable al republicarlo. El consumidor deduplica por `domain_event_id`, conserva la mayor `aggregate.version` y procesa por `partition_key`. Campos desconocidos se ignoran; campos existentes no cambian semántica dentro de v1.

## Catálogo normativo

| Topic | Owner | Consumidores | Payload mínimo, sin PII |
|---|---|---|---|
| `platform.organization.lifecycle_changed.v1` | Team 1 | 2–4 | organization, previous/current state, effective_at |
| `platform.membership.changed.v1` | Team 1 | auditoría/caches auth | membership, user opaco, roles/scopes hash, state |
| `platform.domain.activated.v1` | Team 1 | Content/CDN | site, hostname, primary, activated_at |
| `content.page.published.v1` | Team 1 | CDN/audit | site, page, publication, path, locale, content_hash |
| `configuration.event.release_published.v1` | Team 2 | 1, 3, 4 | publication_id, release_version, manifest_uri/ref, manifest_hash, effective_at |
| `configuration.event.cancelled.v1` | Team 2 | 1, 3, 4 | event, release, reason_code, effective_at |
| `configuration.schedule.changed.v1` | Team 2 | 1, 3, 4 | event, publication, schedule_hash, affected sessions |
| `participation.registration.created.v1` | Team 3 | Operations autorizado | registration opaco, state, source, form_version |
| `participation.registration.confirmed.v1` | Team 3 | Onsite, Operations | registration, event, ticket_id, ticket_version, confirmed_at |
| `participation.registration.waitlisted.v1` | Team 3 | Operations | registration, event, position opcional, policy_version |
| `participation.registration.promoted.v1` | Team 3 | Onsite, Operations | registration, prior state, ticket/version, promoted_at |
| `participation.registration.rejected.v1` | Team 3 | Operations | registration, reason_code, decided_at |
| `participation.registration.cancelled.v1` | Team 3 | Onsite, Operations | registration, prior state, cancelled_at |
| `participation.ticket.issued.v1` | Team 3 | Onsite | ticket, registration, event, scope, version, key_id, expiry |
| `participation.ticket.revoked.v1` | Team 3 | Onsite | ticket, event, version, reason_code, revoked_at |
| `participation.availability.changed.v1` | Team 3 | Content | event, public state, remaining band/value policy, as_of |
| `participation.team_invitation.changed.v1` | Team 3 | Communications | invitation, application, state, expires_at; recipient sólo en envelope cifrado dirigido |
| `participation.application.submitted.v1` | Team 3 | Operations/review projection | application, revision, team_size, submitted_at, form_version |
| `participation.application.status_changed.v1` | Team 3 | Operations | application, revision, previous/current, reason_code |
| `participation.file.scan_completed.v1` | Team 3 | Participation | file, state ready/quarantined, checksum, scanned_at |
| `participation.certificate_subject.available.v1` | Team 3 | Operations exclusivamente | referencia cifrada, key_id, purpose, retention_until, digest |
| `onsite.attendance.recorded.v1` | Team 4 Onsite | Operations | attendance_fact, registration opaco, event, scope, type, occurred_at |
| `onsite.attendance.voided.v1` | Team 4 Onsite | Operations | original_fact, compensating_fact, reason_code, effective_at |
| `onsite.device.revoked.v1` | Team 4 Onsite | Onsite gateway | device, assignments, revoked_at, reason_code |
| `operations.communication.state_changed.v1` | Team 4 Ops | audit/support | message/job, channel, previous/current, provider_code masked |
| `operations.report.state_changed.v1` | Team 4 Ops | admin shell | report_job, previous/current, progress, expires_at |
| `operations.certificate.issued.v1` | Team 4 Ops | audit/communications | certificate, event, template/rule version, artifact digest, verification code |
| `operations.certificate.revoked.v1` | Team 4 Ops | verification/communications | certificate, reason_code, revoked_at, replacement_id opcional |
| `operations.hukid_delivery.state_changed.v1` | Team 4 Ops | admin shell | delivery, certificate, external request opaco, previous/current, retry_at |

HukID no consume ninguno de estos topics. El último evento pertenece al estado local del adaptador outbound de Events.

## Publicación, replay y fallos

- Productor: cambio de agregado + outbox en una transacción; relay con reintentos exponenciales y jitter.
- Consumidor: inbox + efecto/proyección en una transacción; duplicado devuelve éxito; poison message va a DLQ sin PII.
- Ordering: sólo se garantiza por `partition_key`; el consumidor rechaza gaps no recuperables y solicita replay.
- Replay: conserva `domain_event_id` y `occurred_at`, genera nuevo `message_id`/`published_at`, añade header `replay=true`.
- Retención: bus caliente 7 días, archivo cifrado 90 días por defecto; proyecciones siguen su política de datos, no la del bus.
- Compatibilidad: cambios aditivos en la misma versión; required nuevo, rename, tipo o semántica requieren topic `.v2` y convivencia mínima de 90 días.

## Contratos como código

Cada topic debe tener JSON Schema/AsyncAPI, ejemplo válido y test productor-consumidor. CI rechaza mensajes con PII no allowlisted, schemas incompatibles, topic sin owner o consumidor sin inbox/replay test.
