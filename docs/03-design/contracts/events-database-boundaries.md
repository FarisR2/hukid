# Bases de datos, constraints y migraciones

Cada servicio posee una base PostgreSQL lógica separada —base o schema/role aislado en MVP— y credenciales sin privilegios sobre las demás. No hay foreign keys cross-service; las referencias externas son UUID opacos acompañados por versión/hash cuando importa consistencia.

## Ownership de tablas

| Servicio | Tablas/agregados mínimos propios | Constraints críticas |
|---|---|---|
| Platform | `organizations`, `users`, `identities`, `memberships`, `membership_roles`, `invitations`, `sessions`, `refresh_families`, `service_accounts`, `service_credentials`, `domains`, `security_audit` | unique `(issuer,subject)`, slug/hostname global, un owner activo mediante constraint/trigger transaccional, token/secret sólo hash |
| Content | `sites`, `site_themes`, `navigations`, `pages`, `page_drafts`, `page_publications`, `media_assets`, `event_projections`, `availability_projections`, `projection_releases`, `inbox`, `outbox` | unique `(organization_id,slug)`, `(site_id,path,locale)`, publication inmutable, release activa única |
| Configuration | `events`, `event_revisions`, `venues`, `speakers`, `programs`, `sessions`, `form_definitions`, `form_versions`, `form_bindings`, `releases`, `release_artifacts`, `assignments`, `audit`, `outbox` | slugs por site/event, rangos válidos, exclusion constraint para recursos exclusivos, form/release publicados inmutables |
| Participation | `release_projections`, `registrations`, `registration_answers`, `capacity_counters`, `waitlist_entries`, `tickets`, `ticket_revocations`, `ventures`, `team_memberships`, `team_invitations`, `applications`, `application_revisions`, `application_files`, `consents`, `idempotency_keys`, `inbox`, `outbox` | dedupe HMAC por event/policy, confirmed ≤ capacity, waitlist sequence, ticket JTI único, una revisión current, cifrado de PII |
| Onsite | `release_projections`, `ticket_projections`, `revocation_sets`, `devices`, `assignments`, `shifts`, `attendance_facts`, `attendance_effective`, `inbox`, `outbox` | unique efectivo `(ticket_id,business_event_id,scope)`, facts append-only, void referencia fact existente, device no revocado |
| Operations | `message_templates`, `message_jobs`, `deliveries`, `suppression_entries`, `report_jobs`, `report_artifacts`, `certificate_templates`, `eligibility_rules`, `certificates`, `hukid_deliveries`, `subject_envelopes`, `inbox`, `outbox` | provider dedupe, artifact TTL, certificate unique por subject/event/rule/revision, external request unique por idempotency key |
| HukID | definido exclusivamente por su modelo canónico | no se replica ni modifica desde este paquete |

Todas las tablas tenant-scoped incluyen `organization_id NOT NULL`, índice prefijado por tenant y RLS `FORCE ROW LEVEL SECURITY`. El rol runtime usa `NOBYPASSRLS`; el worker establece tenant con `SET LOCAL` dentro de una transacción y lo limpia al devolver la conexión.

## Patrón común de infraestructura

```sql
-- Forma normativa, no migration ejecutable.
id uuid primary key,
organization_id uuid not null,
revision bigint not null default 1,
created_at timestamptz not null,
updated_at timestamptz not null,
created_by uuid,
updated_by uuid
```

- IDs UUIDv7 generados por aplicación; timestamps los fija el servidor.
- Estados usan `text` + check constraint versionada, no enum PostgreSQL difícil de contraer.
- PII de búsqueda: ciphertext + blind index/HMAC separado; jamás plaintext en índice/log.
- Outbox: `domain_event_id`, aggregate/version, topic/schema, payload, occurred/published, attempts/lease.
- Inbox: `(consumer_name, domain_event_id)` unique, processed/result hash/error metadata.
- Idempotency: `(organization_id, actor/client, operation, key)` unique + request hash + response ref + expiry.
- Soft delete sólo cuando el lifecycle lo exige; purga física mediante job y tombstone.

## Protocolo de migración sin downtime

1. **Expand:** agregar tabla/columna nullable, índice concurrente o constraint `NOT VALID`.
2. **Deploy dual-compatible:** código lee viejo/nuevo y escribe según feature flag; nunca depende aún del backfill.
3. **Backfill:** job reanudable por cursor, rate-limited, con métricas y checksum.
4. **Validate:** `VALIDATE CONSTRAINT`, conteos/hash, contract/e2e y rollback de código probado.
5. **Switch:** activar lectura nueva y observar al menos una ventana de carga.
6. **Contract:** remover campo/ruta sólo en release posterior y después del periodo de compatibilidad.

No se usan down migrations destructivas en producción. El rollback es de aplicación/flag; una migración correctiva forward revierte semántica. Toda migration tiene owner, impacto de lock, duración estimada, estrategia de backfill, métrica y runbook.

## Gates CI/CD de datos

- Lint SQL y migración sobre base vacía y snapshot de versión anterior.
- Test de dos tenants usando el mismo pool demuestra cero fuga y RLS efectiva.
- CI rechaza tabla tenant sin `organization_id`, policy o índice tenant-first.
- Pruebas de carrera para cupo, ticket, check-in, publicación y firma exactamente una vez.
- Restore drill trimestral con RPO/RTO medidos; restauración no reanima datos purgados sin tombstones.
- Cambios incompatibles de evento/API y schema DB no se despliegan en el mismo paso.
