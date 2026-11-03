# Equipo 2 — Event Configuration

## Producto

Entrega Event Configuration API/DB/outbox y módulos React para eventos, recursos, agenda, formularios y release manifest. No posee registros, tickets, asistencia ni contenido CMS.

## Épica EC-A — Ciclo de vida del evento

| ID | Historia | Criterios de aceptación esenciales |
|---|---|---|
| EC-001 | Como event manager, quiero crear un evento/convocatoria en borrador. | Tipo, sitio, slug, zona, fechas, cupo/policy inicial; idempotente; tenant/rol; auditoría. |
| EC-002 | Como manager, quiero editar metadatos y reglas con concurrencia segura. | ETag/If-Match; validaciones de ventana; 412 obsoleto; no altera release publicada. |
| EC-003 | Como manager, quiero duplicar un evento como nuevo borrador. | Copia configuración allowlisted, no IDs/publicaciones/registros; nuevas fechas requeridas; auditoría. |
| EC-004 | Como manager, quiero cerrar inscripciones. | Nueva policy version; Participation confirma consumo; no cancela confirmados; estado visible. |
| EC-005 | Como manager, quiero cancelar o archivar el evento. | Razón; release de cancelación; notificación event; archive sólo terminal; no borra historia. |
| EC-006 | Como owner, quiero asignar managers/reviewers/check-in staff por evento/sede. | Membership activa; scopes mínimos; vigencia; revocación propagada; no crea usuarios. |

## Épica EC-B — Recursos, agenda y programas

| ID | Historia | Criterios de aceptación esenciales |
|---|---|---|
| EC-010 | Como manager, quiero gestionar sedes y salas. | Capacidad, ubicación, exclusividad y accesibilidad; ETag; no solapamiento exclusivo. |
| EC-011 | Como manager, quiero gestionar ponentes. | Nombre público/bio/media ref/consentimiento; recurso exclusivo opcional; no mezcla identidad de usuario. |
| EC-012 | Como manager, quiero crear programas/tracks ordenados. | Slug por evento; color accesible; orden estable; revisión. |
| EC-013 | Como manager, quiero crear y mover sesiones. | Programa/sala/ponentes/UTC+zona; rango válido; conflicto devuelve 409 con recurso/intervalo. |
| EC-014 | Como manager, quiero cancelar o completar una sesión. | Estado versionado; razón; nueva release; asistencia previa preservada. |
| EC-015 | Como manager, quiero visualizar agenda paralela y conflictos antes de publicar. | Vista por track/sala/recurso; preview; conflictos bloqueantes/no bloqueantes distinguibles. |

## Épica EC-C — Formularios y bindings

| ID | Historia | Criterios de aceptación esenciales |
|---|---|---|
| EC-020 | Como manager, quiero crear una definición de formulario. | Purpose registration/application/feedback; campos estándar/custom allowlisted; draft. |
| EC-021 | Como manager, quiero configurar validaciones y UI. | JSON Schema 2020-12; required/pattern/range/options; UI schema; no código; preview accesible. |
| EC-022 | Como privacy owner, quiero declarar consentimiento y política por campo. | Purpose/classification/retention/export allowlist; texto/version/hash; campos de alto riesgo señalados. |
| EC-023 | Como manager, quiero publicar una versión inmutable. | Schema/UI/consent hashes; versión; no update/delete; compatibilidad revisada. |
| EC-024 | Como manager, quiero vincular una versión a un evento y propósito. | Ventana; sólo binding open por purpose; form purpose compatible; snapshot en release. |
| EC-025 | Como manager, quiero cerrar/reemplazar un binding sin alterar respuestas existentes. | Nueva versión/binding; anterior closed; Participation usa versión activa para nuevos comandos. |

## Épica EC-D — Release consistente

| ID | Historia | Criterios de aceptación esenciales |
|---|---|---|
| EC-030 | Como manager, quiero validar readiness antes de publicar. | Checklist sitio, fechas, agenda, policy, binding, consentimiento y permisos; errores accionables. |
| EC-031 | Como manager, quiero publicar un release completo. | `publication_id`; snapshot/hash/manifiesto atómico; outbox; idempotencia; snapshots previos inmutables. |
| EC-032 | Como consumidor, quiero materializar release pending→active. | Manifest enumera artefactos/hashes; replay; gap recovery; ack opcional; no mezcla versiones. |
| EC-033 | Como manager, quiero ver el estado de propagación. | Por consumidor/version: pending/active/failed/lag; reintento seguro; no falso “publicado” operativo. |
| EC-034 | Como manager, quiero publicar cambios de agenda posteriores. | Nueva publication; diff público; no muta anterior; evento para comunicaciones. |

## Épica EC-E — Administración y operación

| ID | Historia | Criterios de aceptación esenciales |
|---|---|---|
| EC-040 | Como manager, quiero buscar/filtrar eventos y ver su estado. | Cursor, site/type/date/status; tenant isolation; empty/error states. |
| EC-041 | Como auditor, quiero historial de cambios/publicaciones. | Actor/revisión/diff/hash/request ID; append-only; acceso por scope. |
| EC-042 | Como equipo, quiero pruebas de contrato y carga de publicación. | OpenAPI/event schemas; producer tests; replay/gap/out-of-order; métricas de publish/lag. |
| EC-043 | Como operador, quiero recuperar fallos de outbox/release. | Lease/retry/DLQ; requeue auditado; no publicación parcial; runbook. |

## Contratos que posee

`/configuration/v1/events`, `/venues`, `/speakers`, `/programs`, `/sessions`, `/forms`, `/bindings`, `/releases`. Produce `configuration.event.release_published.v1`, `configuration.event.cancelled.v1`, `configuration.schedule.changed.v1`; consume membership/role changes.
