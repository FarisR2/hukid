# Equipo 4 — Onsite Operations

## Producto

Entrega Onsite API/DB, React PWA online, Communications Worker, Reporting/Certificates API y dashboards. No cambia registros/tickets ni conserva respuestas completas. Offline es una épica futura fuera del primer incremento.

## Épica OO-A — Dispositivos y preparación operativa

| ID | Historia | Criterios de aceptación esenciales |
|---|---|---|
| OO-001 | Como supervisor, quiero registrar/autorizar un dispositivo de check-in. | Device key/attestation cuando disponible; nombre/sede/vigencia; revoke; auditoría; no secret exportable. |
| OO-002 | Como staff, quiero iniciar sesión y seleccionar evento/sede/scope asignado. | `onsite:checkin`; MFA según policy; assignment vigente; UI forbidden; session timeout. |
| OO-003 | Como operador, quiero precargar release, claves y revocaciones. | Publication activa; JWKS/kid; revocation version/freshness; readiness visible; no PII innecesaria. |
| OO-004 | Como supervisor, quiero ver salud de dispositivos y sincronización. | Last seen/version/errors; revocar; alertar stale; sin ubicación/PII no necesaria. |

## Épica OO-B — Check-in online

| ID | Historia | Criterios de aceptación esenciales |
|---|---|---|
| OO-010 | Como staff, quiero escanear QR y validar acceso. | Firma/kid/aud/org/event/scope/exp/version/revocation; lista <15 s; p95 <700 ms; resultado accesible. |
| OO-011 | Como sistema, quiero impedir doble entrada efectiva. | Unique `(ticket,event,scope)`; misma idempotency reproduce; nueva key devuelve already_checked_in; carrera probada. |
| OO-012 | Como staff, quiero buscar manualmente cuando el QR no puede leerse. | Sólo proyección mínima; búsqueda exacta/limitada; masked data; selección confirmada; rate/audit. |
| OO-013 | Como staff, quiero registrar check-out. | Entrada previa/policy; append-only; idempotente; hora/dispositivo/actor; estado efectivo. |
| OO-014 | Como supervisor, quiero anular un hecho incorrecto. | `onsite:void`; compensates ID mismo scope; razón obligatoria; no update/delete; audit. |
| OO-015 | Como staff, quiero controlar acceso por sesión. | Ticket/regla permite sesión; capacidad opcional local; scope session; no altera registro principal. |
| OO-016 | Como staff, quiero manejar QR inválido, expirado, revocado o de otro evento. | Mensajes distintos sin PII; no registra asistencia; reason code/métrica; supervisor flow separado. |
| OO-017 | Como supervisor, quiero resolver un ticket recién emitido no materializado. | JWS válido se acepta si revocation cache fresca; proyección se completa por evento; auditoría de provisional verification. |

## Épica OO-C — Comunicaciones

| ID | Historia | Criterios de aceptación esenciales |
|---|---|---|
| OO-020 | Como manager, quiero gestionar plantillas transaccionales. | Variables allowlisted; locale; preview/test; version/publish; sanitización; no secret/PII en logs. |
| OO-021 | Como sistema, quiero enviar confirmaciones, invitaciones y cambios. | Consumer idempotente; provider message ID; retry/backoff; no duplicado; estado delivery. |
| OO-022 | Como manager, quiero programar recordatorios segmentados. | Audiencia por IDs/proyección autorizada; schedule/cancel; consent/preferences; dry-run/count. |
| OO-023 | Como operador, quiero manejar bounce/complaint/unsubscribe. | Webhook firmado; dedup; suppression list; evento; no reintenta hard bounce. |
| OO-024 | Como soporte, quiero reintentar mensajes fallidos. | DLQ sin body sensible; replay autorizado/auditado; presupuesto; poison aislado. |

## Épica OO-D — Dashboards, reportes y exports

| ID | Historia | Criterios de aceptación esenciales |
|---|---|---|
| OO-030 | Como manager, quiero ver inscritos/confirmados/asistencia agregada. | Proyecciones versionadas; watermark/lag; filtros event/session; no PII para scope agregado. |
| OO-031 | Como report viewer, quiero crear un reporte. | Snapshot de filtros/authorization/watermark; job async 202; estado progress/succeeded/failed/expired. |
| OO-032 | Como usuario autorizado, quiero descargar export sensible. | `reports:export_sensitive` + MFA reciente; URL one-use/TTL; archivo cifrado/retención; audit. |
| OO-033 | Como operador, quiero cancelar/reintentar jobs. | Estado válido; idempotente; cleanup parcial; retry no duplica artifact; audit. |
| OO-034 | Como privacy admin, quiero purgar reportes vencidos. | Scheduler; legal hold; object delete/crypto-shred; estado purged; métrica/evidencia. |

## Épica OO-E — Certificados

| ID | Historia | Criterios de aceptación esenciales |
|---|---|---|
| OO-040 | Como manager, quiero crear/versionar template de certificado. | Campos allowlisted; preview; immutable published version; font/assets licenciados; hash. |
| OO-041 | Como manager, quiero configurar regla de elegibilidad. | Attendance threshold/sessions/estado; versión; dry-run/count; no cambia retrospectivamente. |
| OO-042 | Como sistema, quiero emitir certificado idempotente. | Subject envelope + attendance watermark + rule/template version; PDF/hash/object; unique revision; evento. |
| OO-043 | Como participante, quiero descargar/verificar mi certificado. | Enlace firmado/portal; QR verification sin PII excesiva; status active/revoked/replaced. |
| OO-044 | Como manager, quiero revocar/reemitir. | Razón; historial; anterior terminal; nueva revisión; evento/notificación. |
| OO-045 | Como manager, quiero solicitar credencial HukID opcional. | Consent/issuer config; el adaptador outbound del Equipo 4 llama la Integration API por HTTPS/OAuth2 con idempotencia; guarda sólo IDs/estado necesarios; polling o webhook; backoff/DLQ; HukID no accede al bus de Events. |

## Épica OO-F — Operación y auditoría

| ID | Historia | Criterios de aceptación esenciales |
|---|---|---|
| OO-050 | Como operador, quiero monitorizar check-in, workers, reports y certificados. | SLO, dashboards, lag/DLQ/provider errors, alertas y trace IDs; simulacro. |
| OO-051 | Como auditor, quiero trazabilidad de hechos/void/exports/certificados. | Append-only; actor/device/scope/reason; consultas autorizadas; retención. |
| OO-052 | Como equipo, quiero restore y continuidad del evento. | Backup/PITR; restore drill; fallback online controlado; runbook impreso mínimo sin convertirse en source of truth. |

## Futuro fuera del incremento

`OO-FUT-01 Modo offline seguro`: identidad de dispositivo, snapshot firmado, cola AES-GCM/keystore, TTL, reglas de conflicto/revocación, sync y borrado seguro. No se implementa parcialmente.

## Contratos que posee

`/onsite/v1/devices`, `/readiness`, `/attendance/check-ins`, `/check-outs`, `/voids`, `/status`; `/operations/v1/templates`, `/messages`, `/reports`, `/exports`, `/certificate-templates`, `/eligibility-rules`, `/certificates`, `/hukid-deliveries`.
