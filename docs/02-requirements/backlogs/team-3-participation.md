# Equipo 3 — Participation

## Producto

Entrega Participation API/DB/outbox, isla React pública de registro/postulación y módulos React administrativos. Posee registros, capacidad, waitlist, tickets, emprendimientos, miembros, postulaciones, archivos y PII canónica.

## Épica PA-A — Registro público y autoservicio

| ID | Historia | Criterios de aceptación esenciales |
|---|---|---|
| PA-001 | Como visitante, quiero cargar el formulario vigente del evento. | Site/event/release/binding activos; schema/UI/consent hashes; no draft; cache breve sin personalización. |
| PA-002 | Como visitante, quiero registrarme sin crear una cuenta cuando la policy lo permita. | Idempotency-Key; validación server-side; consentimiento; anti-abuso; PII cifrada; receipt sin enumeración. |
| PA-003 | Como usuario autenticado, quiero reutilizar datos permitidos con consentimiento. | Opt-in; preview/corrección; no rellena campos sensibles no autorizados; snapshot de aceptación. |
| PA-004 | Como sistema, quiero detectar registros duplicados. | Identidad normalizada por event/policy; misma key reproduce; duplicado con otra key devuelve resultado seguro/409 sin fuga. |
| PA-005 | Como participante, quiero verificar mi correo cuando la policy lo exija. | Token hasheado/expirable/one-use; resend limitado; estados pending/verified/expired. |
| PA-006 | Como participante, quiero consultar el estado mediante sesión o enlace firmado. | Propósito único, expiración/revocación; muestra confirmed/waitlisted/cancelled/rejected; sin enumeración. |
| PA-007 | Como participante, quiero cancelar mi registro. | Titular o staff autorizado; idempotente; revoca ticket; libera cupo una vez; promoción atómica. |
| PA-008 | Como participante, quiero descargar o añadir mi ticket al wallet del dispositivo. | Sólo confirmed; QR JWS sin PII; exp/version/kid/audience; descarga no-store; revocación visible. |

## Épica PA-B — Capacidad, waitlist y ticket

| ID | Historia | Criterios de aceptación esenciales |
|---|---|---|
| PA-010 | Como sistema, quiero materializar la registration policy del release. | Pending→active por publication; hashes; replay/gap; no acepta registro hasta release completa. |
| PA-011 | Como organizador, quiero garantizar que el cupo nunca sea superado. | Lock/CAS local; confirmed count invariant; prueba concurrente 3× pico; timeout/retry controlado. |
| PA-012 | Como participante, quiero entrar a una waitlist ordenada si no hay cupo. | Posición monotónica; estado/expectativa; no ticket activo; privacidad de posición. |
| PA-013 | Como sistema, quiero promover automáticamente al siguiente elegible. | Misma transacción de liberación; una promoción; expiry opcional; evento/notification. |
| PA-014 | Como manager, quiero confirmar/rechazar registros sujetos a aprobación. | Scope; estado válido; razón allowlisted; capacidad respetada; audit/evento. |
| PA-015 | Como sistema, quiero emitir, rotar y revocar tickets. | JWS asimétrico; KMS/key rotation/JWKS; `jti` opaco; revocation list firmada/versionada; eventos minimizados. |

## Épica PA-C — Emprendimientos y equipos

| ID | Historia | Criterios de aceptación esenciales |
|---|---|---|
| PA-020 | Como líder, quiero crear un emprendimiento y postulación draft. | Binding application activo; identidad/contacto; ownership; draft; consentimiento. |
| PA-021 | Como líder, quiero invitar integrantes con rol. | Token one-use/expiry; email normalizado; no duplicado; min/max policy; evento de invitación. |
| PA-022 | Como integrante, quiero aceptar/rechazar participación. | Identidad/verificación; estados; no puede aceptar por otro; retiro posterior auditado. |
| PA-023 | Como líder, quiero editar datos y respuestas antes del cierre. | JSON Schema; ETag; autosave; límites; no modifica revisión enviada. |
| PA-024 | Como líder, quiero adjuntar archivos/enlaces requeridos. | Upload firmado, MIME/tamaño/hash, malware scan, quarantine, retención y ACL; submit bloqueado si no ready. |
| PA-025 | Como líder, quiero enviar la postulación. | Ventana/miembros/archivos/consent valid; snapshot inmutable + hash; idempotente; receipt/evento. |
| PA-026 | Como líder, quiero retirar una postulación. | Policy/ventana; estado terminal o nueva revisión según regla; razón; notificación/auditoría. |
| PA-027 | Como líder, quiero subsanar cuando el organizador lo solicita. | Solicitud con campos/fecha; crea draft desde revisión; nueva revisión al enviar; evaluadores ven revisión explícita. |

## Épica PA-D — Backoffice y admisibilidad

| ID | Historia | Criterios de aceptación esenciales |
|---|---|---|
| PA-030 | Como manager, quiero listar/buscar registros con filtros. | Paginación cursor; filtros estado/date/email HMAC; PII masked según rol; no query sin tenant. |
| PA-031 | Como manager, quiero corregir datos administrativos permitidos. | Campos allowlisted; razón; no altera answers/snapshot; audit y notificación cuando corresponda. |
| PA-032 | Como reviewer, quiero revisar admisibilidad de una revisión. | Assignment/scope; checklist; admit/reject/needs_changes; razón; optimistic lock. |
| PA-033 | Como manager, quiero importar registros controlados. | CSV template; dry-run; errores por fila; idempotency/external ref; consentimiento/legal basis explícita. |
| PA-034 | Como privacy admin, quiero atender acceso/corrección/erasure. | Legal hold; workflow; borra/pseudonimiza DB/files/events derivados según policy; evidencia sin PII. |
| PA-035 | Como Operations, quiero una proyección purpose-bound para reporte/certificado. | Allowlist; envelope AES-GCM/key ID/purpose/retention/digest; sólo destinatario; no DLQ/log plaintext. |

## Épica PA-E — Seguridad, rendimiento y operación

| ID | Historia | Criterios de aceptación esenciales |
|---|---|---|
| PA-040 | Como plataforma, quiero rate limit y bot protection adaptativos. | Por IP/event/device; challenge; 429/Retry-After; allowlist operativa; métricas sin PII. |
| PA-041 | Como equipo, quiero pruebas de carga y concurrencia. | Perfil registro/waitlist/cancel; 3× pico; cero sobrecupo/doble ticket; p95/DB pool documentados. |
| PA-042 | Como operador, quiero reconciliar releases/eventos y DLQ. | Inbox/outbox; replay; gaps; herramientas auditadas; runbook. |
| PA-043 | Como auditor, quiero historial de cambios sensibles. | Actor/action/target/result/request ID; append-only; PII mínima; retención. |

## Contratos que posee

`/participation/public/v1/.../form`, `/registrations`, `/registration-access`, `/tickets`; `/participation/v1/registrations`, `/ventures`, `/members`, `/applications`, `/files`, `/admissibility`, `/privacy-requests`. Produce registration/ticket/availability/application/certificate-subject events; consume releases y membership revocations.
