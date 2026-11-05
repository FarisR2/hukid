# FEAT-002 — Tareas

Estado: USR-T01 contrato/reglas, USR-T02 persistencia/RLS/transacciones y USR-T03 lecturas autorizadas completadas en laboratorio; USR-T04 siguiente. Mutaciones, entrega y UI pendientes. Owner: Team 5, tenancy/seguridad, backend/worker y consola.

| Estado / ID | Objetivo y artefacto | Depende de | Componentes | Aceptación / verificación | Riesgo |
| --- | --- | --- | --- | --- | --- |
| [x] USR-T01 | Materializar contrato/matriz, política email/TTL, reingreso y schemas de invitación/member. | AUTH-T02, AUTH-T03, AUTH-T05, AUTH-T07 | OpenAPI, tenancy, ADR-0002, ADR-0011 | Baseline de 12 operaciones contract-only, schemas/ejemplos y reglas Go; aceptación sin membership y 409 último admin validados. Sin handlers/DDL de invitación. | Escalación de permisos. |
| [x] USR-T02 | Ampliar migraciones, RLS, locks y audit/outbox compartidos. | USR-T01 | Postgres/tenancy/audit, ADR-0012 | Migración 0007 desde vacío/0006; únicos/FK/RLS, credencial separada y pool reuse probados; lock tenant/último admin y evidencia atómica. Sin segundo registro de identidad ni handlers. | Integridad y concurrencia. |
| [x] USR-T03 | Implementar listado/consulta autorizada con filtros y cursor. | USR-T02 | API/repositorios | AC01: sólo datos del tenant y campos permitidos; rol sin lectura no consulta directorio; cursor manipulado falla. | Enumeración/PII. |
| [ ] USR-T04 | Implementar crear/revocar invitación y entrega cifrada idempotente. | USR-T02 | Tenancy, notification port/worker | AC02/04: token hasheado, payload temporal cifrado, proveedor falso/sandbox, errores separados de aceptación y sin secretos en logs. | Entrega y replay. |
| [ ] USR-T05 | Implementar aceptación y reinvitación con identidad verificada. | USR-T04, AUTH-T04, AUTH-T05 | Tenancy, IdP, API | AC03: identidad correcta acepta una vez; dos aceptaciones concurrentes no duplican; token expirado/ajeno falla; token viejo no revive al reenviar. | Toma de cuenta. |
| [ ] USR-T06 | Implementar edición de roles/alcance y lifecycle con ETag y lock tenant. | USR-T02, USR-T03 | Authorization, tenancy | AC05/06/07: 412/403/409 sin efecto parcial; carreras no eliminan último admin; issuer ajeno nunca se concede. | Pérdida de administración. |
| [ ] USR-T07 | Conectar revisión de permisos e invalidación de contexto a FEAT-001. | USR-T05, USR-T06, AUTH-T05, AUTH-T06 | Session/auth/tenancy | AC08: siguiente petición denegada tras suspensión; /me actualiza capacidades; otros tenants de la identidad siguen disponibles. | Permisos cacheados. |
| [ ] USR-T08 | Implementar UI de miembros/invitaciones y aceptación con estados accesibles. | USR-T03–USR-T07, AUTH-T08 | Console user-management | AC10: journey invitación→aceptación→rol→suspensión con teclado; 412 preserva cambios y pide recargar; confirmación muestra objetivo/razón. | Edición obsoleta/UX. |
| [ ] USR-T09 | Ejecutar gate de seguridad, concurrencia, retención y documentación. | USR-T08, AUTH-T09 | Tests, audit, runbook | AC09 y QR: commit/audit/outbox coherentes, replay reautorizado, purga y logs seguros; evidencias y DoD. | Falsos éxitos/fuga. |

## Cobertura requisito → aceptación → tarea

| Requisito | AC | Tareas |
| --- | --- | --- |
| USR-FR01 | AC01 | USR-T01, USR-T03, USR-T08 |
| USR-FR02 | AC02 | USR-T01, USR-T04 |
| USR-FR03 | AC03 | USR-T05, USR-T08 |
| USR-FR04 | AC04 | USR-T04, USR-T05, USR-T09 |
| USR-FR05 | AC05 | USR-T06, USR-T08 |
| USR-FR06 | AC06 | USR-T06, USR-T07 |
| USR-FR07 | AC07 | USR-T02, USR-T06, USR-T09 |
| USR-FR08 | AC08 | USR-T07, USR-T09 |
| USR-FR09 | AC09 | USR-T02, USR-T09 |
| USR-FR10 | AC10 | USR-T08 |
| USR-QR01 | AC01/05/08 | USR-T03, USR-T06, USR-T09 |
| USR-QR02 | AC03/07/09 | USR-T02, USR-T05, USR-T06, USR-T09 |
| USR-QR03 | AC10 | USR-T08 |
| USR-QR04 | AC02/03/04/09 | USR-T04, USR-T05, USR-T09 |

## Orden y límites

USR-T03 y el diseño de notificación parten de U0; no modificar al mismo tiempo middleware/session store/DDL comunes sin coordinar migraciones. FEAT-003 consume la matriz final; no mantiene una copia distinta.

No construir integration clients, grants de emisión ni credential definitions dentro de estas tareas. Cualquier ampliación se especifica como otra feature y actualiza contratos/ADR.

Completar cada tarea requiere artefacto revisable y pruebas indicadas. El gate U4 exige todas las AC/QR, [plan](plan.md) y [DoD](../../05-delivery/definition-of-done.md). Las casillas marcadas reflejan sólo el alcance y evidencia de cada incremento; cerrar T01 no cierra U4.

## Evidencia USR-T01 — 2026-11-05

[Contrato/política](../../03-design/console-members-contract.md) y [ADR-0011](../../decisions/ADR-0011.md) materializan doce operaciones Management/BFF contract-only, schemas estrictos compartidos, matriz existente sin nuevos grants, política test de email/TTL/retención e idempotencia, reingreso con lifecycle/historial y protección del último admin. No se modifica la emisión de tokens ni se cambia el login de AUTH.

Las cinco pruebas nuevas de contrato validan OpenAPI/referencias y todos los ejemplos, headers/seguridad/capacidades, aceptación sin membership previa y Problem 409 last_admin_required, más negativos de campos extra, PII/tokens en responses, roles/issuerIds, email, patches e input/política. Las cinco unitarias Go superiores y sus subcasos prueban carga estricta/relaciones, normalización email conservadora, deadline sin skew, ownership de grants, revisión/terminalidad y guard de último administrador. Este guard requiere datos resueltos bajo el mismo lock de tenant; todavía no hay una prueba de concurrencia de mutaciones USR.

Se ejecutaron y aprobaron `npm run check` (Go/vet, TypeScript, catorce tests de contrato/IdP y documentación), `npm run test:postgres` (regresión AUTH con DB/HTTP/IdP propios), `npm run build`, `npm run smoke` y `git diff --check`. La suite acumulada encontró inicialmente el puerto 19090 ocupado por la demo manual; se detuvo el laboratorio propio y la repetición pasó. No se cambió el fixture ni se omitieron tests para resolverlo.

No hay migración nueva, handlers, worker/email ni UI de miembros. No se ejecutó Chromium para este incremento sin cambios visuales; el E2E de AUTH conserva su evidencia histórica. Verificación email real del IdP y su perfil sintético ampliado corresponden a T05; fuente issuer confiable, lifecycle/historial y transacciones a T02/T06; entrega a T04 y gate final a T09. Producción y perfil VC conservan sus bloqueos. Siguiente: USR-T02.

## Evidencia USR-T02 — 2026-11-05

[Persistencia](../../03-design/console-members-persistence.md) y [ADR-0012](../../decisions/ADR-0012.md) materializan la migración 0007 expand: lifecycle/fechas y archivo revocado, alcance issuer, invitaciones con hash/HMAC/destinatario cifrado, envelope de entrega separado y fingerprints/referencias idempotentes. Se conserva identidad issuer/subject, membership lógica, sesiones e historia AUTH. Para revocaciones legacy sin fecha, el corte de reingreso es conservador al instante de migración; no se inventa una fecha histórica.

El nuevo runtime de miembros es separado, no propietario/NOBYPASSRLS, con RLS forzada y permisos mínimos por columnas. No amplía las credenciales AUTH. WithMemberMutation toma lock transaccional por UUID normalizado del tenant y confirma mutación/audit/outbox juntos; el callback debe reautorizar actor/MFA o destinatario antes del efecto. ArchiveRevokedMembership conserva grants finales sin permitir su modificación posterior al runtime. No hay otro registro de identidad.

Seis escenarios nuevos con PostgreSQL real cubren upgrade 0006→0007 y repetición, RLS/default deny/pool físico reutilizado y dos tenants, credenciales mezcladas rechazadas, FK/unique/CHECK, evidencia atómica ante fallos de audit/outbox, archivo y reemplazo sin duplicar membership, huellas administrativas/de aceptación ligadas al hash exacto, almacenamiento/purga de destinatario sin borrar token hash/evidencia, carrera de dos últimos admins, UUID equivalente y rollback/panic/cancelación del lock/waiter. Los comandos sintéticos de prueba demuestran la foundation de persistencia, no autorización HTTP ni el canje USR-T05.

Se ejecutaron y aprobaron `npm run check` (Go/vet, TypeScript, catorce tests de contrato/IdP y docs), `npm run test:postgres`, `npm run build`, `npm run smoke`, `npm run test:browser` (regresión Chromium AUTH con esquema nuevo) y `git diff --check`. El primer check general encontró 19090 ocupado por la demo propia; se detuvo ese laboratorio y la repetición aprobó los catorce tests. No se cambiaron fixtures ni omitieron verificaciones para resolver la colisión.

Sin endpoints/credencial USR conectada a API, lookup global de invitación, evidencia email, worker, replay HTTP, purga programada ni UI de miembros. La fuente confiable de ownership issuer sigue ausente: se prepara almacenamiento, sin conceder grants. Producción, carga/restore y retención institucional siguen pendientes. Siguiente: USR-T03, listado/consulta autorizada con filtros/cursor.

## Evidencia USR-T03 — 2026-11-05

[Directorio autorizado](../../03-design/console-members-directory.md) y [ADR-0013](../../decisions/ADR-0013.md) materializan cuatro GET de listas Management/BFF con campos mínimos, filtros y cursor opaco AES-256-GCM. Cada petición revalida tenant/membership activos y capacidad de la matriz antes del directorio, dentro de un snapshot repetible de sólo lectura con credencial members independiente y RLS. BFF exige el tenant seleccionado por AUTH; no se añade login ni endpoint individual. Ocho mutaciones siguen contract-only y no hay migración nueva.

El cursor liga actor/tenant/operación/filtros/límite/posición/versión/deadline; no extiende su TTL al continuar. Keyset createdAt/UUID resuelve empates; no promete snapshot entre páginas. El destinatario no se descifra: máscara fija o redacted por retención/purga. SQL representa y filtra expiración efectiva sin modificar deliveryState. Los grants legacy incompletos producen 503 sin inventar alcances ni ocultar filas.

Unitarias prueban filtros, matriz y cursores manipulados/ajenos/expirados/con otra clave. Dos escenarios nuevos de PostgreSQL real cubren paginación de ambas listas, empates, filtros, dos tenants, pool reutilizado, cancelación y reautorización por rol/suspensión; revocar SELECT de invitaciones prueba denegación previa a la consulta. También prueban grants legacy incompletos y proyección con alcance almacenado, vencimiento exacto, deliveryState y máscara al vencer retención. La integración HTTP existente se amplía con API/IdP/DB reales y configuración USR: ambos transportes, headers, campos mínimos, errores 400/401/403/404/422 y contexto suspendido. El contrato conserva doce operaciones y declara cuatro GET implementados y ocho mutaciones pendientes, con 422 explícito.

Se ejecutaron y aprobaron `npm run check` (Go/vet, TypeScript, catorce tests de contrato/IdP y documentación), `npm run test:postgres`, `npm run build`, `npm run smoke` y `git diff --check`. La primera suite HTTP detectó una expectativa incorrecta de once campos frente a los diez definidos por el schema; se corrigió el test y se repitió. El primer check general encontró 19090 ocupado por la demo propia: se detuvo sólo ese laboratorio y el check completo pasó. No se omitieron pruebas ni cambiaron fixtures para resolver la colisión. No se ejecutó Chromium nuevo: no hay cambios visuales y la integración BFF está cubierta por HTTP real.

Sin creación/revocación/aceptación, worker/entrega, evidencia email, UI, rate limiting específico, carga/restore ni operación productiva. La credencial members conserva los permisos preparados en 0007, aunque las rutas nuevas sólo leen. La máscara fija no distingue destinatarios; el límite queda explícito para USR-T08. Siguiente: USR-T04, invitación y entrega cifrada/idempotente, manteniendo AUTH→USR→DASH y el roadmap HK separado.
