# FEAT-002 — Tareas

Estado: USR-T01 completada como baseline de contrato y reglas puras de laboratorio; USR-T02 siguiente. Endpoints, ampliación de persistencia, entrega y UI pendientes. Owner: Team 5, tenancy/seguridad, backend/worker y consola.

| Estado / ID | Objetivo y artefacto | Depende de | Componentes | Aceptación / verificación | Riesgo |
| --- | --- | --- | --- | --- | --- |
| [x] USR-T01 | Materializar contrato/matriz, política email/TTL, reingreso y schemas de invitación/member. | AUTH-T02, AUTH-T03, AUTH-T05, AUTH-T07 | OpenAPI, tenancy, ADR-0002, ADR-0011 | Baseline de 12 operaciones contract-only, schemas/ejemplos y reglas Go; aceptación sin membership y 409 último admin validados. Sin handlers/DDL de invitación. | Escalación de permisos. |
| [ ] USR-T02 | Ampliar migraciones, RLS, locks y audit/outbox compartidos. | USR-T01 | Postgres/tenancy/audit | Base previa migra sin pérdida; únicos/tenant scope y pool reuse funcionan; no segundo registro de identidad. | Integridad y concurrencia. |
| [ ] USR-T03 | Implementar listado/consulta autorizada con filtros y cursor. | USR-T02 | API/repositorios | AC01: sólo datos del tenant y campos permitidos; rol sin lectura no consulta directorio; cursor manipulado falla. | Enumeración/PII. |
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
