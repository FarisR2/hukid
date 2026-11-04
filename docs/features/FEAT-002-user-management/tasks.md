# FEAT-002 — Tareas

Estado: pendiente. Owner: Team 5, tenancy/seguridad, backend/worker y consola.

| Estado / ID | Objetivo y artefacto | Depende de | Componentes | Aceptación / verificación | Riesgo |
| --- | --- | --- | --- | --- | --- |
| [ ] USR-T01 | Materializar contrato/matriz, política email/TTL, reingreso y schemas de invitación/member. | AUTH-T02, AUTH-T03, AUTH-T05, AUTH-T07 | OpenAPI, tenancy, ADR-0002 | Roles/capabilities y errores definidos; casos sin membership y último admin tienen ejemplos validados. | Escalación de permisos. |
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

Completar cada tarea requiere artefacto revisable y pruebas indicadas. El gate U4 exige todas las AC/QR, [plan](plan.md) y [DoD](../../05-delivery/definition-of-done.md). Las casillas no representan progreso actual.
