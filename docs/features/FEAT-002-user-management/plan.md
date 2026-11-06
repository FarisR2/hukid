# FEAT-002 — Plan técnico

Referencias: [spec](spec.md), [tareas](tasks.md), [FEAT-001](../FEAT-001-authentication/plan.md).

USR-T01 materializa U0: [contrato y políticas](../../03-design/console-members-contract.md), [OpenAPI](../../../src/platform/contracts/console-members.openapi.json), schemas y reglas puras según [ADR-0011](../../decisions/ADR-0011.md). USR-T02 añade [persistencia/RLS y protocolo transaccional](../../03-design/console-members-persistence.md) según [ADR-0012](../../decisions/ADR-0012.md). USR-T03 conecta [cuatro lecturas autorizadas con filtros/cursor](../../03-design/console-members-directory.md) según [ADR-0013](../../decisions/ADR-0013.md); USR-T04 conecta [creación/revocación y entrega sintética](../../03-design/console-invitation-delivery.md) según ADR-0014. USR-T05 conecta [aceptación/reingreso y evidencia OIDC](../../03-design/console-invitation-acceptance.md) según [ADR-0015](../../decisions/ADR-0015.md). USR-T06 conecta [ambos PATCH con ETag y lock tenant](../../03-design/console-members-lifecycle.md), según [ADR-0016](../../decisions/ADR-0016.md). USR-T07 conecta [revalidación y reconciliación de contexto](../../03-design/console-authorization-revalidation.md), según [ADR-0017](../../decisions/ADR-0017.md). El siguiente incremento es USR-T08: UI de miembros/invitaciones.

## Estado inicial y módulos

Partir del tenant/identidad/membership/session store de FEAT-001. Ampliar tenancy y autorización existentes; no crear un servicio users independiente ni un segundo sistema de login.

| Componente propuesto | Trabajo |
| --- | --- |
| Platform internal/tenancy | ListMembers, InviteMember, AcceptInvitation, ChangeMembership y RevokeInvitation. |
| Platform internal/authorization | Matriz de capacidades, issuer scopes, step-up y revisión de actor. |
| Platform adapters/privateapi y console | Management operator y proxy BFF; validación de requests/ETag. |
| Platform adapters/postgres | Invitaciones, roles/alcance, lock de tenant y transacciones audit/outbox. |
| Platform cmd/worker + notification port | Entrega de invitaciones con reintentos y payload sensible cifrado. No usar workers Events. |
| Console src/user-management | Lista, filtros, invitación, edición y confirmaciones. |

## Baseline de contratos USR-T01

Management exige Bearer operator conforme al perfil. Las rutas tenant-scoped exigen membership válida y capacidad; aceptación tiene la excepción explícita descrita abajo. El tenantId de ruta selecciona recurso; el servidor valida pertenencia. Browser usa rutas equivalentes bajo /console/api mediante cookie/CSRF/Origin; no expone access token. El detalle normativo de campos, filtros, reintentos, scopes y errores vive sólo en la referencia del contrato USR-T01.

| Ruta Management | Entrada / resultado |
| --- | --- |
| GET /v1/operator/tenants/{tenantId}/memberships | state, role, query, cursor, limit; items mínimos + nextCursor. |
| POST /v1/operator/tenants/{tenantId}/invitations | email, roles, issuerIds; 201 con id/state/expiresAt/deliveryState, sin token. |
| GET /v1/operator/tenants/{tenantId}/invitations | Filtros/cursor; destinatario mínimo autorizado y estado, sin enlace. |
| POST /v1/operator/tenants/{tenantId}/invitations/{id}/revocations | reasonCode; transición idempotente con revisión. |
| POST /v1/operator/invitation-acceptances | token de un uso; sesión operator y destinatario verificado; devuelve tenant/membership autorizados. |
| PATCH /v1/operator/tenants/{tenantId}/memberships/{id} | roles, issuerIds y/o state, reasonCode; If-Match; recurso actualizado + ETag. |

El endpoint de aceptación permite al operador autenticado sin membership activa aceptar únicamente su invitación; no necesita ni obtiene acceso al directorio. Su token en body se excluye de traces/logs. Es una excepción explícita al requisito de membership previa, no al de identidad/autorización.

Comandos usan Idempotency-Key acotada por actor/operación/tenant y hash; acceptance además consume el token una vez. Reautorizar antes de devolver replay. 401 inválido; 403 sin capacidad/MFA; 404 recurso ajeno; 409 estado/último admin/key reutilizada; 412 revisión obsoleta; 422 input inválido. Materializar schemas y ejemplos antes de controllers.

## Migraciones y concurrencia

La migración 0007 de USR-T02 añade invitaciones, lifecycle/archivo, alcance, deadlines y fingerprints idempotentes mediante expand, conservando identidad única issuer/subject y membership lógica por tenant/identidad. Registra binding opcional de generación/revocación objetivo y corte vigente de membership; USR-T05 los compara bajo lock al resolver la identidad verificada. El modelo de reingreso conserva historial y membershipId y abre lifecycle nuevo con revisión monotónica y grants explícitos, sin duplicar membership efectiva. USR-T04/T05 conectan los comandos de invitación y aceptación; USR-T06 conecta los cambios PATCH y el archivo de revocación bajo el mismo lock, sin migración nueva.

WithMemberMutation bloquea el agregado tenant mediante advisory lock transaccional del UUID normalizado antes del callback; se prueba el guard de último admin con dos conexiones reales. Invitar/aceptar/promover/reactivar/degradar deben usar esta misma primitiva y orden de locks para no eludir la invariante por otra ruta. RLS del runtime de miembros aísla tenant; autorización de actor/capacidades sigue siendo obligación de cada handler/replay.

Dentro de la transacción volver a validar revisión/capacidad del actor, cambios permitidos y tenant activo; persistir cambios, revisión de autorización, audit y outbox. Tras commit, FEAT-001 revalida cada API; USR-T07 reconcilia revisión/selección al leer la sesión, con locks family→generation y comparación del contexto observado. Mantener identidades/sesiones de otros tenants operables.

Invite token se genera con CSPRNG, se guarda hasheado para canje y se transporta por envelope temporal cifrado al worker. Outbox no contiene token/email en claro; los reintentos del proveedor tienen deduplicación y errores seguros. Reenviar con token nuevo revoca el anterior; no recuperar el código desde un hash.

## Hitos

| Hito | Dependencias | Gate |
| --- | --- | --- |
| U0 — Contrato y matriz | AUTH-T02/T03/T05/T07 | Materializado en USR-T01; OpenAPI/schemas/ejemplos y reglas puras, sin handlers. |
| U1 — Lectura/aislamiento | U0 | Lecturas API/BFF con filtros/cursor y roles negativos probados en USR-T03; tabla visual pendiente USR-T08. |
| U2 — Invitación vertical | U1 + worker/IdP test | Admin invita, entrega sintética, identidad correcta acepta una vez. |
| U3 — Ciclo de acceso | U2 | Roles/suspensión/revocación y último admin bajo concurrencia. |
| U4 — UI y entrega | U3 | [UI USR-T08](../../03-design/console-members-interface.md) con journey, 412/403/expiración y revalidación; gate integral/auditoría USR-T09 pendiente. |

## Pruebas y reversión

Contratos antes de UI integrada; dominio con reloj/entropía inyectados; Postgres con dos tenants y carreras; proveedor email falso y luego sandbox; E2E con administrador y no administrador.

Los comandos reales se incorporan al toolchain de AUTH-T01. Registrar migración, checks ejecutados y fixtures en el paquete al finalizar. No se afirma que el modelo SQL citado en fuentes ya exista.

Rollout tenant sintético, luego piloto. Deshabilitar escrituras si falla la validación de permisos; no borrar memberships ni historial para revertir. Invitaciones no entregadas se cancelan/expiran; nunca restablecer tokens revocados tras restore.

## Riesgos

IdP debe proporcionar identidad/email verificados conforme a política; no usar sólo igualdad de correo no verificado. TTL y puerto/evidencia están definidos en USR-T01; T04 implementa entrega sintética y T05 integra el perfil email sintético del IdP; no acredita un proveedor productivo. DB/RLS y consulta mínima de memberships del login deben coordinarse con AUTH para evitar circularidad o bypass global. La propiedad issuer necesita fuente confiable antes de habilitar grants issuerIds; no crear emisores ficticios ni ampliar permisos por esa dependencia.
