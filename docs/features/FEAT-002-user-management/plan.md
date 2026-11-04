# FEAT-002 — Plan técnico

Referencias: [spec](spec.md), [tareas](tasks.md), [FEAT-001](../FEAT-001-authentication/plan.md).

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

## Contratos propuestos

Todas las rutas Management exigen Bearer operator conforme al perfil, membership válida y capacidad. El tenantId de ruta selecciona recurso; el servidor valida pertenencia. Browser usa rutas equivalentes bajo /console/api mediante cookie/CSRF; no expone access token.

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

Añadir invitaciones y estados/roles/alcance necesarios mediante expand; conservar identidad única issuer/subject y membership lógica por tenant/identidad. USR-T01 define el modelo de reingreso tras revocación: conservar historial y usar una nueva revisión/lifecycle sin duplicar membership efectiva.

Proteger mutaciones de administradores bloqueando el agregado tenant antes de contar tenant_admin activos y cambiar membership. Invitar/aceptar/promover/reactivar/degradar deben usar el mismo orden de locks para no eludir la invariante por otra ruta.

Dentro de la transacción volver a validar revisión/capacidad del actor, cambios permitidos y tenant activo; persistir cambios, revisión de autorización, audit y outbox. Tras commit, FEAT-001 invalida/revalida el contexto. Mantener identidades/sesiones de otros tenants operables.

Invite token se genera con CSPRNG, se guarda hasheado para canje y se transporta por envelope temporal cifrado al worker. Outbox no contiene token/email en claro; los reintentos del proveedor tienen deduplicación y errores seguros. Reenviar con token nuevo revoca el anterior; no recuperar el código desde un hash.

## Hitos

| Hito | Dependencias | Gate |
| --- | --- | --- |
| U0 — Contrato y matriz | AUTH-T02/T03/T05/T07 | Permisos/campos/estados/modelo acordados; OpenAPI validado. |
| U1 — Lectura/aislamiento | U0 | Tabla real con filtros/cursor y roles negativos probados. |
| U2 — Invitación vertical | U1 + worker/IdP test | Admin invita, entrega sintética, identidad correcta acepta una vez. |
| U3 — Ciclo de acceso | U2 | Roles/suspensión/revocación y último admin bajo concurrencia. |
| U4 — UI y entrega | U3 | Journey con 412/403/expiración, auditoría y revalidación de sesión. |

## Pruebas y reversión

Contratos antes de UI integrada; dominio con reloj/entropía inyectados; Postgres con dos tenants y carreras; proveedor email falso y luego sandbox; E2E con administrador y no administrador.

Los comandos reales se incorporan al toolchain de AUTH-T01. Registrar migración, checks ejecutados y fixtures en el paquete al finalizar. No se afirma que el modelo SQL citado en fuentes ya exista.

Rollout tenant sintético, luego piloto. Deshabilitar escrituras si falla la validación de permisos; no borrar memberships ni historial para revertir. Invitaciones no entregadas se cancelan/expiran; nunca restablecer tokens revocados tras restore.

## Riesgos

IdP debe proporcionar identidad/email verificados conforme a política; no usar sólo igualdad de correo no verificado. El proveedor de notificación y TTL se concretan en USR-T01/T04. DB/RLS y consulta mínima de memberships del login deben coordinarse con AUTH para evitar circularidad o bypass global.
