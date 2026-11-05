# FEAT-001 — Plan técnico

Referencia: [spec](spec.md), [tareas](tasks.md), [decisión propuesta](../../decisions/ADR-0002.md).

## Evidencia y decisiones

AUTH-T01 incorpora bootstrap Go y entry point React/TypeScript con Vite; ver [desarrollo local](../../04-engineering/local-development.md). El owner acordó `src/platform` y `src/console`. AUTH-T02 añade [contrato y política](../../03-design/console-auth-contract.md) según ADR-0003 y AUTH-T03 [persistencia con RLS](../../03-design/console-persistence.md) según ADR-0004. AUTH-T04 implementa [login/callback y sesión inicial](../../03-design/console-oidc-login.md) según ADR-0005; AUTH-T05/T06 añaden lecturas y ciclo de sesión; AUTH-T07 implementa [step-up y tenant-context](../../03-design/console-reauthentication.md). No se heredan sesiones/claims de Events.

AUTH-T05 incorpora [middleware operator y /me](../../03-design/console-operator-context.md), con decisión de lectura mínima de sesión en [ADR-0006](../../decisions/ADR-0006.md). El BFF guarda tokens en servidor y llama a Management con access token operator. Management sigue exigiendo Bearer: no se modifica para aceptar la cookie del navegador. Si se ejecutan en el mismo proceso, el adaptador conserva idénticas validaciones de token/actor y los límites de aplicación.

## Componentes y estado actual

| Área bajo src | Responsabilidad |
| --- | --- |
| platform/cmd/api | Bootstrap, configuración test y routing login/callback, /me y contexto operator. |
| platform/internal/bootstrap | Liveness y validación loopback existentes. |
| platform/internal/authentication | Política, puertos y casos de uso login/callback/sesión inicial existentes; ciclo de sesión implementado en AUTH-T06. |
| platform/internal/tenancy | Actor, membership, tenant y capacidades propias; administración de miembros pendiente. |
| platform/internal/adapters/oidc | Discovery restringido, intercambio PKCE y verificación de ambos tokens. |
| platform/internal/adapters/privateapi | Middleware operator, /me y contexto tenant, sin acoplar DTO al dominio. |
| platform/internal/adapters/console | Login/callback, /me, refresh/logout, cookies rotatorias, Origin/CSRF, rate limiting y errores; step-up/tenant-context desde AUTH-T07. |
| platform/internal/adapters/secretbox | Envelopes AES-256-GCM con AAD y clave externa; gestión productiva pendiente. |
| platform/internal/adapters/postgres | Migraciones, roles/RLS, contexto y descubrimiento mínimo, transacciones OIDC y creación inicial de identidad/sesión. Rotación/refresh/logout y purga desde AUTH-T06. |
| console/src/authentication | AUTH-T08: login/retorno, selector, guards y recuperación de sesión. |

Los componentes de autenticación indicados están implementados hasta AUTH-T08 en laboratorio, incluido el panel React. Auditoría integrada y operación/gate siguen en AUTH-T09/T10. Los módulos de miembros, dashboard y credenciales conservan sus tareas propias. El fixture IdP reside en tests y no forma parte de Platform. No crear módulos de emisión ni wallet para demostrar login.

## Contratos nuevos de consola

AUTH-T02 los materializa en [OpenAPI propio](../../../src/platform/contracts/console-auth.openapi.json), con política/semántica en el contrato de consola. La siguiente tabla conserva el inventario; el OpenAPI es la fuente de schemas y errores. AUTH-T04/T05 implementan login/callback y tres lecturas /me/context sólo para laboratorio; AUTH-T06 implementa refresh/logout; AUTH-T07 implementa [step-up y tenant-context](../../03-design/console-reauthentication.md). No son los endpoints /auth de Events.

| Ruta | Entrada / efecto | Seguridad |
| --- | --- | --- |
| GET /console/auth/login | returnTo allowlisted; crea transacción y redirige al IdP. | Rate limit; transacción ligada al navegador. |
| GET /console/auth/callback | code/state; valida y crea/rota sesión. | PKCE/nonce/state de un uso; errores no filtran secretos. |
| POST /console/auth/refresh | Renueva sesión/token cuando esté permitido. | Cookie + CSRF/origin; sincronización server-side. |
| POST /console/auth/logout | Revoca sesión local y limpia cookie. | Cookie + CSRF; idempotente. |
| POST /console/auth/step-up | Retorno interno/acción permitida; inicia MFA/reauth. | Cookie + CSRF; nunca recibe amr confiable del body. |
| POST /console/auth/tenant-context | tenantId; rota contexto tras resolver membership. | Cookie + CSRF; pertenencia comprobada. |
| GET /console/api/me | Compone identidad, contexto de sesión y capacidades del tenant activo. | Cookie; no-store. |
| GET /v1/operator/me | actorId y tenants permitidos; funciona sin contexto activo. | Access token operator; no tokens en respuesta. |
| GET /v1/operator/tenants/{tenantId}/context | Capacidades efectivas, issuerIds y authorizationRevision del propio operador para ese tenant. | Access token operator + membership activa; no directorio de terceros. |

activeTenantId se obtiene de la sesión validada para navegador. El BFF consulta /me y, cuando hay selección, /tenants/{tenantId}/context, y compone /console/api/me sin enviar la cookie a Management. Un consumidor directo de Management solicita contexto mediante la ruta/recurso y el servidor comprueba membership; no confía en headers tenant libres. Un ID token valida la sesión OIDC, pero no sustituye el access token exigido por Management.

## Datos y migraciones

AUTH-T03 crea migraciones nuevas contrastadas con el modelo HukID Markdown disponible; el DDL original sigue ausente. Los nombres y registros lógicos del [modelo de sesión](../../03-design/console-auth-contract.md#modelo-lógico-de-sesión-para-auth-t03t06) se materializan en tenancy.operator_identities/tenants/memberships/membership_roles y console_auth.oidc_transactions/session_families/sessions, con roles, constraints/RLS y audit/outbox mínimos propios. No se declara que sean el DDL original.

Identidad estable única por issuer/subject; membership única por tenant/identidad. El selector sólo lista memberships autorizadas usando consulta privilegiada mínima por identidad autenticada, sin desactivar RLS globalmente. Las lecturas tenant-scoped usan SET LOCAL y runtime no propietario/NOBYPASSRLS. Separar repositorio de sesiones y descubrimiento de contexto del repositorio normal tenant-scoped.

Bootstrap local crea dos tenants y operadores sintéticos, con secreto externo al repo; producción usa provisioning restringido y auditable. FEAT-002 amplía los mismos agregados y no recrea identidades.

## Hitos y gates

| Hito | Depende de | Salida verificable |
| --- | --- | --- |
| A0 — Entorno/contrato | AUTH-T01/T02 | Toolchain reproducible, IdP test, configuración MFA/TTL y OpenAPI válido. |
| A1 — Registro/sesión | A0 | Migraciones, bootstrap sintético, sesión tenant-scoped y tests de dos tenants. |
| A2 — Login vertical | A1 | Navegador→IdP→callback→/me→logout con tokens sólo en servidor. |
| A3 — Endurecimiento | A2 | Reauth, expiración, revocación viva, refresh concurrente y fallos de IdP/DB. |
| A4 — Entrega | A3 | Contrato/E2E, evidencia redaction y runbook; todas las AC/QR cubiertas. |

## Verificación y rollout

Los comandos vigentes están en [desarrollo local](../../04-engineering/local-development.md): check, test:postgres, build, smoke y test:browser. AUTH-T03–T07 agregan PostgreSQL/RLS, HTTP y middleware, sesión concurrente y comandos; AUTH-T08 incorpora navegador. El estado y la evidencia por tarea están en [tasks.md](tasks.md); las suites de laboratorio no acreditan MFA real, carga/restore ni producción. AUTH-T09 amplía auditoría/redacción y AUTH-T10 conserva el gate A4.

Habilitar inicialmente a tenant sintético en entorno aislado. Un rollback revoca/deshabilita acceso a consola, conserva auditoría y usa migración forward; no borra tablas de sesión ni cambia comportamiento OID4VCI. No hay modificaciones destructivas previstas.

## Riesgos y trabajo desbloqueado

Validar que el IdP pueda producir access tokens operator con audiencia/clase del perfil y evidencia MFA suficiente; no relajar el perfil para acomodar un proveedor. Si no puede, registrar alternativa del Authorization Server antes de conectar.

El siguiente incremento es AUTH-T09 sobre AUTH-T01–T08 ya entregadas; después AUTH-T10 documenta operación y evidencia del gate. El despliegue productivo conserva requisitos de proveedor/factores reales, secretos, HTTPS, soporte, retención y DoD, sin asumirlos aprobados por cerrar tareas de laboratorio.

## Incremento AUTH-T06

Los incrementos siguientes conservan la secuencia de entrega. Para el estado acumulado usar el encabezado de [tareas](tasks.md), no las pendientes que se describen al cierre de cada incremento anterior.

Se implementa el [ciclo de sesión](../../03-design/console-session-lifecycle.md) según [ADR-0007](../../decisions/ADR-0007.md): actividad autorizada, lease por familia, rotación atómica de generación y prueba CSRF, refresh OIDC sin reintento incierto, logout y mantenimiento acotado. El inventario anterior conserva la evolución por incremento. AUTH-T07 completa MFA/step-up y comandos; AUTH-T08 conserva la UI.

## Incremento AUTH-T07

[Reautenticación y contexto](../../03-design/console-reauthentication.md), según [ADR-0008](../../decisions/ADR-0008.md): nueva transacción OIDC ligada a familia/generación, autenticación reciente de la misma identidad y rotación atómica sin ampliar el absoluto. La migración 0005 añade generación al propósito step_up. Step-up y selección tenant exigen Origin/CSRF, JSON estricto y autorización server-side. Las futuras mutaciones privilegiadas deberán usar el gate VerifyPrivilegedOperator además de sus capacidades. AUTH-T08/T09/T10 conservan UI, auditoría integrada y gate A4.

## Incremento AUTH-T08

La [interfaz de autenticación](../../03-design/console-auth-interface.md), según [ADR-0009](../../decisions/ADR-0009.md), conecta React al BFF same-origin. Login y step-up ofrecen navegación JSON opcional, conservando 303; callback ofrece error HTML fijo al navegador. El origen de proxy local debe configurarse explícitamente y no se toma de headers. UI en español, teclado/foco, selección/acceso pendiente, refresh/logout/step-up, retiro de contexto y descarte de respuestas obsoletas. Web Locks coordina las peticiones entre pestañas sin transmitir secretos; BroadcastChannel invalida el contexto visual. No hay polling ni tokens/CSRF persistidos. La suite Chromium usa API, IdP y PostgreSQL propios. AUTH-T09/T10 conservan auditoría integrada y gate A4.
