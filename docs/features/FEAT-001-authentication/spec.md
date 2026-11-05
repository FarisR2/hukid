# FEAT-001 — Autenticación de operadores

- Producto: HukID Console / Team 5.
- Estado: AUTH-T01–T05 materializan bootstrap, contratos, PostgreSQL, login/callback y [lecturas autorizadas /me](../../03-design/console-operator-context.md) de laboratorio. AUTH-T06 añade [ciclo de sesión, refresh/logout y purga](../../03-design/console-session-lifecycle.md). Step-up, cambio de tenant y UI siguen pendientes.
- Dependencias: IdP OIDC, tenant/membership mínimo, PostgreSQL y auditoría.
- Salidas: [plan](plan.md), [tareas](tasks.md).

## Objetivo y actores

Un operador autorizado inicia sesión, cumple MFA, selecciona un tenant permitido y accede a la consola. La identidad OIDC es el par issuer/subject; el correo no es clave de identidad ni autoriza una membresía.

Actores: operador, IdP, BFF de consola, Management API y repositorio de tenants/memberships. Un usuario autenticado sin membresías activas sólo puede ver acceso pendiente, cerrar sesión o aceptar su invitación válida cuando FEAT-002 esté disponible.

## Alcance

Incluye login/logout, callback, verificación de tokens, sesión, renovación, MFA/step-up, selección tenant, identidad actual y protección de rutas. El tenant y primer administrador se provisionan mediante un proceso de bootstrap restringido; no por registro público.

Fuera: contraseñas propias, alta pública, administración de miembros, client credentials, OID4VCI y PIN/biometría de Flutter. La recuperación de cuenta y factores se delegan al IdP.

## Requisitos y aceptación

| ID | Comportamiento verificable | Criterio de aceptación |
| --- | --- | --- |
| AUTH-FR01 | Iniciar Authorization Code + PKCE con retorno allowlisted. | AC01: al abrir una ruta protegida sin sesión, se inicia login y sólo se retorna a un destino permitido tras autenticación. Un returnTo externo se rechaza. |
| AUTH-FR02 | Validar callback y consumir la transacción una vez. | AC02: state/nonce/issuer/PKCE inválidos, callback repetido o transacción expirada no crean sesión. No se acepta un destino derivado de entrada no validada. |
| AUTH-FR03 | Aceptar sólo identidad/token de operador en Management. | AC03: token integration, oid4vci, ID token usado como access token, aud múltiple/incorrecta o clase ausente producen rechazo antes de consultar datos del tenant. |
| AUTH-FR04 | Mantener sesión opaca server-side y renovar sin exponer tokens. | AC04: el navegador sólo conserva cookie segura; access/refresh tokens no aparecen en almacenamiento JS, HTML, URL de retorno ni respuestas de identidad. Renovación concurrente no genera familias inconsistentes; refresh reutilizado fuera del flujo válido revoca la familia. |
| AUTH-FR05 | Exigir MFA verificada y step-up para acciones privilegiadas. | AC05: sin evidencia confiable de MFA no se accede a consola operativa. MFA insuficiente o antigua para una mutación requiere reautenticación; la UI no puede afirmarla mediante un campo libre. |
| AUTH-FR06 | Resolver contexto tenant por membership activa. | AC06: un tenant se selecciona sólo si pertenece al operador y está activo. Otro tenant no cambia sesión ni carga información. Con varios tenants se muestra selector; con ninguno se muestra acceso pendiente. |
| AUTH-FR07 | Revalidar autorización local en cada petición protegida. | AC07: tras commit de suspensión/revocación de membership o tenant, la siguiente petición protegida se deniega aunque el token IdP siga vigente. No se promete cancelar operaciones que ya terminaron. |
| AUTH-FR08 | Cerrar sesión y manejar expiración/IdP caído. | AC08: logout invalida sesión local aunque falle logout federado; reutilizar cookie falla. Renovación no verificable se deniega, sin fallback inseguro. La UI ofrece reingreso sin bucle de redirecciones. |
| AUTH-FR09 | Exponer identidad mínima y capacidades efectivas. | AC09: /me devuelve actor opaco, tenant activo, memberships accesibles y capacidades calculadas; sin tokens ni roles tomados del navegador. Cambio de tenant limpia estado/caché de la vista anterior. |
| AUTH-FR10 | Auditar sin secretos y proteger comandos de sesión. | AC10: login/logout/context switch/denegaciones generan eventos mínimos correlacionables. CSRF inválido u origen ajeno no ejecutan cambios; no se registran code/state/token/cookie. |

## Restricciones de calidad

| ID | Restricción | Comprobación |
| --- | --- | --- |
| AUTH-QR01 | Cookie HttpOnly/Secure y política SameSite compatible con callback; tokens sólo server-side cifrados. | Inspección HTTP, storage del navegador y persistencia. Local HTTP sólo en configuración explícita de desarrollo. |
| AUTH-QR02 | Consentimiento MFA, errores y selector utilizables por teclado/lector. | E2E de foco, errores asociados, loading y retorno. |
| AUTH-QR03 | Lifetimes/clock skew/step-up/rate limits provienen de política validada, no de los TTL de Events. | Reloj controlado: antes/después de cada límite; arranque falla ante valores ausentes o incoherentes. |
| AUTH-QR04 | Contexto y respuesta privada no se cachean públicamente. | Cache-Control no-store, no fuga por pooling, navegación atrás o cambio de tenant. |

No se agrega un SLA numérico de login sin perfil de carga aprobado.

## Estados y reglas

Estados de sesión propuestos: anonymous → authenticating → authenticated; authenticated → step_up_required/expired/revoked. El flujo step-up crea una transacción OIDC nueva y sólo vuelve a authenticated con evidencia válida.

El selector es contexto solicitado, no autoridad: el servidor vuelve a resolver actor, tenant y membership. /v1/operator/me puede funcionar sin tenant activo y enumera sólo los contextos del propio operador. /console/api/me agrega la selección de la sesión y las capacidades obtenidas de /v1/operator/tenants/{tenantId}/context; las APIs tenant-scoped requieren contexto autorizado. Aceptación de invitación es la única operación futura de FEAT-002 permitida sin membership activa, bajo su propia autorización.

Los errores privados usan Problem Details; endpoints/redirecciones del IdP conservan sus protocolos. 401 indica sesión/token inválido; 403 autorización/MFA insuficiente; recurso tenant ajeno usa 404 cuando aplique; caída de dependencia tiene respuesta recuperable sin datos privados.

## Datos

Propuesta mínima: identidad por (oidc_issuer, subject), tenants, memberships y roles; sesiones/familias, transacciones OIDC y auditoría. El navegador no recibe refresh token. Código PKCE, verifier y tokens necesarios se guardan temporalmente cifrados y se purgan por política; IDs/códigos no recuperables se hashean cuando no se necesite reusarlos. No persistir sólo un hash de un secreto que el protocolo requiere recuperar.

## Trazabilidad y límites de decisión

| Fuente | Cobertura |
| --- | --- |
| [Arquitectura HukID §3.2/5](../../03-design/hukid-architecture.md) | OIDC/PKCE, MFA, contexto tenant y dominio separado. |
| [Perfil §6](../../03-design/hukid-profile.md#6-separación-de-tokens-y-audiences) | Clases/audiences exactas y rechazo de sustitución. |
| [Seguridad HukID](../../04-engineering/hukid-security-and-operations.md) | RBAC, claves, auditoría y entorno. |
| [HK-001/005](../../02-requirements/backlogs/team-5-hukid.md) y [fase 1](../../05-delivery/hukid-roadmap.md) | Foundation tenant, miembros y evidencias. |
| [ADR-0002](../../decisions/ADR-0002.md) | BFF, rutas, organización de código y políticas pendientes de validación. |

AUTH-T02 fija proveedor/claims/scopes/TTL para laboratorio en el [contrato de consola](../../03-design/console-auth-contract.md) y [ADR-0003](../../decisions/ADR-0003.md). `/me` puede devolver un synchronizer token de CSRF, sin access/refresh token ni autoridad desde el navegador. El claim privado `hukid_grant` fija procedencia humana en la consola; no redefine otras clases del perfil. La evidencia MFA del fixture es sintética; login integrado y producción requieren sus tareas, factores y validaciones adicionales.
