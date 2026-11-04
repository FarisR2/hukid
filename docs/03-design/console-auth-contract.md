# Contrato de autenticación de consola — AUTH-T02

Estado: baseline ejecutable de laboratorio, validada como OpenAPI/JSON Schema y contra un IdP OIDC de pruebas. No implementa los handlers BFF/Management ni demuestra MFA real, RLS o interoperabilidad de credenciales. El perfil HukID sigue `v0.1-draft`.

## Fuentes de detalle

| Artefacto | Autoridad y alcance |
| --- | --- |
| [OpenAPI de consola y operador](../../src/platform/contracts/console-auth.openapi.json) | Nueve operaciones nuevas de FEAT-001, requests/responses, seguridad, errores y ejemplos sintéticos. Todas marcadas `not-implemented`. No reemplaza el OpenAPI histórico ausente. |
| [Política test](../../src/platform/config/auth.test.json) y [schema](../../src/platform/contracts/auth-policy.schema.json) | Valores del laboratorio; Go valida además relaciones entre duraciones y configuración explícita. |
| [Claims operator](../../src/platform/contracts/operator-token.schema.json) | Shape de claims del access token test; no verifica criptografía por sí solo. |
| [Matriz de capacidades](../../src/platform/contracts/capabilities.json) | Roles locales y restricciones; no otorga scopes OAuth ni permisos globales. |
| [Loader y reglas temporales](../../src/platform/internal/authentication/policy.go) | Rechazo de configuración ausente/incoherente, límites de sesión y MFA. Aún no conectado a peticiones autenticadas. |
| [Fixture IdP](../../tests/fixtures/oidc-provider.mjs) | `oidc-provider` con claves y secreto de cliente generados en memoria por ejecución. Usuarios/interacciones/MFA sintéticos. |

La selección y sus límites se registran en [ADR-0003](../decisions/ADR-0003.md); la [spec](../features/FEAT-001-authentication/spec.md) mantiene los criterios funcionales aún pendientes.

## Superficies, errores y autorización

El navegador usa cookie opaca con BFF del mismo origen; Management sólo acepta Bearer operator. El BFF no reenvía cookies a Management ni entrega access/refresh tokens al navegador. `/console/api/me` compone `/v1/operator/me` y, si hay selección, el contexto del tenant. `activeTenantId` y `context.tenantId` deben coincidir y pertenecer a `tenants`; sin selección ambos son null. Esa relación entre campos requiere validación de aplicación, no sólo del schema.

`csrfToken` de `/console/api/me` es un synchronizer token de 256 bits ligado a sesión, accesible a JavaScript únicamente para el header `X-CSRF-Token`; no es un token de acceso ni autoridad de identidad. Se regenera al crear/rotar sesión y cambiar tenant. Los POST requieren además `Origin` exactamente igual a `consoleOrigin`, incluido puerto. No se confía en `Referer`, CORS, roles de navegador ni headers tenant como autoridad. El callback usa cookie de transacción/estado/nonce/PKCE; el login limita `returnTo` a la lista exacta configurada. El perfil test sólo permite `/`, sin query, fragmento, URL absoluta ni variantes codificadas.

Todas las respuestas privadas/controladas usan `Cache-Control: no-store`, `Referrer-Policy: no-referrer` y `X-Correlation-Id` opaco. No registrar query de callback, códigos, state/nonce/verifier, cookies, secretos, JWT ni bodies de identidad. El borde deberá aplicar la misma redacción; el bootstrap no tiene access log por petición.

Los errores siguen Problem Details con `type=about:blank`, status, título seguro, `code` estable y correlación. No incluyen `error_description` del IdP ni detalles personales. 401 corresponde a credencial inválida; 403 a MFA/CSRF/origin/capacidad; 404 oculta tenant ajeno/inactivo; 409 a renovación concurrente en progreso; 422 a input inválido; 429 a límites; 503 a dependencia. 409/429/503 devuelven `Retry-After`. Sólo los 401 Bearer de Management requieren `WWW-Authenticate`. El protocolo del token endpoint del IdP conserva errores OAuth.

Los comandos BFF de sesión no reutilizan el header de idempotencia de las APIs de emisión: callback/PKCE se consumen una vez; refresh se coordina por familia; logout es idempotente con prueba CSRF verificable; selección repetida del mismo tenant vuelve a autorizar y no amplía permisos. Las futuras mutaciones Management de miembros sí seguirán idempotencia/revisión de [FEAT-002](../features/FEAT-002-user-management/plan.md).

## Identidad, grant y capacidades

Antes de consultar tenancy se deben verificar firma con JWKS del issuer configurado (sin `jku` ni redirects a otra autoridad), ES256 para este laboratorio, `kid` reconocido, `typ=at+jwt`, issuer exacto, `client_id` registrado, audience operator exacta y escalar, clase `operator`, tiempo, scope `operator:read` y evidencia MFA confiable. El cliente nunca obtiene autoridad desde un ID token. El rechazo de arrays de audience de un solo elemento es una restricción explícita de esta consola, además del rechazo normativo de audiences múltiples.

Se define `hukid_grant=authorization_code` como claim privado nuevo de la consola para la procedencia humana original; se conserva tras refresh. No es un cambio retroactivo al formato de integration/OID4VCI ni una equivalencia con `gty` de otros proveedores. El IdP test sólo registra Code + refresh; no habilita password, implicit ni client credentials para operador. Un proveedor futuro debe mapear esta procedencia de forma verificable o requerirá revisión del contrato.

`operator:read` autoriza solicitar identidad/contexto propio, sin conceder lectura de miembros por sí mismo. Se revalida membership activa en cada petición tenant-scoped antes de usar capacidades. El conjunto de roles se resuelve en servidor; el issuer scope limita `issuer_operator`, y `support_readonly` sólo obtiene agregados técnicos sin PII/claims. Tener `dashboard:read` no convierte todos los dashboards en equivalentes. Las capacidades futuras de escritura de la matriz quedan condicionadas por sus contratos, scopes y step-up de USR-T01; AUTH-T02 no implementa esas operaciones.

## Política temporal del laboratorio

Los valores numéricos se mantienen únicamente en `auth.test.json`. Access/ID token dura cinco minutos; transacción OIDC cinco minutos; inactividad de sesión treinta minutos; límite absoluto y familia refresh ocho horas; step-up cinco minutos; skew treinta segundos; login/callback admiten diez intentos por minuto. Son decisiones de laboratorio de HukID, no TTL heredados de Events ni defaults productivos.

En el futuro rate limiter, combinar IP de conexión confiable y binding de transacción antes de login; tras autenticar, añadir actor/familia. No confiar en `X-Forwarded-For` de un cliente directo. No se implementa todavía rate limiting HTTP.

Expiración local es estricta: en el instante del deadline ya está expirada. Skew sólo admite evidencia IdP con `auth_time` hasta el margen configurado en el futuro; no se suma al deadline local, freshness de step-up ni duración absoluta. Exigir ambos `pwd` y `otp` más ACR test exacto. Refresh preserva `auth_time` y MFA originales; nunca crea autenticación reciente. Step-up requerirá nueva transacción OIDC con `prompt=login`, `max_age=0` y verificación de la nueva evidencia, sin leer AMR/ACR del body. El fixture inyecta estos valores desde el harness: no comprueba contraseña/OTP ni certifica assurance real.

Test cookie de sesión: `hukid_test_session`; HttpOnly, SameSite=Lax, Path=/, sin Domain, Secure=false sólo en loopback explícito. Cookie de transacción independiente: `hukid_test_transaction`, HttpOnly, SameSite=Lax, Path=/console/auth, sin Domain y duración de transacción. Ninguna existe aún en el servidor. Producción requiere HTTPS, cookies Secure con nombres/política separados, IdP y factores reales aprobados; el loader actual rechaza entornos distintos de `test`.

## Modelo lógico de sesión para AUTH-T03/T06

Estos nombres son diseño nuevo de consola, contrastado con el ownership `tenancy` del [modelo HukID](hukid-data-model.md); no son el DDL original ni migraciones ejecutadas. Identidad por `(oidc_issuer, subject)`, nunca por email. Se fijan `tenancy.operator_identities`, `tenancy.tenants`, `tenancy.memberships`, `tenancy.membership_roles`; el schema privado `console_auth` contiene `oidc_transactions`, `session_families` y `sessions`. AUTH-T03 materializa constraints/roles/RLS e índices, sin copiar datos Events.

| Registro | Campos lógicos y protección |
| --- | --- |
| OIDC transaction | ID opaco, hash de state/nonce/binding, issuer/client/redirectUri/returnTo exactos, propósito login/step-up, verifier recuperable cifrado, createdAt/expiresAt y consumedAt. CAS consume una vez antes de crear sesión; fallos posteriores requieren nueva transacción. |
| Session family | ID opaco, identidad `(issuer, subject)` referenciada, createdAt/absoluteExpiresAt, authTime/amr/acr verificados, estado active/revoked/expired y razón segura; grant original y versión de política. |
| Session generation | Hash de cookie de alta entropía, familyId/generation/version, hash de CSRF, lastSeenAt/idleExpiresAt, tenant seleccionado opcional y revisión de autorización observada. CSRF recuperable para `/me` y tokens/verifier necesarios se guardan cifrados, no sólo como hash. |
| Token envelope | Access/refresh cifrados con AES-256-GCM, nonce único de 96 bits, key version y AAD por propósito/familia/generación; expiración y digest de refresh para detectar reuse. Clave fuera de DB y repo; no se almacenan ejemplos ni claves privadas. |

AUTH-T03 necesita FK/constraints compuestas, RLS con rol no propietario/NOBYPASSRLS y `SET LOCAL` para datos tenant-scoped. La consulta mínima de contextos del operador y el store de sesión usan roles/puertos separados y no abren un bypass RLS general. La autorización se vuelve a resolver tras commit de suspensión/revocación; un snapshot de capacidades de sesión nunca es autoridad durable.

Máquina de estados: anonymous → authenticating → authenticated; authenticated → step_up_required/expired/revoked. Una reautenticación crea transacción nueva ligada a familia; sólo una evidencia válida retorna a authenticated. Una sesión sin membership operativa sólo puede leer identidad propia, cerrar sesión o seleccionar un contexto permitido; la aceptación futura de invitaciones tiene su autorización específica.

Refresh se serializa por familia/generación mediante lease/CAS, sin enviar dos refresh simultáneos al IdP. Peticiones que ya validaron la misma generación pueden compartir el resultado en curso; una petición posterior con cookie antigua no recupera el sucesor. Si otra petición ya renueva, esperar dentro del timeout de dependencia o responder 409/Retry-After; no iniciar otra familia. Si el IdP pudo consumir refresh y se pierde su respuesta, la operación queda incierta: intentar de nuevo el mismo refresh no es seguro. Invalidar localmente esa familia y exigir nuevo login; no reconstruir tokens ni publicar éxito. Si se pierde la respuesta BFF después del commit, `/me` determina si el navegador recibió la nueva cookie; si sólo conserva la anterior se exige login nuevo. Se acepta esta pérdida de continuidad para evitar un canal de recuperación/replay con cookie obsoleta. AUTH-T06 debe probar ambas ventanas antes de exponer refresh.

Logout invalida primero la familia local y limpia cookie aunque falle el IdP. Un tombstone con hashes de cookie/CSRF permite repetir sólo logout hasta la expiración absoluta original; jamás `/me`, refresh u otras operaciones. Si ya no hay prueba CSRF verificable, responder 403 sin efectos. Purgar secretos inmediatamente al invalidar; conservar sólo evidencia mínima/tombstone hasta su vencimiento. Retención institucional de auditoría sigue pendiente y no se fija por la duración de sesión.

## Pruebas y cobertura actual

`npm run test:auth` valida OpenAPI y sus ejemplos con schemas estrictos, rechaza campos extra y escalamiento de rol/capacidad, verifica matriz y política, arranca el IdP real de biblioteca y realiza Code + S256 PKCE, firma/JWKS, audiencia/clase, separación de ID token, expiración, refresh y rechazo de reuse. El agente HTTP de pruebas no es un navegador. El adapter en memoria del IdP es deliberado y avisa de su uso exclusivo de laboratorio.

`npm run check:platform` añade rechazo de todos los campos ausentes, JSON inválido/desconocido, duraciones incoherentes, host/configuración no permitidos, boundaries de MFA/sesión y validación previa al arranque. Son reglas de política y tests del fixture; el futuro middleware Go deberá verificar tokens/membership por sí mismo en AUTH-T04/T05. No se han probado cookies reales, CSRF HTTP, store de sesión, DB/RLS, MFA real, concurrencia BFF ni UI. El gate A0 sólo queda cubierto en laboratorio; A1–A4 siguen pendientes.

Fuentes externas para el diseño: [OpenAPI 3.1](https://spec.openapis.org/oas/v3.1.0), [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html), [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html), [OAuth Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html) y [API oficial de oidc-provider](https://github.com/panva/node-oidc-provider/blob/main/docs/README.md). El uso del formato de RFC 9068 en el laboratorio no declara conformidad completa con todos sus algoritmos o requisitos.

El callback test exige también `iss` igual al issuer de la transacción, además de state/binding. El AS anuncia soporte para identificación de issuer de [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207.html); se comprueba el valor también en respuestas OAuth de error. HTTP loopback es una excepción exclusiva del laboratorio, no evidencia de cumplimiento de los requisitos HTTPS productivos de esa RFC.
