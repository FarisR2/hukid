# Login OIDC de consola — AUTH-T04

Estado: implementado y probado en laboratorio aislado. Hay handlers Go de login/callback, persistencia de transacciones y creación de sesión inicial; todavía no existe consola operativa. [ADR-0005](../decisions/ADR-0005.md) registra las decisiones y [AUTH-T02](console-auth-contract.md) conserva la autoridad del contrato/política.

## Flujo y fronteras

`GET /console/auth/login` acepta sólo retorno literal `/` —también cuando se omite— y rechaza URLs externas, variantes codificadas, parámetros duplicados y campos de login desconocidos. Genera state, nonce, binding y verifier independientes de 256 bits; usa S256 PKCE y guarda la transacción antes del 303 al IdP. La cookie `hukid_test_transaction` es HttpOnly, SameSite=Lax, Path=/console/auth, sin Domain. Su expiración sigue la política.

El callback exige exactamente uno de code/error, state, issuer exacto y una única cookie de binding. Comprueba que la transacción esté vigente, sin consumir y ligada al navegador/issuer/client/redirect URI. Un bloqueo de fila y actualización condicional serializan el consumo en PostgreSQL; el commit elimina el envelope del verifier antes de devolverlo al caso de uso. Dos callbacks concurrentes no intercambian dos códigos. State, nonce y binding sólo se persisten como SHA-256.

Después del consumo, OAuth denial, fallo de PKCE, nonce, tokens, cifrado, IdP o persistencia requieren iniciar otro login. Una respuesta incierta del token endpoint no provoca reintento automático del código. Se vuelve a comprobar la expiración local después del intercambio. Un callback sin binding o con issuer/state ajenos no consume la transacción legítima.

Discovery, authorization/token endpoints y JWKS pertenecen a la autoridad explícita configurada. El cliente HTTP bloquea redirects, limita respuestas a 1 MiB y tiene timeout de cinco segundos; la petición completa de login/callback también dispone de cinco segundos. Se exige metadata de S256, client_secret_basic, ES256 y respuesta con `iss` de RFC 9207. No se consulta una clave indicada por jku/x5u/JWK del token. JWKS permite recargar claves publicadas ante un kid nuevo.

El ID token autentica al sujeto: firma ES256/kid, issuer, audience del cliente, azp cuando exista, nonce, tiempos y at_hash cuando exista. El access token se verifica separadamente: typ=at+jwt, issuer, subject coincidente, audience operator escalar, client_id, clase operator, hukid_grant=authorization_code, jti, scope operator:read y evidencia MFA coincidente con el ID token. Se rechazan claims duplicados, audiences múltiples y arrays de access audience aunque tengan un elemento. No se sustituyen tokens entre superficies.

La expiración es estricta; el skew configurado limita evidencia futura iat/nbf/auth_time y no extiende deadlines locales. AMR/ACR proceden de tokens firmados del IdP y se contrastan con la política. El fixture continúa simulando los factores: estos controles no acreditan MFA real.

## Identidad y sesión inicial

La migración nueva [0003_console_login.sql](../../src/platform/internal/adapters/postgres/migrations/0003_console_login.sql) conserva las anteriores. `console_auth.register_operator` inserta o resuelve exactamente issuer/subject, nunca email. Su owner dedicado NOLOGIN/NOBYPASSRLS sólo recibe SELECT/INSERT sobre identidades; runtime tiene EXECUTE, sin INSERT directo ni escritura de memberships. El arranque rechaza runtime que herede ese owner.

El repositorio crea identidad, familia y generación 1 en una sola transacción posterior a la verificación. Un fallo hace rollback de las tres; el consumo OIDC anterior permanece confirmado. El tenant inicial es null y no se crean roles ni membresías. Una identidad ya existente conserva su ID y permisos locales.

Cookie y CSRF nuevos tienen 256 bits y sólo se guardan hasheados. El envelope recuperable contiene access token, refresh token y CSRF; usa AES-256-GCM, nonce aleatorio de 96 bits, key version y AAD `hukid:session:<familyId>:1:<keyVersion>`. El verifier usa AAD `hukid:oidc:<transactionId>:<keyVersion>`. Una sustitución de registro, propósito, versión o ciphertext falla la autenticación del envelope.

La sesión inicial no supera el deadline absoluto contado desde auth_time ni la duración absoluta/idle de la política. La cookie opaca sólo se emite después del commit. Se borra la cookie transaccional al completar el login y se retorna exclusivamente al destino persistido permitido; no se envían tokens, CSRF ni claims al navegador.

## HTTP y configuración

Las respuestas controladas llevan no-store, no-referrer y correlación opaca. Los errores usan Problem Details: 400 invalid_request/authentication_failed, 403 mfa_required, 429 rate_limited y 503 dependency_unavailable. 429/503 incluyen Retry-After. Métodos distintos de GET devuelven 405 sin efectos. El callback añade 403 al OpenAPI para explicitar el rechazo de MFA ya exigido por la spec.

Login/callback comparten un presupuesto por IP de conexión y ventana de política; callback añade binding hasheado. X-Forwarded-For no altera la IP. El limiter es local al proceso, con estado acotado a 4096 claves y rechazo al saturarse; no se presenta como limitador distribuido. No hay access log por petición ni reflexión de error_description, query, cookies o errores crudos de dependencias.

Con todas las variables de autenticación ausentes, Platform conserva sólo liveness. Para habilitar el laboratorio exige:

| Variable | Valor requerido |
| --- | --- |
| `HUKID_ENV` | test |
| `HUKID_AUTH_POLICY` | Ruta a política completa validada |
| `HUKID_LISTEN_ADDR` | IP loopback/puerto cuyo origen coincide exactamente con consoleOrigin; por defecto 127.0.0.1:8080 |
| `HUKID_SESSION_DATABASE_URL` | Credencial externa de rol runtime de sesión; IP loopback, DB hukid_test_*, sin fallback y sslmode=disable sólo para laboratorio |
| `HUKID_CONTEXT_DATABASE_URL` | Desde AUTH-T05: credencial separada hukid_context_runtime para la misma DB test |
| `HUKID_TENANT_DATABASE_URL` | Desde AUTH-T05: credencial separada hukid_tenant_runtime para la misma DB test |
| `HUKID_OIDC_CLIENT_SECRET` | Secreto del cliente test registrado, externo al repo |
| `HUKID_AUTH_KEY` | Clave externa de 32 bytes codificada en Base64 estándar |
| `HUKID_AUTH_KEY_VERSION` | Identificador no vacío de la clave; máximo 128 caracteres |

Configuración parcial/productiva, origen incoherente, rol inseguro o dependencia ausente impiden abrir el listener. El proceso no migra ni provisiona DB ni inicia el IdP. El harness de `npm run test:postgres` genera credenciales/claves en memoria, crea recursos propios y arranca el binario real y el IdP por un canal privado de pruebas; no requiere copiar secretos de ejemplo.

## Evidencia y límites

Las pruebas Go unitarias cubren cifrado/AAD, entropía, límites temporales, callbacks de un uso, concurrencia, retornos, HTTP/rate limiting y JWT negativos con firmas reales/claves efímeras. `npm run test:postgres` añade el binario Go real → IdP oidc-provider → callback → PostgreSQL, cookies, identidades nuevas sin membership, nonce/PKCE, binding/issuer, replay concurrente, expiración, OAuth denial, IdP caído y rollback de sesión. También prueba upgrade 0002→0003 con datos y grants mínimos. Son agentes HTTP, no navegador ni factores reales.

AUTH-T05 implementa [middleware Management y /me](console-operator-context.md), incluida lectura mínima de generación inicial. AUTH-T06 implementa [actividad/rotación de sesiones, refresh/logout y purga](console-session-lifecycle.md); un nuevo login de AUTH-T04 crea una familia nueva y no implementa esa rotación. AUTH-T07 añade [step-up/CSRF y selección tenant](console-reauthentication.md); AUTH-T08 conserva interfaz y navegador. AUTH-T09 integrará auditoría y AUTH-T10 operación/gate A4.

AUTH-T06 añade limpieza automática acotada de transacciones y sesiones vencidas. Siguen pendientes rotación/recuperación de claves y gestión productiva de secretos. Eliminar o cambiar la única clave configurada impide descifrar sus envelopes. El laboratorio usa bases descartables; antes de operación persistente se requieren retención/purga, invalidación y gestión de claves en sus tareas. Las lecturas protegidas se incorporaron en AUTH-T05 y logout en AUTH-T06.

Fuentes: [go-oidc v3.21.0](https://github.com/coreos/go-oidc/tree/v3.21.0), [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html), [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207.html), [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html).
