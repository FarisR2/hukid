# MFA, step-up y comandos de contexto — AUTH-T07

Estado: backend de laboratorio; factores sintéticos y sin consola visual. Decisión: [ADR-0008](../decisions/ADR-0008.md). Complementa [login](console-oidc-login.md), [sesión](console-session-lifecycle.md) y [contexto operator](console-operator-context.md). [OpenAPI](../../src/platform/contracts/console-auth.openapi.json) conserva schemas y respuestas.

## Inicio y callback

`POST /console/auth/step-up` recibe exclusivamente `{"returnTo":"/"}`. Exige una cookie vigente, `Origin` exactamente igual a consoleOrigin y un único `X-CSRF-Token` de la generación. El servidor crea state/nonce/PKCE/binding nuevos y guarda familia/generación en la transacción. Devuelve 303 al IdP y cookie HttpOnly de transacción.

Se pide `prompt=login consent`, `max_age=0` y ACR configurado. Consent conserva offline_access para obtener refresh nuevo; login exige reautenticación. [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest) define prompts múltiples/max_age; su [sección de acceso offline](https://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess) exige consentimiento. Esto concreta la propuesta previa que decía sólo prompt=login.

El callback compartido consume la transacción antes del intercambio y exige binding, issuer y la cookie de la familia/generación originales. Verifica firmas, nonce, audiences/clases/procedencia, correspondencia entre ambos tokens y MFA configurada. El access token anterior puede estar expirado únicamente como evidencia histórica firmada para comparar issuer/subject: no autoriza una petición Management. Cambiar de cuenta rechaza el callback y no registra otra identidad.

`auth_time` debe ser igual o posterior al segundo de creación de la transacción, además de estar dentro de stepUpSeconds. Se respeta la resolución de segundos de OIDC. El margen futuro usa clockSkewSeconds; no se añade skew al límite de freshness ni a vencimientos locales. Se revalida tras las dependencias y antes de persistir.

La actualización compara generación bajo lock de familia, sin locks durante la llamada OIDC. Rota cookie/CSRF, access/refresh/nonce y envelope con AAD de la generación nueva; actualiza auth_time/amr/acr de la familia. Conserva tenant y límite absoluto original. Logout, expiración, refresh con lease o una rotación concurrente impiden el commit. Un callback fallido no eleva ni prolonga la sesión previa; su transacción consumida no se reutiliza. Con respuesta perdida tras commit, la cookie antigua no recupera la nueva.

## Selección de tenant

`POST /console/auth/tenant-context` recibe exclusivamente `{"tenantId":"<id>"}` y exige la misma protección Origin/CSRF. Antes de rotar se verifica Bearer operator server-side, identidad local y membership/tenant activos mediante los pools separados existentes. Tenant ajeno, suspendido o malformado produce 404 sin modificar contexto.

El comando rota cookie/CSRF/AAD y guarda tenant/revisión resueltos en servidor; no devuelve tokens ni capacidades persistidas desde el navegador. Repetir la selección vuelve a autorizar y rotar. `/console/api/me` compone nuevamente capacidades vigentes. Una suspensión que termine entre la lectura y el commit puede dejar una selección sin autorización vigente: la siguiente petición la rechaza. No se promete cancelar operaciones que ya terminaron. AUTH-T08 debe limpiar estado/caché de vista al cambiar tenant.

## Perímetro, almacenamiento y errores

JSON único de hasta 1024 bytes, con exactamente la propiedad requerida; se rechazan duplicados, claims extra, datos trailing, query y retorno externo. Origin se comprueba antes del store; CSRF se compara con hash de la sesión antes de crear transacción/rotar. Límite por IP de conexión y actor autenticado, local al proceso; no se confía en X-Forwarded-For. Respuestas privadas no-store/no-referrer/correlacionadas y Problem Details sin secretos. 401 indica sesión inválida, 403 MFA/CSRF/Origin, 404 contexto no autorizado, 422 entrada inválida, 429 límite y 503 dependencia.

[Migración 0005](../../src/platform/internal/adapters/postgres/migrations/0005_console_reauthentication.sql) añade session_generation: null para login, positiva para step_up y ligada por FK compuesta a la generación existente. No modifica migraciones aplicadas ni grants. Una transacción step_up histórica sin generación impide aplicar el CHECK: el operador de laboratorio debe resolver ese dato inválido antes de reintentar; no se borran transacciones automáticamente. El runtime anterior nunca emitía step_up. El mantenimiento AUTH-T06 purga las transacciones vencidas.

`VerifyPrivilegedOperator` verifica el Bearer vigente y aplica freshness con error `step_up_required` al llegar al deadline. Es el puerto para futuras mutaciones privilegiadas de FEAT-002; sus handlers deberán combinarlo con scopes/capacidades y membership vigentes. Este incremento no añade administración de miembros ni aplica step-up a lectura, logout o selección ordinaria.

## Verificación y límites

Pruebas unitarias cubren parámetros OIDC, MFA/freshness, familia/generación/cookie, identidad distinta, evidencia antigua, expiración durante dependencia, fallos, replay y JSON/headers rechazados. PostgreSQL/HTTP con API e IdP de biblioteca propios recorre step-up→callback→me→selección; verifica rotación, mismo límite absoluto, CSRF anterior, tenant ajeno y suspensión. Pruebas DB ejercitan dos callbacks concurrentes, conflicto con lease/logout y rollback tras retirar la generación anterior. El upgrade desde 0003 conserva la sesión al aplicar 0004/0005.

Comandos de validación: `npm run check`, `npm run test:postgres`, `npm run build`, `npm run smoke` y `git diff --check`. La evidencia final se registra en [tareas](../features/FEAT-001-authentication/tasks.md). El harness crea sólo IdP/DB/procesos descartables; no usa bases existentes.

No acredita factores reales, navegador, rate limiting distribuido, carga/restore ni producción. AUTH-T08 conserva interfaz y pruebas de navegador; AUTH-T09 auditoría/redacción integrada y AUTH-T10 operación/gate A4. El perfil sigue v0.1-draft y no cambia Events ni wallet.
