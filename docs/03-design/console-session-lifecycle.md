# Ciclo de sesión de consola — AUTH-T06

Estado: implementación de laboratorio; complementa [contrato](console-auth-contract.md), [login](console-oidc-login.md), [contexto operator](console-operator-context.md) y [ADR-0007](../decisions/ADR-0007.md). No habilita una consola productiva ni cambia el perfil draft.

## Actividad y generaciones

`GET /console/api/me` descifra la generación activa con AAD por familia/generación, verifica el access token y vuelve a resolver la autorización local. Sólo una lectura completamente autorizada actualiza `last_seen_at` e inactividad. El deadline absoluto original nunca se amplía. Un access token vencido exige refresh explícito; `/me` no renueva de forma implícita.

`POST /console/auth/refresh` requiere una cookie opaca, un único `X-CSRF-Token` y `Origin` exactamente igual al configurado. Se rechazan queries, bodies y transferencia chunked. Origin inválido devuelve `origin_invalid`; prueba CSRF inválida, `csrf_invalid`. Todas las respuestas son no-store y correlacionadas. La protección de estos dos comandos se adelanta desde AUTH-T07; step-up y cambio de tenant siguen pendientes.

El store bloquea primero la familia y confirma un lease persistente de diez segundos antes del intercambio. La petición HTTP dispone de cinco segundos para la dependencia. Otro refresh de la misma generación responde 409 con Retry-After y no llama al IdP. No se roba un lease para reintentar un intercambio incierto.

Tras verificar el refresh, una transacción retira los secretos de la generación anterior, inserta una única sucesora y libera el lease. Se conservan familia, identidad, contexto persistido y límite absoluto; cookie, CSRF y refresh digest cambian. La migración 0004 añade lease/deadline e índice único de generación activa por familia, sin modificar migraciones publicadas.

El adaptador OIDC hace un solo intento, verifica el access token nuevo y conserva subject, auth_time, AMR y ACR originales. Puede validar la firma y evidencia del access token anterior vencido únicamente dentro de este camino privado de refresh. Un ID token de refresh es opcional; cuando existe se valida firma, issuer, audiencia/azp, identidad, tiempos, evidencia, at_hash y nonce si lo incluye. El hash del nonce original se conserva cifrado desde el login; una sesión histórica que carezca de él no acepta un nonce nuevo y requiere reingreso.

## Concurrencia y respuestas perdidas

| Ventana | Resultado |
| --- | --- |
| IdP pudo consumir el refresh, pero su respuesta se pierde | Se invalida la familia y se purgan secretos mediante un contexto de limpieza independiente del navegador. No se repite el refresh. |
| Fallo al guardar la nueva generación | Rollback de la rotación y revocación local; nunca se emite cookie de éxito. |
| BFF confirma rotación, pero el navegador pierde la respuesta | La cookie anterior no lee ni recupera la sucesora. `/me` permite comprobar si llegó la nueva cookie; si sólo quedó la anterior, se necesita login nuevo. |
| Reutilización de una generación retirada con su CSRF válido | Se revoca la familia, incluida la sucesora. |
| Proceso muere o falla la limpieza inmediata | El lease persistente bloquea lecturas; al vencer se revoca por mantenimiento o por el siguiente refresh. No se reintenta contra el IdP. |
| Logout mientras hay refresh | Logout revoca primero; el intercambio en curso ya no puede confirmar una sucesora. |

Una solicitud sin prueba CSRF válida no revoca la familia. No hay recuperación del sucesor mediante cookies antiguas ni nueva familia implícita.

## Logout y mantenimiento

`POST /console/auth/logout` confirma primero la revocación local y la purga del envelope/digest; luego intenta revocación OAuth si discovery anuncia el endpoint. Fallos del IdP o del descifrado posterior no revierten el logout. Devuelve 204 y elimina la cookie. Los hashes de cookie/CSRF de las generaciones retiradas permiten repetir sólo logout hasta la expiración absoluta; no permiten `/me` ni refresh. Una prueba ausente o desconocida responde 403 sin borrar cookies.

El API ejecuta mantenimiento al iniciar y cada minuto, con timeout de cinco segundos y lotes de cien familias. Invalida familias inactivas y leases abandonados; elimina generaciones, transacciones ligadas y familia al vencer el límite absoluto. También elimina hasta cien transacciones OIDC vencidas por ejecución. Bloquea familias con `SKIP LOCKED` y conserva el orden de bloqueo de los comandos. El cierre espera al worker antes de cerrar su pool.

Es mantenimiento de laboratorio sin SLA de purga: un backlog puede requerir varios ciclos y un fallo de DB retrasa la eliminación física. Los deadlines se aplican en cada operación aunque no haya corrido el worker. Alertas, métricas de limpieza, retención institucional de auditoría, recuperación de claves y operación productiva siguen pendientes.

## Verificación

- `npm run check:platform`: reglas temporales y de integridad, validación criptográfica de refresh con ID token opcional, rechazo de sustitución/identidad/MFA/nonce, intercambio sin reintento y negativos HTTP antes del store.
- `npm run test:postgres`: clúster descartable, rotación y AAD generacional, concurrencia, replay, ambas ventanas de pérdida, rollback, cancelación, lease abandonado, logout concurrente/idempotente, expiración/purga y API Go real con IdP/DB.
- `npm run check`, `npm run build`, `npm run smoke` y `git diff --check`: gates generales del incremento.

Las pruebas no son un navegador, factores MFA reales, prueba de carga, caída física de un host ni ensayo de restore. Las pérdidas y el fallo de persistencia se inyectan mediante los puertos reales de aplicación y restricciones de PostgreSQL; el adaptador HTTP OIDC prueba desconexión sin reintento. AUTH-T07–T10 conservan sus entregas y el gate A4 sigue abierto.

El diseño conserva las reglas de [OIDC Core §12.2](https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse) y la detección de replay descrita en [RFC 9700 §4.14.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14.2), dentro del perfil explícito de laboratorio; no declara conformidad completa.

Validación final AUTH-T06: `npm run check`, `npm run test:postgres`, `npm run build`, `npm run smoke` y `git diff --check` aprobados en Windows. La suite PostgreSQL contiene trece pruebas Go superiores con subcasos; incluye upgrade 0003→0004 conservando la sesión y rechazo de dos generaciones activas. No hubo publicación ni cambios sobre bases existentes.
