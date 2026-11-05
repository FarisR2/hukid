# Contexto de operador y /me — AUTH-T05

Estado: implementado y probado en laboratorio. Complementa el [contrato](console-auth-contract.md), la [persistencia](console-persistence.md) y el [login](console-oidc-login.md). [ADR-0006](../decisions/ADR-0006.md) registra la lectura mínima de sesión adelantada desde AUTH-T06. El perfil sigue draft y los factores del IdP siguen siendo sintéticos.

## Autoridad y superficies

`GET /v1/operator/me` exige exactamente un header Bearer. El middleware verifica firma ES256 contra JWKS del issuer configurado, kid, typ, issuer, cliente, audience escalar exacta, clase operator, grant humano original, scope, tiempos y MFA antes de acceder a tenancy. Reutiliza el verificador del callback sin exigir un ID token. Cookies, roles, tenant headers y claims de roles no conceden autoridad.

La identidad local se resuelve por issuer/subject verificados; una identidad no registrada devuelve 401 y no se crea desde Management. Una identidad registrada sin membresías recibe actorId y tenants vacíos. No se expone subject, correo ni directorio de terceros.

`GET /v1/operator/tenants/{tenantId}/context` vuelve a consultar tenant y membership activos en cada petición. Una sola consulta con RLS y contexto transaccional obtiene revisión y roles propios. Tenant ajeno, inexistente, suspendido, membership suspendida/revocada e identificador inválido devuelven 404. Tras commit de una suspensión, la siguiente petición falla aunque el access token siga vigente. No se cancelan operaciones ya terminadas.

Las capacidades son la unión ordenada y sin duplicados de roles locales según la [matriz única](../../src/platform/contracts/capabilities.json), embebida en el binario. issuer_operator/support_readonly no obtienen directorio de miembros. issuerIds permanece vacío: aún no existe registro de asignaciones issuer ni autoridad sobre emisores. Las capacidades de futuras mutaciones describen permisos locales; no implementan esas operaciones ni sustituyen sus scopes/step-up. Un rol desconocido falla cerrado.

`GET /console/api/me` exige una única cookie opaca válida y no acepta Bearer como sustituto. Comprueba familia/generación activas, versión de política, deadlines estrictos y envelope AES-GCM con AAD. Verifica el access token recuperado con el mismo puerto Management y contrasta actorId con la sesión. Compone identidad propia, tenant seleccionado persistido y contexto vigente; sólo devuelve el synchronizer CSRF previsto por contrato, nunca access/refresh tokens. Una selección revocada falla con 404; no se sustituye silenciosamente por otro tenant.

El login todavía crea selección null. AUTH-T05 no implementa el comando de cambio de tenant ni selecciona uno automáticamente. El test provisiona selección mediante SQL administrativo únicamente para verificar la lectura autorizada. Los comandos BFF requieren CSRF/Origin y sus tareas posteriores.

## Sesión y dependencias

La lectura sólo admite la generación inicial 1 creada por AUTH-T04. No actualiza lastSeenAt ni extiende idle, rota cookies, renueva access tokens o implementa logout. Un access token vencido devuelve 401 aunque la sesión aún esté dentro de su deadline; AUTH-T06 completará continuidad/refresh. Ciphertext o CSRF inconsistente falla con 503 sin filtrar errores. Una cookie inválida/expirada/revocada devuelve 401. No se anuncia una sesión operativa completa.

El arranque test requiere ahora tres DSN externos para la misma base de laboratorio: HUKID_SESSION_DATABASE_URL (hukid_session_runtime), HUKID_CONTEXT_DATABASE_URL (hukid_context_runtime) y HUKID_TENANT_DATABASE_URL (hukid_tenant_runtime). Cada pool verifica su rol y rechaza herencia de otro runtime, owners o privilegios peligrosos. Se mantienen loopback, prefijo de base test, ausencia de fallback, configuración completa y fallo antes de escuchar. No se agregan migraciones ni permisos a los roles existentes.

Management conserva Bearer incluso al compartir proceso con el BFF. La composición usa puertos de aplicación y el mismo verificador; no hace HTTP contra sí mismo ni reenvía cookies. La lectura de roles usa el pool tenant con SET LOCAL; el descubrimiento mínimo usa funciones restringidas con credencial separada. Ningún snapshot de sesión es autoridad durable.

Las respuestas controladas incluyen no-store, no-referrer y correlación nueva. Los errores son Problem Details; sólo los 401 Management emiten WWW-Authenticate. Dependencia fallida devuelve 503/Retry-After. Los handlers disponen de timeout de cinco segundos. No hay access log ni cuerpos de dependencias reflejados. JWKS no verificable falla cerrado; un rechazo de verificación se presenta como 401.

## Evidencia y límites

| Aceptación | Verificación |
| --- | --- |
| AC03 | Tokens firmados positivos/negativos, integration/oid4vci/clase ausente/ID token, audience arrays, issuer/client/grant/scope, expiración, firma/kid y MFA. HTTP comprueba cero consultas a tenancy antes de autenticar y rechazo de cookies como Bearer. |
| AC06/07 | PostgreSQL real, dos tenants, cuatro roles, contexto propio, suspensión/revocación, revisión nueva y conexión reutilizada sin contexto residual. Binario HTTP real verifica tenant ajeno y suspensión con credenciales vigentes. El selector UI/comando sigue pendiente. |
| AC09/QR04 | Binario Go + IdP + PostgreSQL: /me sin membresía, contexto null/seleccionado consistente, CSRF, no-store y ausencia de credenciales en respuestas. Pruebas con reloj controlado verifican deadlines, política/generación y corrupción del envelope/CSRF. |

Comandos: npm run check, npm run test:postgres, npm run build y npm run smoke. La suite PostgreSQL se amplía a once pruebas Go superiores con subcasos; no son pruebas de navegador, MFA real, carga, restore o producción. Refresh/logout/rotación siguen en AUTH-T06; step-up/CSRF de comandos en AUTH-T07; UI en AUTH-T08; auditoría integrada y gate operativo en AUTH-T09/T10.
