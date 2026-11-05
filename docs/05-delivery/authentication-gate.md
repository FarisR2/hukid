# Gate A4 de autenticación — evidencia AUTH-T10

Fecha: 2026-11-05. Owner: Team 5. Alcance: laboratorio aislado Windows x64, AUTH-T01–T10 y nueve operaciones del OpenAPI propio. El [runbook](../04-engineering/console-auth-runbook.md) mantiene preparación, rollout, diagnóstico y retirada/reactivación.

## Criterio de cierre

A4 de laboratorio exige checks ejecutados sobre una revisión identificada, trazabilidad de AC01–AC10/QR01–QR04, evidencia de redacción y ensayo de reversión. Este cierre habilita el siguiente incremento de desarrollo; no sustituye la sección release/producción de la [DoD](definition-of-done.md), el conformance gate ni la validación de factores reales.

La especificación usa términos generales como MFA confiable, cookie Secure y rutas protegidas. Los ADR-0003–0010 y la política test acotan su comprobación: MFA es evidencia sintética firmada, HTTP/Secure=false sólo en loopback y la consola contiene la pantalla raíz de autenticación. Ingreso/reingreso se inicia mediante acción explícita según ADR-0009 para evitar bucles; guards de rutas de miembros/dashboard aún no existen porque esos módulos no están construidos. No interpretar esta matriz como cobertura de esos productos o validación de MFA/cookies HTTPS productivas.

## Matriz de aceptación y evidencia ejecutable

| Criterio | Evidencia existente que ejecuta el gate | Alcance o pendiente |
| --- | --- | --- |
| AC01 / FR01 | TestLoginHTTPWithRealOIDCAndPostgres: retorno inválido/duplicado; tests login Go; Chromium login/retorno. | Sólo destino raíz allowlisted e ingreso explícito; otras rutas conservan su feature. |
| AC02 / FR02 | HTTP nonce/PKCE/issuer/state/binding, expiración, callback concurrente/replay, rollback. | IdP de biblioteca con claves efímeras. |
| AC03 / FR03 | tests OIDC operator/privateapi, contracts.test.mjs, TestLiveOperatorAuthorizationAndPoolIsolation. | Clase/audience/firma antes de tenancy; no conformance VC. |
| AC04 / FR04 | TestSessionLifecycleConcurrencyLossAndLogout, HTTP refresh, AES/AAD, navegador storage. | Cookie opaca; envelopes server-side; respuesta perdida exige login según contrato. |
| AC05 / FR05 | tests policy/operator/reauthentication y step-up HTTP/navegador. | Evidencia MFA sintética; gate de privilegios disponible para futuras mutaciones USR, sin afirmar que esas mutaciones existen. |
| AC06 / FR06 | Contexto/HTTP de dos tenants y Chromium cero/uno/varios, selección ajena/suspendida. | Membership local viva, selector sin autoridad propia. |
| AC07 / FR07 | TestLiveOperatorAuthorizationAndPoolIsolation y HTTP/navegador de suspensión vigente. | Deniega petición siguiente al commit; no cancela operaciones terminadas. |
| AC08 / FR08 | refresh/logout con IdP caído, cookie revocada, expiración, navegador sin bucles. | Logout local confirma DB aunque falle IdP; no garantiza revocar todos sus grants. |
| AC09 / FR09 | /me propio y capacidades, pooling/tenant, cambio y descarte de respuesta tardía/historial/pestañas. | Sin directorio ajeno; issuerIds vacío no entrega gestión de emisores. |
| AC10 / FR10 | auth audit HTTP, TestAuthAuditAtomicityPermissionsAndUpgrade y tests audithttp/Origin/CSRF. | Éxitos atómicos; denegaciones best effort acotadas con alerta fija. |
| QR01 | HTTP cookies, AES-GCM/AAD, digests, auditoría y storage de navegador. | Secure=false exclusivamente test loopback; HTTPS/Secure productivo pendiente. |
| QR02 | Chromium teclado/foco/errores/loading/selector y capturas previas AUTH-T08. | No certifica WCAG ni prueba factores o lector de pantalla real. AUTH-T10 no cambia UI. |
| QR03 | Tests de política, relojes/TTL/skew, step-up, rate limit y arranque rechazado por smoke. | Valores del archivo test; sin política productiva/SLA. |
| QR04 | Private no-store, RLS/pooling, contexto desmontado, historial y pestañas. | Sin certificación de proxies/cachés externos. |

Las funciones y escenarios se encuentran en [tests de PostgreSQL/HTTP](../../src/platform/internal/adapters/postgres), [authentication](../../src/platform/internal/authentication), [adaptadores](../../src/platform/internal/adapters), [contratos Node](../../tests/auth) y [suite Chromium](../../tests/browser/authentication.py). La [trazabilidad de tareas](../features/FEAT-001-authentication/tasks.md) conserva los incrementos y sus snapshots fechados.

## Ensayo operativo AUTH-T10

El subcaso operational_disable_invalidate_and_reenable de TestLoginHTTPWithRealOIDCAndPostgres ejecuta el CLI real contra el clúster propio:

1. Obtiene sesión/cookie válida y callback pendiente; detiene su API.
2. Rechaza invalidación por runtime, flag ausente y contexto cancelado.
3. Inyecta fallo de outbox y comprueba rollback: no hay evento parcial, sesión modificada ni callback consumido.
4. Ejecuta invalidate-auth como administrador test; comprueba revocación, purga de secretos/leases y consumo de pendientes; conserva memberships y migraciones. Repetir no duplica eventos.
5. Reinicia sin configuración auth: sólo health 204; rutas auth/operator 404 aun con cookie.
6. Reactiva configuración completa: cookie anterior 401, callback pendiente 400 y login nuevo válido.

Esto prueba retirada y reactivación del mismo binario/esquema; no prueba rollback a una revisión incompatible, restore DB, rotación de claves, drenado por señales o despliegue productivo. La operación no revoca tokens/grants emitidos en el IdP. No se ejecutó contra una base existente.

## Definition of Done aplicable al incremento

| Requisito DoD | Resultado / alcance |
| --- | --- |
| Actor, owner, alcance y criterios | Spec/plan/tasks y esta matriz; Team 5, operador y mantenedor del laboratorio. |
| Contratos/estados/aislamiento | Contrato OpenAPI sin nueva ruta; CLI local test-only; negativos y RLS en suites. |
| Idempotencia/concurrencia | Rotaciones/logout/replay existentes; invalidación repetible y rollback offline. No hay consumidor externo que acreditar. |
| Migraciones | AUTH-T10 no añade DDL. Se vuelven a ejecutar vacío/upgrades/checksum de 0001–0006. |
| Auditoría y diagnóstico | Éxitos/outbox atómicos y correlación; runbook con señales y consultas agregadas sin secretos. Métricas/dashboard/alertas productivas siguen pendientes. |
| Journey/accesibilidad | E2E de laboratorio repetido; no hay nuevos controles visuales ni certificación. |
| Runbook y evidencia | Guía operativa, gate local con informe, ensayo de retirada/reactivación y workflow versionado. CI remoto requiere publicación/ejecución propia. |

## Resultado y límites de entrega

La evidencia ejecutada de este incremento se registra en [tareas AUTH-T10](../features/FEAT-001-authentication/tasks.md#evidencia-auth-t10--2026-11-05). El informe local generado es .cache/auth-gate/latest.json y está ignorado: no subir logs, claves ni directorios de PostgreSQL. No reutilizar un passed antiguo después de cambiar fuentes.

Producción permanece **NO-GO**: IdP/factores y políticas reales, HTTPS/cookies Secure, provisioning/secretos/rotación, retención institucional, observabilidad/alertas/on-call, carga/SLO, backup/restore y DR aún no están acreditados. El publisher/visor de auditoría y un entorno demo persistente tampoco forman parte de este incremento. La pérdida posible de denegaciones ante caída DB/proceso está documentada, no resuelta por el runbook.

El perfil HukID conserva v0.1-draft y el negocio de emisión/wallet/verificación sigue su roadmap. Después de AUTH-T10 corresponde USR-T01 de FEAT-002, conservando AUTH→USR→DASH.
