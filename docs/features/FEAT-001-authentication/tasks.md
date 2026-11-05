# FEAT-001 — Tareas

Estado: AUTH-T01–T05 completadas para bootstrap, contratos, PostgreSQL, login/callback y lecturas autorizadas /me de laboratorio; AUTH-T06 completa [ciclo de sesión, refresh/logout y purga](../../03-design/console-session-lifecycle.md); AUTH-T07 completa [MFA/step-up y cambio de tenant](../../03-design/console-reauthentication.md); AUTH-T08 completa [interfaz y navegador](../../03-design/console-auth-interface.md); AUTH-T09/T10 pendientes. Owner: Team 5; backend/seguridad, consola y plataforma coordinan contratos y migraciones. Hay autenticación visual de laboratorio; miembros/dashboard y evidencia productiva siguen pendientes.

| Estado / ID | Objetivo y artefacto | Depende de | Componentes | Aceptación / verificación | Riesgo |
| --- | --- | --- | --- | --- | --- |
| [x] AUTH-T01 | Bootstrap reproducible de backend Go y consola propuesta; elegir versiones/librerías y registrar comandos/decisiones. | Ninguna | src/platform, src/console, checks locales, ADR-0002 | Copia limpia ejecuta checks/build documentados; sin secretos ni configuración productiva. El fixture IdP aislado se materializó y validó en AUTH-T02, antes de conectar autenticación. | Toolchain local; proveedor productivo aún pendiente. |
| [x] AUTH-T02 | Materializar OpenAPI BFF/Management, modelo de sesión, matriz de capacidades y política validada de TTL/MFA. | AUTH-T01 | Contratos, configuración, authentication/policy, fixture OIDC, ADR-0003 | OpenAPI/schemas/ejemplos y negativos validados; intercambio Code/PKCE con JWT operator y MFA sintética, refresh/reuse y límites de política probados. Decisiones resueltas sólo para laboratorio. | IdP/factores productivos aún no seleccionados; handlers pendientes. |
| [x] AUTH-T03 | Crear migraciones mínimas tenant/identidad/membership/sesión y bootstrap sintético restringido. | AUTH-T02 | migrations, adapters/postgres, cmd/testdb, audit/outbox | PostgreSQL 18.6 descartable: base vacía/upgrade con datos, dos tenants en conexión reutilizada, RLS/grants/FK, rollback/panic/cancelación, bootstrap atómico sin regrant y CLI test-only probados. Sin endpoint público. | Provisioning productivo, cifrado operativo y autorización HTTP aún pendientes. |
| [x] AUTH-T04 | Implementar puertos OIDC y callback de un uso con validación completa. | AUTH-T02, AUTH-T03 | Authentication, adapters OIDC/BFF/PostgreSQL, secretbox | AC01/02 backend: binario Go real + IdP/DB descartables, retorno, binding/state/nonce/issuer/PKCE, replay/concurrencia, cookies opacas y rollback probados. Alta mínima sin membresía y sesión inicial cifrada. | MFA real, sesión operativa y UI siguen en sus gates. |
| [x] AUTH-T05 | Implementar middleware operator y contexto tenant/capacidades con /me. | AUTH-T03, AUTH-T04 | Private API, tenancy, /me | AC03/06/07/09 backend: Bearer verificado antes de tenancy, roles locales, tenant ajeno rechazado, suspensión bloquea siguiente petición y /me no enumera terceros. Binario real/IdP/DB y límites de sesión probados. Selector/comandos/UI siguen pendientes. | Sin refresh ni sesión operativa completa. |
| [x] AUTH-T06 | Implementar almacenamiento/rotación de sesión, refresh coordinado y logout. | AUTH-T04, AUTH-T05 | Session store, BFF | AC04/08: concurrencia y respuesta perdida no duplican familias; logout local persiste con IdP caído; reutilización revocada se rechaza. | Concurrencia/tokens. |
| [x] AUTH-T07 | Implementar MFA/step-up y CSRF/origin para comandos restantes; refresh/logout ya protegidos en AUTH-T06. | AUTH-T02, AUTH-T06 | Authentication, IdP, BFF | AC05/10 backend: claims y autenticación nueva verificados, familia/generación ligadas al callback, rotación atómica, Origin/CSRF y JSON estrictos. Reloj, replay, concurrencia/logout/refresh/rollback y tenant ajeno/suspendido probados. Auditoría integrada conserva AUTH-T09. | Reautenticación insuficiente. |
| [x] AUTH-T08 | Conectar login, selector y acceso pendiente en consola con estados accesibles. | AUTH-T05, AUTH-T06, AUTH-T07 | Console auth/guards | E2E login→tenant→/me→logout; teclado/foco, expiración, 403 y fallo IdP sin bucles; no token en JS storage. | UX/caché de tenant. |
| [ ] AUTH-T09 | Integrar auditoría/redacción y pruebas negativas/concurrencia de la feature. | AUTH-T04–AUTH-T08 | Audit, tests, telemetría | Eventos mínimos; logs/storage no contienen secretos; suites unit/contract/DB/E2E pasan con casos negativos. | Fuga en observabilidad. |
| [ ] AUTH-T10 | Documentar operación, rollout y evidencia del gate A4. | AUTH-T09 | Runbook, CI, docs | Checks reproducibles, limitaciones y reversión probada; cumple DoD sin marcar funciones no construidas. | Entrega incompleta. |

## Evidencia AUTH-T01 — 2026-11-03

El owner acordó `src/platform` y `src/console`. Se ejecutaron instalación desde lockfile (`npm ci --ignore-scripts`), formato Go, `go vet`, pruebas Go, typecheck, builds y smoke HTTP del binario/HTML/JS. Versiones, comandos reproducibles y límites se mantienen en [desarrollo local](../../04-engineering/local-development.md). No se ejecutaron OIDC/MFA, DB/RLS, navegador ni conformidad. No hay pantalla de login.

Precisión de alcance: la separación de fixtures respecto de producción sigue siendo obligatoria. Como todavía no existe IdP, su fixture ejecutable se concentra en AUTH-T02 junto con las políticas y el contrato de operador; no se introduce un emisor simulado ni un bypass para cerrar AUTH-T01. Este ajuste no completa A0 ni acredita los requisitos funcionales de autenticación.

## Evidencia AUTH-T02 — 2026-11-03

Fuente de detalle: [contrato de consola](../../03-design/console-auth-contract.md) y [ADR-0003](../../decisions/ADR-0003.md). `npm run test:auth` ejecuta nueve pruebas de contrato/IdP con escenarios positivos y negativos; `npm run check:platform` prueba política/configuración/boundaries. Los tests verifican tokens emitidos por un AS de biblioteca con claves efímeras y el rechazo del fixture en producción; no implementan middleware Go ni prueban factores reales, DB/RLS, CSRF HTTP, cookies, sesiones concurrentes o UI. El siguiente trabajo es AUTH-T03.

## Evidencia AUTH-T03 — 2026-11-03

[Persistencia de consola](../../03-design/console-persistence.md) y [ADR-0004](../../decisions/ADR-0004.md) describen el DDL nuevo, roles y fronteras. `npm run test:postgres` ejecuta ocho pruebas Go de integración en PostgreSQL real y clúster descartable, sin usar bases existentes. Incluye identidad sin membership, defaults denegados, upgrade, FK, deadlines, envelopes, consumo CAS, fallo de outbox con rollback y el CLI real. No sustituye pruebas del callback, store operativo de sesión, refresh BFF, navegador, carga o restore. El siguiente trabajo es AUTH-T04.

## Evidencia AUTH-T04 — 2026-11-04

[Login OIDC](../../03-design/console-oidc-login.md) y [ADR-0005](../../decisions/ADR-0005.md) documentan puertos, librerías fijadas, consumo confirmado antes del intercambio, cifrado y alta mínima de identidad/sesión inicial. Pruebas Go verifican claims/firmas, deadlines, cifrado/AAD, fallos de entropía y HTTP/rate limiting. `npm run test:postgres` añade binario real/IdP/DB, cookies, callback concurrente, PKCE/nonce, replay, rollback, upgrade 0002→0003 y permisos sin escritura de memberships. No prueba navegador ni factores reales. AUTH-T05 es la siguiente tarea; AUTH-T06 conserva refresh/logout/rotación.

## Evidencia AUTH-T05 — 2026-11-04

[Contexto operator y /me](../../03-design/console-operator-context.md) y [ADR-0006](../../decisions/ADR-0006.md) describen las tres lecturas, middleware Bearer, capacidades locales y pools separados. Se adelanta únicamente lectura/descifrado de generación inicial desde AUTH-T06, sin extender actividad ni renovar tokens. La selección inicial sigue null; el comando tenant requiere su protección CSRF posterior. Pruebas Go, HTTP y once pruebas superiores PostgreSQL con subcasos verifican clases/firma/audience/MFA, ausencia de consultas antes de autenticar, dos tenants, roles/revisión, suspensión/revocación y sesión sin fuga de credenciales. El siguiente trabajo es AUTH-T06: actividad/rotación, refresh coordinado y logout.

## Cobertura requisito → aceptación → tarea

| Requisito | AC | Tareas |
| --- | --- | --- |
| AUTH-FR01 | AC01 | AUTH-T04, AUTH-T08 |
| AUTH-FR02 | AC02 | AUTH-T04, AUTH-T09 |
| AUTH-FR03 | AC03 | AUTH-T02, AUTH-T05, AUTH-T09 |
| AUTH-FR04 | AC04 | AUTH-T03, AUTH-T06, AUTH-T09 |
| AUTH-FR05 | AC05 | AUTH-T02, AUTH-T07, AUTH-T08 |
| AUTH-FR06 | AC06 | AUTH-T03, AUTH-T05, AUTH-T08 |
| AUTH-FR07 | AC07 | AUTH-T05, AUTH-T09 |
| AUTH-FR08 | AC08 | AUTH-T06, AUTH-T08 |
| AUTH-FR09 | AC09 | AUTH-T05, AUTH-T08 |
| AUTH-FR10 | AC10 | AUTH-T07, AUTH-T09 |
| AUTH-QR01 | AC04 | AUTH-T03, AUTH-T06, AUTH-T09 |
| AUTH-QR02 | AC01/05/06/08 | AUTH-T08 |
| AUTH-QR03 | AC02/04/05/08 | AUTH-T02, AUTH-T07, AUTH-T09 |
| AUTH-QR04 | AC06/09 | AUTH-T05, AUTH-T08, AUTH-T09 |

## Orden y handoff

Primer incremento: AUTH-T01→AUTH-T02→AUTH-T03→AUTH-T04→AUTH-T05→AUTH-T06. Después se completa MFA/CSRF antes de exponer consola operativa. Los fixtures no permiten saltar MFA en producción.

El dominio de sesión y los estados visuales pueden diseñarse con el contrato validado, pero comparten middleware y /me con FEAT-002/003: evitar ediciones concurrentes de esos archivos. Este documento describe dependencias, no ordena ejecutar agentes.

Definition of Done por tarea: artefacto revisable, criterios comprobados, tests relevantes ejecutados y documentación del resultado. Gate final: [DoD](../../05-delivery/definition-of-done.md), todas las AC/QR y [plan](plan.md).

## Evidencia AUTH-T06 — 2026-11-04

[Ciclo de sesión](../../03-design/console-session-lifecycle.md) y [ADR-0007](../../decisions/ADR-0007.md) describen la migración 0004, lease persistente, rotación cookie/CSRF/envelope por generación, inactividad tras /me autorizado, logout local primero y purga. PostgreSQL descartable prueba concurrencia, replay, ambas ventanas de respuesta perdida, rollback, cancelación, lease abandonado y tombstones. HTTP con API/IdP reales prueba refresh, CSRF/Origin, logout repetido y logout con IdP caído. El fixture anuncia revocación OAuth y reserva stdout al protocolo JSON del driver. Al cerrar AUTH-T06 quedaban step-up/selector en AUTH-T07/T08. El estado vigente de AUTH-T07 se registra abajo. MFA real, navegador, auditoría integrada y gate A4 siguen pendientes.

## Evidencia AUTH-T07 — 2026-11-05

[MFA/step-up y contexto](../../03-design/console-reauthentication.md) y [ADR-0008](../../decisions/ADR-0008.md) describen transacción ligada a familia/generación, login/consent con max_age=0, evidencia firmada reciente de la misma identidad, rotación atómica y selección tenant protegida. La migración 0005 añade generación y FK compuesta sin ampliar permisos runtime. Cambia el detalle propuesto prompt=login por login consent para mantener offline_access; no relaja la reautenticación.

`npm run check`, `npm run test:postgres`, `npm run build`, `npm run smoke` y `git diff --check` aprobados en Windows con toolchains fijados. PostgreSQL 18.6 descartable conserva trece pruebas superiores y amplía subcasos: upgrade 0004→0005 conserva transacción login/sesión, rechaza generación ausente/inexistente, y prueba callbacks concurrentes, logout/lease y rollback. HTTP con binario real/IdP recorre step-up/callback/me y selección A→B→B→A; rechaza CSRF anterior, tenant ajeno y suspensión vigente. Unitarias verifican identidad distinta, claims MFA, límites temporales, replay, dependencia caída y JSON/headers estrictos. No se usaron bases existentes.

Las nueve operaciones del OpenAPI están implementadas sólo para laboratorio. MFA sigue sintética. VerifyPrivilegedOperator queda disponible para las mutaciones futuras de FEAT-002, que deberán combinarlo con autorización local. No se ejecutaron navegador, factores reales, carga o restore; AUTH-T08 conserva UI y limpieza de caché visual, AUTH-T09 auditoría integrada y AUTH-T10 operación/gate A4. Siguiente tarea: AUTH-T08.

## Evidencia AUTH-T08 — 2026-11-05

[Interfaz](../../03-design/console-auth-interface.md) y [ADR-0009](../../decisions/ADR-0009.md) documentan estados, negociación aditiva login/step-up y proxy local explícito. React no recibe tokens emitidos; CSRF sólo en memoria. Selector y guard dependen de /me autorizado; se retira el contexto antes de cambiarlo y se descartan respuestas obsoletas. No se simulan miembros ni dashboard.

`npm run test:browser` recorre Chromium→Vite→BFF Go→OIDC/PostgreSQL descartables: login, cero/una/varias organizaciones, selección y /me, refresh, step-up, logout, expiración y suspensión real. Incluye errores 403/dependencia/red/callback sin bucles, teclado/foco/error asociado, cookies HttpOnly y storage vacío, historial, pestañas y respuesta tardía descartada. Capturas a 320/360/768/1024/1440 px, oscuro y reflow al 200%; revisión visual de escritorio/móvil/oscuro. Los fallos de UI controlados usan interceptación sólo en tests; el recorrido principal usa servidores reales.

`npm run check`, `npm run test:postgres`, `npm run build`, `npm run smoke`, `npm run test:browser` y `git diff --check` son los gates de este incremento. No se acredita MFA real, WCAG certificada, carga/restore ni producción. AUTH-T09 es la siguiente tarea; auditoría integrada y gate A4 siguen pendientes.
