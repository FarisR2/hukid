# FEAT-001 — Tareas

Estado: AUTH-T01/T02/T03 completadas para bootstrap, laboratorio contractual y foundation PostgreSQL; AUTH-T04–T10 pendientes. Owner: Team 5; backend/seguridad, consola y plataforma coordinan contratos y migraciones. La evidencia de laboratorio no acredita login integrado ni producción.

| Estado / ID | Objetivo y artefacto | Depende de | Componentes | Aceptación / verificación | Riesgo |
| --- | --- | --- | --- | --- | --- |
| [x] AUTH-T01 | Bootstrap reproducible de backend Go y consola propuesta; elegir versiones/librerías y registrar comandos/decisiones. | Ninguna | src/platform, src/console, checks locales, ADR-0002 | Copia limpia ejecuta checks/build documentados; sin secretos ni configuración productiva. El fixture IdP aislado se materializó y validó en AUTH-T02, antes de conectar autenticación. | Toolchain local; proveedor productivo aún pendiente. |
| [x] AUTH-T02 | Materializar OpenAPI BFF/Management, modelo de sesión, matriz de capacidades y política validada de TTL/MFA. | AUTH-T01 | Contratos, configuración, authentication/policy, fixture OIDC, ADR-0003 | OpenAPI/schemas/ejemplos y negativos validados; intercambio Code/PKCE con JWT operator y MFA sintética, refresh/reuse y límites de política probados. Decisiones resueltas sólo para laboratorio. | IdP/factores productivos aún no seleccionados; handlers pendientes. |
| [x] AUTH-T03 | Crear migraciones mínimas tenant/identidad/membership/sesión y bootstrap sintético restringido. | AUTH-T02 | migrations, adapters/postgres, cmd/testdb, audit/outbox | PostgreSQL 18.6 descartable: base vacía/upgrade con datos, dos tenants en conexión reutilizada, RLS/grants/FK, rollback/panic/cancelación, bootstrap atómico sin regrant y CLI test-only probados. Sin endpoint público. | Provisioning productivo, cifrado operativo y autorización HTTP aún pendientes. |
| [ ] AUTH-T04 | Implementar puertos OIDC y callback de un uso con validación completa. | AUTH-T02, AUTH-T03 | Authentication, adapter OIDC/BFF | AC01/02: retorno inseguro, replay, state/nonce/issuer inválidos rechazados con tests de contrato. | Robo de sesión. |
| [ ] AUTH-T05 | Implementar middleware operator y contexto tenant/capacidades con /me. | AUTH-T03, AUTH-T04 | Private API, tenancy, /me | AC03/06/07/09: token de otra clase falla; tenant ajeno no carga; suspensión bloquea siguiente petición; consulta mínima sin tenant no enumera terceros. | Confusión de autoridad. |
| [ ] AUTH-T06 | Implementar almacenamiento/rotación de sesión, refresh coordinado y logout. | AUTH-T04, AUTH-T05 | Session store, BFF | AC04/08: concurrencia y respuesta perdida no duplican familias; logout local persiste con IdP caído; reutilización revocada se rechaza. | Concurrencia/tokens. |
| [ ] AUTH-T07 | Implementar MFA/step-up y CSRF/origin para comandos. | AUTH-T02, AUTH-T06 | Authentication, IdP, BFF | AC05/10: amr/acr/auth_time verificados; CSRF malo no cambia nada; reloj prueba cada límite configurado. | Reautenticación insuficiente. |
| [ ] AUTH-T08 | Conectar login, selector y acceso pendiente en consola con estados accesibles. | AUTH-T05, AUTH-T06, AUTH-T07 | Console auth/guards | E2E login→tenant→/me→logout; teclado/foco, expiración, 403 y fallo IdP sin bucles; no token en JS storage. | UX/caché de tenant. |
| [ ] AUTH-T09 | Integrar auditoría/redacción y pruebas negativas/concurrencia de la feature. | AUTH-T04–AUTH-T08 | Audit, tests, telemetría | Eventos mínimos; logs/storage no contienen secretos; suites unit/contract/DB/E2E pasan con casos negativos. | Fuga en observabilidad. |
| [ ] AUTH-T10 | Documentar operación, rollout y evidencia del gate A4. | AUTH-T09 | Runbook, CI, docs | Checks reproducibles, limitaciones y reversión probada; cumple DoD sin marcar funciones no construidas. | Entrega incompleta. |

## Evidencia AUTH-T01 — 2026-11-03

El owner acordó `src/platform` y `src/console`. Se ejecutaron instalación desde lockfile (`npm ci --ignore-scripts`), formato Go, `go vet`, pruebas Go, typecheck, builds y smoke HTTP del binario/HTML/JS. Versiones, comandos reproducibles y límites se mantienen en [desarrollo local](../../04-engineering/local-development.md). No se ejecutaron OIDC/MFA, DB/RLS, navegador ni conformidad. No hay pantalla de login.

Precisión de alcance: la separación de fixtures respecto de producción sigue siendo obligatoria. Como todavía no existe IdP, su fixture ejecutable se concentra en AUTH-T02 junto con las políticas y el contrato de operador; no se introduce un emisor simulado ni un bypass para cerrar AUTH-T01. Este ajuste no completa A0 ni acredita los requisitos funcionales de autenticación.

## Evidencia AUTH-T02 — 2026-11-03

Fuente de detalle: [contrato de consola](../../03-design/console-auth-contract.md) y [ADR-0003](../../decisions/ADR-0003.md). `npm run test:auth` ejecuta nueve pruebas de contrato/IdP con escenarios positivos y negativos; `npm run check:platform` prueba política/configuración/boundaries. Los tests verifican tokens emitidos por un AS de biblioteca con claves efímeras y el rechazo del fixture en producción; no implementan middleware Go ni prueban factores reales, DB/RLS, CSRF HTTP, cookies, sesiones concurrentes o UI. El siguiente trabajo es AUTH-T03.

## Evidencia AUTH-T03 — 2026-11-03

[Persistencia de consola](../../03-design/console-persistence.md) y [ADR-0004](../../decisions/ADR-0004.md) describen el DDL nuevo, roles y fronteras. `npm run test:postgres` ejecuta ocho pruebas Go de integración en PostgreSQL real y clúster descartable, sin usar bases existentes. Incluye identidad sin membership, defaults denegados, upgrade, FK, deadlines, envelopes, consumo CAS, fallo de outbox con rollback y el CLI real. No sustituye pruebas del callback, store operativo de sesión, refresh BFF, navegador, carga o restore. El siguiente trabajo es AUTH-T04.

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
