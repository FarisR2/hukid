# FEAT-003 — Tareas

Estado: DASH-T01 completada en laboratorio (sólo contrato/reglas/fixtures); DASH-T02 siguiente. Owner: Team 5, backend/lecturas y consola; cada dominio mantiene sus datos.

| Estado / ID | Objetivo y artefacto | Depende de | Componentes | Aceptación / verificación | Riesgo |
| --- | --- | --- | --- | --- | --- |
| [x] DASH-T01 | Materializar contrato overview/activity, métricas, límites, capacidad status y fixtures. | AUTH-T02, AUTH-T05, USR-T01 | OpenAPI, dashboard, dataset | Cada sección declara fuente/permisos/periodo/asOf; errores y null/0 tienen ejemplos que validan. | Semántica engañosa. |
| [ ] DASH-T02 | Implementar caso de uso y lectura base autorizada de tenancy/audit. | DASH-T01, USR-T03, USR-T07, AUTH-T09 | Dashboard, Postgres, authorization | AC02/03/05/09: conteos/feed exactos y tenant/issuer scopes antes de agrupar; fuentes no implementadas unavailable. | Filtración por agregación. |
| [ ] DASH-T03 | Implementar API/BFF con filtros, paginación y estados parciales. | DASH-T02 | Private API/console adapters | AC04/06/07: intervalo [from,to), límites, 401/403/404, parciales y no-store probados por contrato. | Falsos éxitos/consultas ilimitadas. |
| [ ] DASH-T04 | Implementar shell, contexto, navegación y vista base accesible. | DASH-T01, DASH-T03, AUTH-T08 | Console dashboard | AC01/07/08: rol/contexto reales, teclado/móvil, reintento y descarte de respuestas de tenant anterior. | Caché/respuestas tardías. |
| [ ] DASH-T05 | Conectar por separado adaptadores issuer/definition/issuance/status cuando existan sus módulos. | DASH-T01, DASH-T03; módulos propietarios disponibles | Puertos de lectura y repositorios | Cada fuente incorporada cumple AC02/03/04/06 con fixtures. Registrar fuentes habilitadas; no fingir emisión o status con datos mock. | Dependencia futura. |
| [ ] DASH-T06 | Ejecutar matriz negativa, cambios de permisos, ventanas y degradación. | DASH-T02–DASH-T04; DASH-T05 para cada fuente conectada | Unit/integration/contract tests | Actor sólo-A nunca observa B; data no disponible no aparece como 0; stale/desired/published, límites UTC y cursors manipulados correctos. | Exposición/consistencia. |
| [ ] DASH-T07 | Ejecutar E2E/accesibilidad y medición de consultas sin datos sensibles. | DASH-T04, DASH-T06 | Browser QA, métricas | Foco/estados/rangos y cambio tenant/rol funcionan; logs no exponen PII; latencias medidas sin prometer SLA nuevo. | UX/performance no medidos. |
| [ ] DASH-T08 | Documentar fuentes activas, rollout y evidencia de DoD. | DASH-T07 | Runbook, contrato, docs | Incremento D1/D2 identificable; D3 abierto si faltan dominios; limitaciones y reversión reproducibles. | Marcar cobertura falsa. |

## Cobertura requisito → aceptación → tarea

| Requisito | AC | Tareas |
| --- | --- | --- |
| DASH-FR01 | AC01 | DASH-T04, DASH-T07 |
| DASH-FR02 | AC02 | DASH-T01, DASH-T02, DASH-T05, DASH-T06 |
| DASH-FR03 | AC03 | DASH-T01, DASH-T02, DASH-T05, DASH-T06 |
| DASH-FR04 | AC04 | DASH-T01, DASH-T03, DASH-T05, DASH-T06 |
| DASH-FR05 | AC05 | DASH-T02, DASH-T06 |
| DASH-FR06 | AC06 | DASH-T03, DASH-T05, DASH-T06 |
| DASH-FR07 | AC07 | DASH-T03, DASH-T04, DASH-T07 |
| DASH-FR08 | AC08 | DASH-T04, DASH-T06, DASH-T07 |
| DASH-FR09 | AC09 | DASH-T02, DASH-T06, DASH-T07 |
| DASH-QR01 | AC04/09 | DASH-T01, DASH-T03, DASH-T07 |
| DASH-QR02 | AC02/08 | DASH-T03, DASH-T06 |
| DASH-QR03 | AC01/07 | DASH-T04, DASH-T07 |
| DASH-QR04 | AC03/06/07 | DASH-T01, DASH-T06 |

## Orden y trabajo diferido

DASH-T01 materializa la matriz USR-T01 sin ampliar sus grants. Continuar por DASH-T02. El shell puede prepararse con contrato y fixture de UI aislado, pero la feature se entrega sólo con APIs reales. Fixtures de pruebas deben estar identificados; no se usan como datos operativos.

DASH-T05 se subdivide por fuente cuando el dominio esté listo. No bloquea el incremento base y permanece pendiente para las fuentes ausentes. Las tareas que verifican D3 se ejecutan para cada adaptador incorporado, sin dar por completa la tarea global.

La DoD exige [spec](spec.md), [plan](plan.md), fuentes activas documentadas y [criterios comunes](../../05-delivery/definition-of-done.md). Sin datos Events, inventario wallet ni exportaciones nuevas.

## Evidencia DASH-T01 — 2026-11-06

Baseline [contractual](../../03-design/console-dashboard-contract.md) según [ADR-0019](../../decisions/ADR-0019.md): OpenAPI 3.1 de cuatro GET Management/BFF contract-only, schemas estrictos, seis métricas con fuente/capacidad/periodo/issuer, perfil test cerrado y reglas Go de ventanas/filtros. status:read queda reservada sin ampliar la matriz de roles. Ejemplos de cero, no autorizado, unavailable, stale, parcial, actividad vacía y errores; dataset sintético de dos tenants y tres issuers, bordes [from,to) y desired distinto de published.

Validación local: `npm run check` aprobó formato/vet/unitarias Go, TypeScript, 18 pruebas Node de contratos/IdP (cuatro nuevas DASH) y enlaces/anclas/bloques/estructura Markdown. `npm run build` aprobó ambos artefactos; `npm run smoke` comprobó configuración fail-closed, liveness, auth deshabilitada y bundle de consola. Las pruebas nuevas verifican paridad API/BFF, ausencia de grants futuros, ejemplos válidos, rechazo de PII/propiedades adicionales, null/0 y metadatos protegidos; Go cubre UTC, 31 días, límites, duplicados y cursores sin ventana explícita.

No se cambian persistencia, rutas runtime ni UI: no se ejecutan PostgreSQL ni Chromium nuevos para este incremento contractual. Las comprobaciones de dataset son un oráculo de ejemplos, no una prueba de autorización de un repositorio real. DASH-T02/03 conservan lectura/RLS, autorización viva, autenticación de cursor y endpoints; DASH-T04 interfaz; DASH-T05 dominios futuros. No se acredita producción, interoperabilidad VC ni cierre de la feature completa. Siguiente: DASH-T02.
