# FEAT-003 — Tareas

Estado: DASH-T01–T04 y DASH-T06/T07 completadas para la base de laboratorio (contrato, lectura autorizada, API/BFF/cursor, interfaz, matriz negativa y E2E/medición). Siguiente DASH-T08; DASH-T05 pendiente por módulos propietarios futuros. Owner: Team 5, backend/lecturas y consola; cada dominio mantiene sus datos.

| Estado / ID | Objetivo y artefacto | Depende de | Componentes | Aceptación / verificación | Riesgo |
| --- | --- | --- | --- | --- | --- |
| [x] DASH-T01 | Materializar contrato overview/activity, métricas, límites, capacidad status y fixtures. | AUTH-T02, AUTH-T05, USR-T01 | OpenAPI, dashboard, dataset | Cada sección declara fuente/permisos/periodo/asOf; errores y null/0 tienen ejemplos que validan. | Semántica engañosa. |
| [x] DASH-T02 | Implementar caso de uso y lectura base autorizada de tenancy/audit. | DASH-T01, USR-T03, USR-T07, AUTH-T09 | Dashboard, Postgres, authorization | AC02/03/05/09: conteos/feed exactos y tenant/issuer scopes antes de agrupar; fuentes no implementadas unavailable. | Filtración por agregación. |
| [x] DASH-T03 | Implementar API/BFF con filtros, paginación y estados parciales. | DASH-T02 | Private API/console adapters | AC04/06/07: intervalo [from,to), límites, 401/403/404, parciales y no-store probados por contrato. | Falsos éxitos/consultas ilimitadas. |
| [x] DASH-T04 | Implementar shell, contexto, navegación y vista base accesible. | DASH-T01, DASH-T03, AUTH-T08 | Console dashboard | AC01/07/08: rol/contexto reales, teclado/móvil, reintento y descarte de respuestas de tenant anterior. | Caché/respuestas tardías. |
| [ ] DASH-T05 | Conectar por separado adaptadores issuer/definition/issuance/status cuando existan sus módulos. | DASH-T01, DASH-T03; módulos propietarios disponibles | Puertos de lectura y repositorios | Cada fuente incorporada cumple AC02/03/04/06 con fixtures. Registrar fuentes habilitadas; no fingir emisión o status con datos mock. | Dependencia futura. |
| [x] DASH-T06 (base) | Ejecutar matriz negativa, cambios de permisos, ventanas y degradación. | DASH-T02–DASH-T04; DASH-T05 para cada fuente conectada | Unit/integration/contract tests | Actor sólo-A nunca observa B; data no disponible no aparece como 0; stale/desired/published, límites UTC y cursors manipulados correctos. Matriz y alcance diferido al final. | Exposición/consistencia. |
| [x] DASH-T07 | Ejecutar E2E/accesibilidad y medición de consultas sin datos sensibles. | DASH-T04, DASH-T06 | Browser QA, métricas | Foco/estados/rangos y cambio tenant/rol funcionan; logs no exponen PII; latencias medidas sin prometer SLA nuevo. | UX/performance no medidos. |
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

DASH-T01 materializa la matriz USR-T01 sin ampliar sus grants. DASH-T04 conecta la interfaz real y DASH-T06 valida la matriz base. DASH-T07 completa E2E/accesibilidad y medición local; continuar por DASH-T08; DASH-T05 se ejecuta por fuente cuando exista su módulo y requiere repetir la matriz DASH-T06 de ese adaptador. El shell puede prepararse con contrato y fixture de UI aislado, pero la feature se entrega sólo con APIs reales. Fixtures de pruebas deben estar identificados; no se usan como datos operativos.

DASH-T05 se subdivide por fuente cuando el dominio esté listo. No bloquea el incremento base y permanece pendiente para las fuentes ausentes. Las tareas que verifican D3 se ejecutan para cada adaptador incorporado, sin dar por completa la tarea global.

La DoD exige [spec](spec.md), [plan](plan.md), fuentes activas documentadas y [criterios comunes](../../05-delivery/definition-of-done.md). Sin datos Events, inventario wallet ni exportaciones nuevas.

## Matriz negativa DASH-T06 — base de laboratorio

La matriz reúne pruebas nuevas y regresión de DASH-T01–T04. Sólo tenancy (miembros) y audit (actividad tenant) son fuentes operativas. Cada adaptador futuro DASH-T05 debe repetir sus casos de autorización, periodo, degradación y freshness antes de considerarse cubierto.

| Riesgo / AC | Evidencia ejecutable | Resultado exigido / límite |
| --- | --- | --- |
| Tenant/actor ajeno y sólo lectura, AC02/09 | [Integración base](../../../src/platform/internal/adapters/postgres/dashboard_integration_test.go), [matriz nueva](../../../src/platform/internal/adapters/postgres/dashboard_negative_integration_test.go) | Conteos/feed aislados; replay entre actores autorizados o tenants rechaza cursor; actor sólo-A recibe ErrTenant en B; RLS y pool sin contexto residual; lectura no escribe audit/outbox. |
| Cambio de autorización entre páginas, AC02/05/08 | Matriz nueva y [HTTP real](../../../src/platform/internal/adapters/postgres/dashboard_http_integration_test.go) | Retirada de audit:read devuelve 403 incluso con fuente averiada; revocación devuelve 404; reactivación con revisión nueva invalida el cursor; scopes issuer nuevos fallan cerrados sin ownership. |
| Precisión y límites UTC, AC04 | [Parser](../../../src/platform/internal/dashboard/request_test.go), matriz nueva y HTTP real | [from,to), 31 días, futuro, duplicados y límites de página; cinco casos PostgreSQL fijan bordes exactos y desplazados 1 ns, incluido intervalo vacío menor que 1 µs. Ventana original intacta. |
| Cursor autenticado y deadline fijo, AC04/08 | [Unitarias activity](../../../src/platform/internal/dashboard/activity_test.go) y HTTP real | Actor/tenant/revisión/roles/scopes/rango/límite ligados; manipulación separada de nonce/ciphertext/tag y cambio de clave rechazados antes de consultar filas. Cursor de segunda página emitido en t+899 s vence en t+900 s; se acepta hasta 1 ns antes. asOf permanece fijo. |
| Degradación real y autorización, AC03/07 | HTTP real Management y BFF, [unitarias service](../../../src/platform/internal/dashboard/service_test.go) | Fallo SQL de audit da 503 sin items ni diagnóstico; overview independiente sigue disponible. Fallo de fuente de autorización cierra ambas lecturas con 503, nunca cero. Problemas serializados validan schema estricto. |
| Cero, null y freshness, AC03/06 | Unitarias service, [contratos](../../../tests/auth/dashboard-contracts.test.mjs) | Cero sólo tras consulta exitosa; notAuthorized/unavailable/error sin value/asOf; permiso evaluado antes del error. Edad de 300 s sigue disponible, +1 ns es stale; observación futura +1 ns se rechaza; conteo máximo exacto y overflow diferenciados. |
| desired/published y fuentes futuras, AC03/06 | Contratos y [dataset sintético](../../../tests/fixtures/dashboard/dataset.json) | desired≠published no cambia published. Evidencia sólo contractual: no existe adaptador status ni grants status:read; no acredita publicación operativa ni aislamiento issuer real. |
| Respuestas tardías, cambios de filtros/tenant/rol, AC07/08 | [Regresión Chromium DASH-T04](../../../tests/browser/dashboard.py) | Descarta respuestas anteriores, revalida /me tras 403 y retira feed/navegación; 401 vuelve al login. Degradaciones de secciones futuras y cursor UI son interceptaciones explícitas. |

No se cambia DDL, política de grants, payload ni compatibilidad HTTP. La corrección de precisión implementa el contrato UTC existente; no requiere una nueva decisión de arquitectura. DASH-T07 conserva E2E/accesibilidad y medición de consultas; DASH-T08 conserva rollout/runbook y DoD del incremento base. D3, carga/SLO, factores reales, CI remoto y producción no se acreditan por esta matriz.

## Evidencia DASH-T01 — 2026-11-06

Baseline [contractual](../../03-design/console-dashboard-contract.md) según [ADR-0019](../../decisions/ADR-0019.md): OpenAPI 3.1 de cuatro GET Management/BFF contract-only, schemas estrictos, seis métricas con fuente/capacidad/periodo/issuer, perfil test cerrado y reglas Go de ventanas/filtros. status:read queda reservada sin ampliar la matriz de roles. Ejemplos de cero, no autorizado, unavailable, stale, parcial, actividad vacía y errores; dataset sintético de dos tenants y tres issuers, bordes [from,to) y desired distinto de published.

Validación local: `npm run check` aprobó formato/vet/unitarias Go, TypeScript, 18 pruebas Node de contratos/IdP (cuatro nuevas DASH) y enlaces/anclas/bloques/estructura Markdown. `npm run build` aprobó ambos artefactos; `npm run smoke` comprobó configuración fail-closed, liveness, auth deshabilitada y bundle de consola. Las pruebas nuevas verifican paridad API/BFF, ausencia de grants futuros, ejemplos válidos, rechazo de PII/propiedades adicionales, null/0 y metadatos protegidos; Go cubre UTC, 31 días, límites, duplicados y cursores sin ventana explícita.

No se cambian persistencia, rutas runtime ni UI: no se ejecutan PostgreSQL ni Chromium nuevos para este incremento contractual. Las comprobaciones de dataset son un oráculo de ejemplos, no una prueba de autorización de un repositorio real. DASH-T02/03 conservan lectura/RLS, autorización viva, autenticación de cursor y endpoints; DASH-T04 interfaz; DASH-T05 dominios futuros. No se acredita producción, interoperabilidad VC ni cierre de la feature completa. Siguiente: DASH-T02.

## Evidencia DASH-T02 — 2026-11-06

[Lectura base](../../03-design/console-dashboard-reads.md) según [ADR-0020](../../decisions/ADR-0020.md): caso de uso overview y puerto de actividad dentro de snapshot autorizado READ ONLY / REPEATABLE READ. Migración aditiva 0011 con credencial de lectura separada, RLS tenant/allowlist y proyección mínima. Conteo exacto de membresías activas; feed acotado con ventana, asOf, orden y posición keyset internos. Reutiliza matriz y revalida roles/revisión/scopes sin datos cliente ni escrituras audit/outbox.

Las fuentes futuras respetan permiso primero: roles actuales reciben notAuthorized; una fuente futura autorizada desconectada se representa unavailable, nunca cero. Sin ownership issuer confiable, selectores/conjuntos restringidos fallan cerrados antes de agregar. No hay atribución issuer inventada.

Validación local aprobada: `npm run check` (formato/vet/unitarias Go, TypeScript, 18 pruebas Node de contratos/IdP y documentación), `npm run test:postgres` (40.000 s), `npm run build`, `npm run smoke` y `git diff --check`. El validador documental comprobó 106 Markdown y 964 enlaces/anclas locales, bloques y estructura. Las pruebas añaden disponibilidad/frescura/null/0 y cuatro escenarios PostgreSQL de conteos/aislamiento, feed/ventana/allowlist/keyset, upgrade/privilegios/fallos y snapshot/revisión viva. No se ejecuta Chromium nuevo porque no cambia UI.

No hay handlers, configuración de pool API ni cursor público autenticado por este incremento: siguen en DASH-T03. DASH-T04 conserva interfaz; DASH-T05 módulos futuros; DASH-T06–T08 gate y operación. No acredita carga, CI remoto, interoperabilidad VC ni producción. Siguiente DASH-T03.

## Evidencia DASH-T03 — 2026-11-06

[API/BFF del dashboard](../../03-design/console-dashboard-http.md) según [ADR-0021](../../decisions/ADR-0021.md): cuatro GET implemented-test, configuración opcional completa con pool/clave exclusivos, Bearer/sesión y autorización viva antes de consultar. Filtros UTC [from,to), límites, errores propios, no-store y correlación UUID. Cursor AES-256-GCM ligado a operación/actor/tenant/revisión/roles/scopes/filtros/límite, asOf y deadline fijos durante 900 segundos; no renueva TTL. Se autentica dentro del snapshot tras reautorizar.

Validación local aprobada: `npm run check` (formato/vet/unitarias Go, TypeScript, 18 pruebas Node de contratos/IdP y documentación), `npm run test:postgres` (57.239 s en la ejecución final), `npm run build`, `npm run smoke` y `git diff --check`. La suite HTTP real añade ambos transportes, tres páginas con timestamps iguales, bordes/tenant, cambio de revisión/rol, errores, selección ausente, suspensión y schema estricto de respuestas serializadas. Unitarias añaden binding/manipulación/expiración/rotación de clave y configuración incompleta, insegura o mal formada. Los fixtures nuevos conservan pares audit/outbox para no alterar la regresión AUTH.

La primera pasada detectó precedencia de selección retirada por AUTH; BFF ahora devuelve 404 para selector inaccesible antes del 403 de selección accesible distinta/ausente. Las correcciones de fixtures de pruebas no cambian el runtime AUTH/USR. Con una única fuente de conteo autorizada conectada, su fallo sigue siendo 503 global; parciales/unavailable/stale futuros conservan cobertura contractual/pura y se aplicarán al conectar dominios. No se fingen fuentes ni ownership issuer.

Sin migración nueva, UI o Chromium nuevo. No acredita carga/SLO, CI remoto, interoperabilidad VC, producción ni cierre de la feature completa. DASH-T04 es la siguiente tarea; DASH-T05 conserva fuentes futuras y DASH-T06–T08 la matriz ampliada, navegador y operación.

## Evidencia DASH-T04 — 2026-11-06

[Interfaz base](../../03-design/console-dashboard-interface.md) según [ADR-0022](../../decisions/ADR-0022.md): shell con tenant seleccionado y roles/capacidades de membresía viva, enlaces por permiso, resumen/actividad BFF reales, filtros UTC [from,to), estados textuales y fechas por sección. Roles se añade como campo aditivo al DTO de contexto y schema; no se deduce de capacidades ni cambia grants. Sin migración ni fuentes nuevas.

Validación local aprobada: npm run check (formato/vet/unitarias Go, TypeScript, 18 pruebas de contratos/IdP y documentación), npm run test:postgres (38.494 s), npm run build, npm run smoke y npm run test:browser (43.423 s en ejecución final). La validación documental final comprobó 110 Markdown y 1022 enlaces/anclas locales, bloques y estructura; git diff --check aprobó. Las capturas desktop/móvil/oscuro/parcial se revisaron; el harness comprobó reflujo 320/360/768/1024/1440 px y 200%, teclado y un solo h1. La medición sintética del flujo AUTH con dashboard conectado registró LCP 176 ms, CLS 0.0522 y mayor interacción 32 ms bajo el perfil de laboratorio, sin establecer un SLO.

Chromium añade conteos reales A=1/B=2, rango inválido con foco, periodo vacío, errores parciales/503 y reintento, todos los estados de sección y cero, paginación de UI/cursor inválido, filtros ligados al cursor y respuestas tardías tras filtro/tenant. Cambios de rol reales en DB provocan 403, revalidación /me y retirada del directorio/feed; 401 vuelve al login. Los casos de degradación futura y cursor de UI son fixtures interceptados explícitos, no fuentes productivas; cursor autenticado conserva pruebas HTTP DASH-T03. La regresión AUTH/USR permanece activa, con selectores acotados a su región y ausencia de directorio sin permisos.

Las pasadas iniciales detectaron normalización de segundos cero por datetime-local: el cliente ahora serializa UTC canónico antes de consultar. La suite ajustó el conteo B al dataset real y espera el fin de la respuesta antes de retirar interceptores. No se ocultaron fallos del runtime mediante fixtures operativos.

DASH-T04 queda completa en laboratorio. DASH-T05 permanece pendiente por módulos/ownership futuros; siguiente DASH-T06 para la matriz base, después DASH-T07/T08. No acredita certificación WCAG, lector físico, carga/SLO, CI remoto, IdP/MFA reales, interoperabilidad VC, preparación productiva ni cierre de la feature completa o del roadmap HK.

## Corrección posterior DASH-T04 — reloj de fuente, 2026-11-06

El pipeline Windows reportó fallos PostgreSQL en el conteo tras suspensión y en overview BFF (503). Una prueba diagnóstica local reprodujo asOf de PostgreSQL 161,6 microsegundos por delante del generatedAt de Go: la comparación entre relojes distintos activaba el rechazo de datos futuros. Los checks/build previos podían pasar sin observar la diferencia intermitente.

Según [ADR-0023](../../decisions/ADR-0023.md), el overview obtiene generatedAt del reloj PostgreSQL mediante clock_timestamp() después de leer las fuentes, dentro de su snapshot autorizado. Conserva asOf de transaction_timestamp(), rechazo de datos futuros, error de fuente/reloj y frescura. No amplía permisos, no añade tolerancia/sleeps/reintentos, ni cambia JSON, ventana, sesión o TTL del cursor de actividad.

Regresión determinista: unitarias con relojes distintos, dato disponible/stale, observación futura de un microsegundo y fallo del reloj; integración PostgreSQL con reloj de aplicación fijado en 2020 y cien lecturas actuales coherentes. Las pruebas existentes de aislamiento, suspensión y HTTP permanecen activas.

Validación local: check:platform y test:postgres (37.635 s) aprobados; después npm run test:members:gate completo aprobado con check, build, PostgreSQL (31.856 s), smoke y Chromium (31.817 s). La evidencia corresponde al código corregido antes del añadido documental de este resultado; CI remoto debe ejecutarse de nuevo tras publicar la corrección. No se acredita todavía ese nuevo resultado remoto.

## Evidencia DASH-T06 — 2026-11-06

La matriz base anterior queda ejecutada en laboratorio. Nuevas pruebas PostgreSQL reproducen dos errores en los bordes de 1 ns: truncar from incluía un evento previo, y truncar to excluía un evento interior. El adaptador ahora eleva ambos límites a la cuadrícula microsegundo de recorded_at, preservando el intervalo [from,to), los valores devueltos y el binding original. Los cinco subcasos de precisión pasan tras la corrección.

Se añaden replays entre actores autorizados/tenants, retirada de permiso con fuente averiada, revocación/reactivación con revisión nueva y grants issuer sin ownership. Las unitarias fijan el deadline de un cursor de continuación, manipulación de nonce/ciphertext/tag, prioridad de permiso y freshness a 1 ns. API y BFF usan revocación temporal de privilegios SQL en la DB descartable para verificar fallo real de audit (503 con overview independiente disponible), fallo de autorización (ambas lecturas 503) y precedencia del 403; las respuestas se validan con schema estricto.

Validación local aprobada: npm run check (Go/formato/vet, TypeScript, 18 pruebas de contratos/IdP y documentación), npm run test:postgres (40.462 s), npm run build, npm run smoke y npm run test:browser (43.242 s). Chromium ejecuta la regresión existente AUTH/USR/DASH-T04; no se añade UI ni se vuelve a acreditar revisión visual manual. Enlaces/anclas/bloques/estructura Markdown y git diff --check validados. No se crea migración ni se cambia configuración runtime.

DASH-T06 queda completa para la base. DASH-T05 sigue abierta por fuentes futuras y requiere extender esta matriz; desired/published y parciales futuros conservan evidencia contractual/sintética. Siguiente DASH-T07, después DASH-T08. No se acredita CI remoto, medición de carga/SLO, interoperabilidad VC ni preparación productiva.

## Evidencia DASH-T07 — 2026-11-06

[Informe reproducible](../../05-delivery/reviews/dashboard-t07-laboratory.md): E2E Chromium con 30 eventos por tenant y cursor real (dos páginas, 35 eventos únicos, asOf fijo, sin datos B); recorrido Tab de filtros/ayuda/validación y recuperación del cursor inválido. La nueva regresión reprodujo pérdida de foco al retirar el botón de siguiente página; ahora se enfoca el encabezado de actividad antes de desmontarlo. Se conserva la regresión de rangos, estados, cambios de tenant/rol, respuestas tardías y reintentos AUTH/USR/DASH.

El harness comprueba un canary email sintético rechazado con 422 y su ausencia literal/URL-encoded en logs de aplicación y auditoría, junto con claves dashboard/cursor. Medición pgx de consultas efectivas con 20.000 eventos sintéticos, una conexión serial, 3 warmups y 30 muestras por operación; sólo etiquetas/tiempos sin SQL/argumentos/PII. p95 local overview 1,5146 ms, actividad posterior límite 100 2,1157 ms. Paginación Chromium hasta renderizado 125,26 ms en una muestra con CPU 4x. No fija SLA/SLO ni acredita carga del piloto.

Validación local aprobada: npm run check (Go/formato/vet, TypeScript, 18 contratos/IdP y documentación), npm run test:postgres (35,453 s), npm run build, npm run smoke y npm run test:browser (45,137 s). Revisadas capturas desktop/móvil/oscuro; reflujo 320–1440 px y texto 200% comprobados por harness. Informe con límites de accesibilidad, perfiles, percentiles, reproducción y artefactos locales; enlaces/anclas/bloques/estructura y diff validados al cerrar.

DASH-T07 completa para la base de laboratorio. Siguiente DASH-T08; DASH-T05 sigue pendiente por dominios/ownership futuros. Sin certificación WCAG/ISO, lector físico, motores alternativos, factores reales, carga/SLO, CI remoto, preparación productiva ni cierre del roadmap HK. Sin migración, permiso o contrato nuevo.
