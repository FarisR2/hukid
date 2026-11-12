# Gate D4 del dashboard base — DASH-T08

Fecha: 2026-11-06. Owner: Team 5. Alcance: D1/D2 de FEAT-003 en laboratorio Windows aislado, con regresión AUTH/USR, PostgreSQL real y OIDC/MFA sintéticos. D3 permanece abierto por DASH-T05. El [runbook](../04-engineering/console-dashboard-runbook.md) mantiene fuentes activas, activación, diagnóstico y retirada. El perfil HukID conserva v0.1-draft.

## Reproducción y evidencia

Ejecutar `npm run test:dashboard:gate` desde la raíz con el toolchain de [desarrollo local](../04-engineering/local-development.md). Reutiliza el runner acumulado: check, build, test:postgres, smoke y test:browser, secuenciales y sin aceptar resultados previos. Se detiene al primer fallo. No introduce datos operativos ni abre una base existente. El [workflow](../../.github/workflows/authentication.yml) usa ese mismo comando; las órdenes AUTH/USR anteriores conservan sus informes independientes.

El informe ignorado `.cache/dashboard-gate/latest.json` contiene gate=dashboard, HEAD, dirty, digest SHA-256 de fuentes versionadas/no ignoradas, Node, estado, tiempos y códigos de salida. No guarda logs, entorno, credenciales ni payload. Si dirty=true, HEAD identifica la base y sourceDigest el árbol evaluado. Cambiar fuentes durante la ejecución invalida el resultado. Los artefactos de medición conservan las rutas y límites de [DASH-T07](reviews/dashboard-t07-laboratory.md); no fijan un SLA/SLO ni se suben automáticamente a un servicio externo.

## Matriz de aceptación y DoD

La [spec](../features/FEAT-003-dashboard/spec.md) mantiene los AC/QR; [tareas](../features/FEAT-003-dashboard/tasks.md) mantiene la evidencia fechada y la matriz negativa detallada. Las suites enlazadas son ejecutadas por el gate, no fuentes operativas.

| Criterio / DoD | Evidencia ejecutable | Límite de aceptación base |
| --- | --- | --- |
| AC01, actor/contexto y journey | [Chromium](../../tests/browser/dashboard.py), /me y roles vivos AUTH/USR | Shell/navegación sólo según capacidades actuales. Factores sintéticos. |
| AC02/05, aislamiento y autorización | [Integración base](../../src/platform/internal/adapters/postgres/dashboard_integration_test.go), [negativos](../../src/platform/internal/adapters/postgres/dashboard_negative_integration_test.go) y [HTTP](../../src/platform/internal/adapters/postgres/dashboard_http_integration_test.go) | Tenant A/B, revisión/roles/scopes revalidados, RLS/pool sin contexto residual. Ownership issuer no disponible: falla cerrado. |
| AC03/06, exactitud y disponibilidad | [Service](../../src/platform/internal/dashboard/service_test.go), [contratos](../../tests/auth/dashboard-contracts.test.mjs), PostgreSQL y HTTP | activeMembers real; null/0/freshness/parcial futuro cubiertos por reglas/fixtures. desired/published no prueba un publicador status real. |
| AC04, ventana y consultas acotadas | [Parser](../../src/platform/internal/dashboard/request_test.go), negativos/HTTP y [cursor](../../src/platform/internal/dashboard/activity_test.go) | [from,to), 31 días, precisión ns sobre DB µs, límite 1–100, cursor autenticado con deadline fijo 900 s. Sin snapshot entre páginas. |
| AC07/08, recuperación y accesibilidad | Chromium, HTTP y negativos | Teclado/foco, estados, rango, cambio tenant/rol, respuestas tardías y reintento. Fuentes futuras/errores UI interceptados explícitos. Sin certificación WCAG/ISO ni lector físico. |
| AC09, observación y efectos | Integración base/HTTP, Chromium y [medición](../../src/platform/internal/adapters/postgres/dashboard_measurement_integration_test.go) | Lecturas sin nuevos eventos de negocio; latencia/resultado/correlación sin payload, canary/keys ausentes de canales observados. Sin colector/alertas productivas. |
| Contratos, compatibilidad y migraciones | OpenAPI/schema validados en check; pruebas de upgrade 0010→0011 y privilegios en PostgreSQL | Sin nuevo contrato, grants ni DDL en DASH-T08. No se migró una base existente. |
| Idempotencia/concurrencia | Regresión AUTH/USR; snapshot de lectura y autorización viva DASH | DASH-T08 no añade mutaciones ni consumidores. Una lectura ya autorizada conserva su snapshot hasta finalizar. |
| Operación, rollout y reversión | Runbook y configuración test existente; smoke/HTTP/unitarias | Procedimiento reproducible documentado, sin retirada selectiva por tenant. Retirada/reactivación manual completa, rollback binario y restore pendientes. |

## Cierre permitido y trabajo abierto

D4 cierra la aceptación documental/operativa del incremento D1/D2 de laboratorio tras el gate local aprobado registrado en tareas. No declara entregada toda FEAT-003: DASH-T05 conserva issuer/definition/issuance/status y debe repetir matriz/gate por fuente. El panel base no completa el roadmap HK, emisión, wallet, verifier, Events ni conformidad del perfil.

Producción conserva NO-GO: ownership issuer y política de dominios, IdP/MFA/correo reales, HTTPS, secretos/rotación operativa, rate limiting dashboard, retención institucional, observabilidad/alertas/on-call, perfiles de carga/SLO, rollback binario, backup/restore y DR. CI remoto requiere una ejecución posterior a publicar; la validación local no prueba ese resultado. La evidencia histórica DASH-T01–T07 conserva su alcance original.
