# DASH-T07 — E2E, accesibilidad y medición de laboratorio

Fecha: 2026-11-06. Alcance: dashboard base D1/D2, con tenancy/audit reales de laboratorio. [Tareas](../../features/FEAT-003-dashboard/tasks.md), [spec](../../features/FEAT-003-dashboard/spec.md) y [referencia de interfaz](../../03-design/console-dashboard-interface.md). DASH-T05 conserva las fuentes futuras; DASH-T08 conserva runbook, rollout y evidencia global de DoD.

## Reproducción y artefactos

Usar el toolchain de [desarrollo local](../../04-engineering/local-development.md): Go 1.27.3, PostgreSQL 18.6 y Python/Playwright/Chromium del harness existente. Ejecutar desde la raíz:

```powershell
npm run check
npm run test:postgres
npm run build
npm run smoke
npm run test:browser
git diff --check
```

PostgreSQL y navegador usan clústeres descartables propios en loopback, IdP/MFA sintéticos y claves efímeras. No se consulta una base existente. Las mediciones se sobrescriben en `.cache/dashboard-queries.json` y `.cache/browser-auth/dashboard-performance.json`; las capturas quedan en `.cache/browser-auth/dashboard-*.png`. Son artefactos locales ignorados por Git; la evidencia fechada de este informe conserva el resultado de la ejecución indicada, no un umbral exigible en otros equipos.

## Cobertura E2E y accesibilidad

El operador consulta el resumen de su organización, aplica un periodo UTC y recorre actividad autorizada por teclado. Se reutiliza el patrón dashboard y sus tokens; el cambio de UI conserva el foco al sustituir una página de actividad.

| Área / aceptación | Prueba y resultado exigido | Alcance |
| --- | --- | --- |
| Contexto, AC01/08 | Roles vivos, A=1/B=2 miembros; cambio real de tenant y rol; retira navegación/feed al perder permiso. | API/BFF/DB reales; regresión DASH-T04. |
| Paginación, AC04/07 | Treinta eventos sintéticos por tenant con audit/outbox; dos páginas reales, límite 25, IDs sin duplicados, asOf fijo y sin targets del tenant B. | Cursor autenticado real hasta Chromium; los IDs/cursor sólo se comparan en memoria. |
| Teclado/foco, AC07 | Tab desde Actualizar resumen hasta Desde/Hasta/Aplicar; etiquetas y ayuda vinculadas; rango inválido enfoca inicio con aria-invalid; al corregir retira el error. | Controles datetime-local nativos de Chromium, con recorrido acotado de sus subcampos. |
| Recuperación de página, AC07 | Siguiente página enfoca el h3 de actividad antes de retirar el botón; permanece al terminar o fallar y Tab llega a Reiniciar actividad. | Éxito real y cursor inválido interceptado; sin tab stop adicional del encabezado. |
| Estados, AC03/07 | busy/status/alert, vacío, cero, sin permiso, error y stale con texto; reintento 503 independiente del overview. | Fuentes futuras/errores UI se interceptan explícitamente; no se consideran adaptadores operativos. |
| Respuestas tardías, AC08 | Cambio de filtro/tenant descarta respuesta anterior; 401 retira datos y vuelve a login; 403 revalida /me. | Interceptación de retrasos/401, rol real en DB. |
| Reflujo y presentación, QR03 | 320/360/768/1024/1440 px sin desbordamiento, texto 200%, claro/oscuro y movimiento reducido. | Capturas y assertions del harness; no equivalen a zoom óptico ni lector físico. |
| Privacidad, AC09 | Canary email sintético en filtro inválido recibe 422; ausente de logs de aplicación y audit, tanto literal como URL-encoded. Claves dashboard/cursor ausentes de esos destinos. | Amplía comprobaciones AUTH/USR; no cubre logs de proxies, DB o infraestructura externos. |

La regresión de foco falló antes de la corrección: el botón se desmontaba al cargar y el h3 quedaba inactivo. Se corrige con ref y tabindex=-1, moviendo el foco antes de actualizar la página. No cambia contratos, permisos, fuentes, DDL ni compatibilidad; no requiere ADR nuevo.

Revisión de la checklist ISO 25010 aplicada al incremento: estructura/navegación (A), teclado y elementos semánticos (B), validación recuperable (C), etiquetas/estados UTC (D), tokens existentes (E), foco/mensajes/reflujo (F/G) y errores/privacidad/medición (H). No se añade estilo ni se rediseña la pantalla. Lector físico, auditoría automatizada completa de contraste/axe, otros motores, dispositivos reales y carga del piloto siguen sin acreditarse; no se declara certificación WCAG ni conformidad ISO completa.

## Medición de consultas

[TestDashboardQueryMeasurement](../../../src/platform/internal/adapters/postgres/dashboard_measurement_integration_test.go) crea dos tenants con 10.000 eventos cada uno y estadísticas ANALYZE. Usa el rol real hukid_dashboard_runtime, RLS y snapshot autorizado; una conexión, ejecución serial, tres iteraciones de calentamiento descartadas y treinta muestras por operación. No se fuerza un plan ni se cambia un índice. El dataset tiene una membresía activa por tenant; no mide directorios masivos.

Un tracer pgx exclusivo de pruebas mide las consultas efectivas del adaptador. Clasifica con etiquetas fijas y descarta SQL, argumentos, errores, filas e identificadores. Incluye round-trip/consumo de filas; no es tiempo exclusivo del ejecutor SQL ni EXPLAIN ANALYZE. Los tiempos de operación incluyen autorización, contexto y transacción; actividad mide el puerto de lectura, sin transporte HTTP ni cifrado de cursor. La primera página usa límite 1; la posterior usa límite 100 y posición interna a mitad del dataset. Cada lectura comprueba límite+1 para el lookahead. El E2E cubre por separado el cursor público.

Percentiles nearest-rank, en milisegundos, ejecución PostgreSQL local de 35,453 s:

| Operación | Muestras | p50 | p95 | Máximo |
| --- | --- | --- | --- | --- |
| Overview autorizado | 30 | 0,5055 | 1,5146 | 1,6070 |
| Actividad primera, límite 1 | 30 | 0,5996 | 1,2334 | 2,0465 |
| Actividad posterior, límite 100 | 30 | 1,6902 | 2,1157 | 2,2836 |
| Consulta de actividad, ambas variantes | 60 | 0,6013 | 1,5414 | 1,9727 |
| Consulta de autorización | 90 | 0 | 0,6823 | 2,0465 |
| Consulta de conteo de miembros | 30 | 0 | 0,5887 | 1,5146 |

Un cero significa duración por debajo de la resolución observable del reloj en este host Windows; no ausencia de consulta. El informe también conserva contexto, reloj de fuente y begin/commit. Las aserciones exigen 30 conteos, 60 consultas de actividad y 90 revalidaciones para evitar medir una ruta que dejó de ejecutar esas consultas.

No hay concurrencia, red remota, cache fría controlada, saturación, hardware del piloto ni fuentes D3. No se fija p95 objetivo, SLA o SLO a partir de esta muestra. Antes de optimizar deben medirse el volumen y concurrencia del piloto con planes/índices reales y las fuentes que se conecten en DASH-T05.

## Ejecución y límites finales

Pasaron check (Go/vet/formato, TypeScript, 18 contratos/IdP), PostgreSQL (35,453 s), build, smoke y Chromium (45,137 s). El navegador recorrió 35 eventos únicos en dos páginas; la muestra hasta renderizado de la segunda página fue 125,26 ms con CPU 4x. La regresión AUTH registró LCP 112 ms, CLS 0,0521 y mayor interacción observada 32 ms; son métricas del flujo AUTH con dashboard conectado, no un INP de campo ni una distribución exclusiva del dashboard. Revisadas capturas de escritorio, 320 px y oscuro; no se afirma una auditoría completa de contraste a partir de ellas.

La primera medición falló por un cast UUID omitido en el generador sintético; se corrigió el fixture antes de registrar resultados. Las ejecuciones bloqueadas por ACL del sandbox no son fallos del producto; los checks y Chromium se completaron con permisos para sus recursos locales. La evidencia es local: CI remoto, factores reales, restore/DR y preparación productiva siguen pendientes.
