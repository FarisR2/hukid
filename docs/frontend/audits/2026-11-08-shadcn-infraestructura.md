# Integración shadcn — fases 1 y 2

Fecha: 2026-11-08. Alcance: infraestructura de consola; sin migración de componentes. Decisión: [ADR-0024](../../decisions/ADR-0024.md). Identidad: [design system](../design-system.md).

## Baseline

- Git inicialmente limpio, HEAD `2f98258` en `feature/frontend-audit-corrections`. Rama de trabajo `feature/shadcn-infrastructure` creada desde esa base local para conservar las correcciones aprobadas. Sin commit ni push.
- `npm run check:console`: aprobado.
- `npm run build:console`: aprobado, 26 módulos; CSS 11,25 kB / gzip 2,92 kB; JS 263,08 kB / gzip 80,66 kB.
- `npm run test:browser`: aprobado, 61,425 s. Clúster PostgreSQL descartable y Chromium; sin conexión a base existente.
- Medición sintética: LCP 344 ms, CLS 0,0790778, interacción máxima 32 ms. No equivale a métricas de campo.
- Capturas y métricas previas preservadas localmente en `.cache/shadcn-baseline`; incluyen 28 capturas deterministas a 390/1280 px, claro/oscuro, de carga, acceso, workspace, errores, confirmación y aceptación.
- Sin fallo funcional previo observado. Starship emite advertencia `TERM=dumb` en algunas invocaciones, sin impedir los checks. Las primeras consultas/instalaciones restringidas fallaron por EACCES de red; reintentos con permisos aprobados completaron la operación. `base-nova` no es un argumento válido de preset en la CLI actual: se corrigió a `nova` con `--base base`.

## Cambios revisados

CLI 4.23.0 detectó Vite, Tailwind v4 y alias. Creó `components.json`, `src/lib/utils.ts` y modificó CSS/dependencias. Se revisó el resultado antes de conservarlo; se restauraron colores/radio/fuente aprobados, se omitió Preflight y se retiraron extras sin uso. `components/ui/.gitkeep` conserva la carpeta vacía.

Dependencias directas añadidas: `@base-ui/react` 1.9.0 y `cn` 0.5.2. Dependencias de desarrollo: `tailwindcss` y `@tailwindcss/vite`, ambas 4.3.5. El manifiesto raíz conserva sus valores y el lockfile sigue siendo único en la raíz. Comparación de versiones existentes en lock: ninguna actualización ni eliminación. Instalación final: 0 vulnerabilidades informadas por npm.

MCP usado: `get_project_registries`, `view_items_in_registries` y `get_audit_checklist`. La consulta de `@shadcn/init` devuelve NOT_FOUND; no se inventó un componente init. La consulta genérica Button devuelve Radix; se verificó la variante real con CLI `info` y `add @shadcn/button --dry-run/--view`, sin añadir componentes. `info` confirma base `base`, rutas locales y componentes vacíos; la autodetección CSS y la dependencia CVA omitida del resumen de preview se explican en ADR-0024.

## Verificación posterior

| Comprobación | Resultado |
| --- | --- |
| `npm run check:console` | Aprobado, sin errores TypeScript. |
| `npm run build:console` | Aprobado, 26 módulos; CSS 14,48 kB / gzip 3,50 kB; JS 263,08 kB / gzip 80,66 kB. |
| `npm run test:browser` | Aprobado, 62,715 s; AUTH, miembros, dashboard y regresiones de auditoría sobre laboratorio aislado. |
| Rendimiento sintético | LCP 216 ms; CLS 0,0790778; interacción máxima 32 ms. Dentro de los umbrales existentes; sin prometer métricas de campo. |
| Contraste | 12 pares por tema, 24 en total, aprobados con las mismas garantías y valores de la paleta anterior. |
| `npm run check:docs` | Aprobado: 119 Markdown y 1135 enlaces/anclas locales, bloques y estructura. |
| `git diff --check` | Aprobado; advertencias de normalización LF/CRLF del checkout, sin errores de whitespace. |
| Límites de arquitectura | Diff de lógica de aplicación/contratos/backend vacío; manifiesto raíz sin cambios. Ninguna versión previa del lock actualizada/eliminada. |
| Utilidad `cn` | Comprobada fusión de clases en conflicto: `px-2` + `px-4` produce `px-4`. |

Comparación visual real con Chromium: las 28 capturas de auditoría cubren 390 y 1280 px en claro y oscuro. Se compararon dimensiones y píxeles con las imágenes de baseline: 8 idénticas (carga/acceso en todas las combinaciones), 20 con diferencias; dimensiones idénticas en las 28. En estas últimas cambian principalmente las horas de filtros que se generan con el reloj real, junto con pequeñas diferencias residuales de captura; no se afirma igualdad píxel a píxel completa. Comparación local en `.cache/shadcn-cli-review/pixel-comparison.json`.

Se inspeccionaron visualmente 10 imágenes: acceso posterior 390 claro/1280 oscuro; workspace posterior y anterior 390 oscuro/1280 claro; confirmación posterior 390 claro/1280 oscuro. Sin regresión observada de geometría, identidad, reflow, contraste o foco en la muestra revisada. Las capturas workspace incluyen la sección de dashboard en error/no-permiso y el directorio; la suite adicional ejercita también el dashboard con datos, permisos y paginación. El reloj variable impide tratar esta comparación como un gate visual determinista; fijarlo y estabilizar caret/captura es una mejora de pruebas pendiente.

El incremento aumenta CSS gzip aproximadamente 0,58 kB, manteniendo el tamaño JS publicado por Vite. Ni Base UI ni cn se importan en las pantallas actuales; están preparados para la migración posterior. No se ejecutó una nueva prueba de lector de pantalla ni de dispositivos físicos.

## Límites y reversión

No se ha migrado ningún componente. La fase 3 requiere revisar bases sin Preflight, tamaños del preset, foco, contraste y dependencias reales de cada import; no basta con el resumen CLI. Quedan pendientes lector de pantalla, zoom nativo, otros motores/dispositivos y métricas de campo. No se amplía el alcance de laboratorio ni se cierran dependencias productivas/HK/DASH-T05.

Para revertir antes de commit, revisar primero el diff y preservar cualquier trabajo posterior. Restaurar únicamente los cambios propios de `src/console/package.json`, `package-lock.json`, `src/console/tsconfig.json`, `src/console/vite.config.ts`, las tres hojas CSS, la renombración del token en la prueba y la documentación de este incremento; retirar los nuevos `components.json`, `src/lib/utils.ts` y marcador UI si siguen siendo exclusivamente de este trabajo. Ejecutar `npm ci` desde la raíz con el lock anterior y repetir check/build/navegador. No usar reset/clean global ni eliminar las correcciones de `2f98258`.

Para iniciar la fase 3 se recomienda un único incremento de selector de organización con Button/Field/Native Select, conservando todos los callbacks y contratos. Esta recomendación no constituye ejecución de la fase 3.
