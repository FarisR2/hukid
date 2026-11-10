# Reauditoría frontend — correcciones de consola

- Fecha: 2026-11-08.
- Alcance: sólo F-001–F-006 de la [auditoría inicial](2026-11-08-consola.md), sobre la rama `feature/frontend-audit-corrections`, base `c379898`.
- Fuente visual: [design system aprobado](../design-system.md). Flujos y permisos: referencias [AUTH](../../03-design/console-auth-interface.md), [USR](../../03-design/console-members-interface.md) y [DASH](../../03-design/console-dashboard-interface.md).
- Skills aplicadas: `05-frontend-ui-system`, `iso25010-frontend`, `05-clean-implementation`, `06-webapp-testing` y `06-frontend-ui-audit`. Son correcciones de pantallas ya especificadas: no se crean flujos nuevos ni se incorpora shadcn.
- Tipo de revisión: estática, ejecución de Chromium y revisión visual de capturas nuevas. Aprobación del owner obtenida antes de implementar el design system.

## Veredicto: APROBADO

Los seis hallazgos quedan resueltos en el alcance auditado. Cero bloqueantes, altas, medias o bajas pendientes de esta lista. Esto no amplía el alcance productivo ni sustituye una auditoría completa de accesibilidad.

## Resultado por hallazgo

| ID | Regla | Corrección y evidencia | Estado |
| --- | --- | --- | --- |
| F-001 | DOC-MISSING | Design system aprobado y enlazado desde las tres referencias de interfaz; describe tokens, componentes, variantes, layout y estados. | Resuelto |
| F-002 | LAYOUT-01/02, ISO E4 | Acceso compacto con explicación y botón en el mismo flujo; contexto lateral en desktop y apilado móvil. La suite comprueba altura del panel anónimo inferior a 450 px a 1280 px y alineación de texto/acción. Capturas 390/1280 en ambos temas. | Resuelto |
| F-003 | FLOW-03, ISO A4 | Inicialización conserva sólo anclas allowlisted. Tras sesión/contexto válidos restaura foco y sección; destino sin permiso vuelve al título. E2E de recarga a `#title`, `#overview`, `#members-title` y `#content`, destino de miembros sin capacidad y descarte de fragmentos desconocidos/invitación inválida. Regresión real de custodia de invitación conserva su cobertura. | Resuelto |
| F-004 | STATE-07, ISO C1 | Diálogo enumera los alcances issuer que un reemplazo de roles retirará y explica la pérdida de operación. Fixture UI-only comprueba objetivo, consecuencia, lista, Escape/retorno de foco, ausencia de escritura al cancelar y payload de confirmación con `issuerIds: []`. | Resuelto |
| F-005 | STATE-06/A11Y-02, ISO C2 | Error de código con ID, `aria-invalid`, `aria-describedby` y foco; conserva lo escrito. Error de transporte global sin declarar inválido el formato. E2E comprueba ambos errores, recuperación y éxito. | Resuelto |
| F-006 | TOKEN-01/03/04 | Backdrop, escala tipográfica, pesos, tracking, interlineados, bordes, foco, anchos y capa del skip link centralizados. CSS de USR/DASH usa esos tokens. Breakpoint nativo 767 px documentado como excepción técnica; no se añaden herramientas de build. | Resuelto |

## Evidencia ejecutada

| Comprobación | Resultado |
| --- | --- |
| `npm run check` | Aprobado: formato/vet/pruebas Go, TypeScript, 18 pruebas de contratos/IdP y validación documental. |
| `npm run build` | Aprobado: Platform y Console. Bundle JS 263,08 kB; gzip 80,66 kB. |
| `npm run smoke` | Aprobado: rechazo de configuración parcial/productiva, liveness y disponibilidad de HTML/JS. |
| `npm run test:browser` | Aprobado: 39,216 s de suite Go; conserva journey real AUTH/USR/DASH sobre servicios propios y añade fixture UI-only de correcciones. |
| Revisión estática | Colores en tokens; tipografía y medidas reutilizables compartidas. Sin dependencia, migración, contrato API ni cambio de grants. |
| Contraste | 12 pares por tema, calculados desde los tokens CSS cargados en Chromium: texto ≥5,910:1; control/foco ≥4,197:1 en los pares medidos. |
| Estabilidad/rendimiento sintético | LCP 156 ms; CLS 0,07908 frente al límite existente 0,1; evento de interacción máximo observado 16 ms. Dos páginas de actividad/35 eventos únicos, 75,04 ms de siguiente página a renderizado. |

Los tiempos son muestras loopback en Chromium con CPU 4×; el evento máximo no es INP de campo y no fija SLA. La suite conserva reflow 320/360/768/1024/1440 y fuente raíz duplicada; la revisión nueva añade 390/1280 en claro y oscuro.

Durante la implementación, la primera variante visual superó el CLS permitido. La causa se midió en los rectángulos de layout: el contenedor principal cambiaba de ancho al resolver `/me`. Se mantiene un ancho exterior común y sólo la geometría pública durante revalidación; el contenido privado sigue desmontándose. El umbral no se relajó. El fallo de `check` por puerto 19090 ocupado se resolvió aislando la prueba contractual en un puerto libre, sin detener el proceso existente ni cambiar la política runtime.

## Capturas y revisión visual

La suite genera 28 capturas nuevas: siete estados × 390/1280 × claro/oscuro. Estados: carga, acceso, contexto autenticado, error de código, error de transporte, confirmación de retirada de alcances y aceptación exitosa. Los datos son sintéticos; los códigos no se serializan ni aparecen en claro.

Artefactos locales: `.cache/browser-auth/audit-*.png`, `audit-contrast.json`, `layout-shifts.json`, `performance.json` y `dashboard-performance.json`. Las capturas se copian también a `docs/frontend/audits/2026-11-08-consola-correcciones/screens/`, excluida de Git como evidencia generada. El código del recorrido reproducible está en [frontend_audit.py](../../../tests/browser/frontend_audit.py).

Inspección manual realizada: acceso 1280 claro/oscuro y 390 claro; error de código 390 oscuro; confirmación 1280 claro y 390 oscuro; éxito de aceptación 390 claro. Se observa proximidad texto/acción, reflow, consecuencia de retirada visible y error de campo claro. Las demás capturas fueron generadas y comprobadas sin overflow, pero no se afirma inspección manual de todas.

## Límites y pendientes reales

- F-004 usa una respuesta de directorio y un comando interceptados explícitamente: prueba la presentación y el payload, no una asignación real de ownership issuer. El backend continúa rechazando asignaciones sin autoridad confiable.
- No se ejecutó la suite PostgreSQL separada: no hay cambios de persistencia. La suite de navegador sí usa un clúster propio descartable para el journey existente.
- El contraste medido cubre los pares enumerados en el fixture; no cubre cada combinación del DOM, todos los estados de controles, modo forzado ni contenido arbitrario.
- Lector de pantalla, zoom nativo, otros motores, dispositivos físicos, axe/Lighthouse y rendimiento de campo siguen sin verificarse aquí.
- DASH-T05, IdP/MFA/correo reales, CI remoto y todos los bloqueos productivos anteriores permanecen abiertos. No se hace push ni merge como parte de esta entrega local.
