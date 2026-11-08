# Design system — HukID Console

Estado: **aprobado por el owner**, 2026-11-08. Documenta la base existente y concreta las correcciones de la [auditoría](audits/2026-11-08-consola.md). La aprobación del diseño no sustituye la evidencia de implementación y validación.

## Alcance y autoridad

Operadores humanos que acceden a una organización, consultan su resumen y administran miembros autorizados. Los flujos y permisos conservan la autoridad de las referencias [AUTH](../03-design/console-auth-interface.md), [USR](../03-design/console-members-interface.md) y [DASH](../03-design/console-dashboard-interface.md). Se usa la estructura documental existente; no se crea otra versión de esas especificaciones.

Alcance aprobado: conservar la identidad visual actual y corregir F-001–F-006 sin un rediseño general. El patrón es acceso con contexto lateral y consola por secciones semánticas, como ya establece el proyecto.

## Stack y componentes existentes

- React/TypeScript y CSS propio; fuentes del sistema. Sin dependencia nueva.
- Tokens base en [styles.css](../../src/console/src/styles.css); extensiones de [USR](../../src/console/src/user-management/styles.css) y [DASH](../../src/console/src/dashboard/styles.css).
- Elementos nativos: botones, inputs, selectores, fieldsets y diálogo modal. Componentes existentes: AuthConsole, WorkspaceNavigation, Dashboard, MemberManagement, InviteForm, EditForm, Acceptance y Confirm.
- No hay shadcn ni `components.json`: `05-shadcn-base-ui` no aplica a este incremento.

## Color semántico existente

| Token | Uso | Claro | Oscuro |
| --- | --- | --- | --- |
| `--bg` | Fondo | `#f4f7fa` | `#11212d` |
| `--surface` | Superficie | `#fff` | `#182e3b` |
| `--text` | Texto | `#142d3d` | `#e6eff5` |
| `--muted` | Texto secundario | `#4e6270` | `#b6c6d0` |
| `--border` | Divisores | `#d0dbe2` | `#3f5968` |
| `--control-border` | Controles | `#687f8c` | `#819caa` |
| `--primary` | Acción principal/enlaces | `#075e67` | `#87d5d1` |
| `--hover` | Hover primario | `#034650` | `#abe9e5` |
| `--on-primary` | Texto sobre primario | `#fff` | `#102c32` |
| `--badge-bg` | Fondo de badge | `#e1f0ef` | `#25454a` |
| `--badge-text` | Texto de badge | `#145b57` | `#b4e4df` |
| `--focus` | Foco | `#1265b3` | `#8bc1ff` |
| `--danger` | Error/destructivo | `#a12435` | `#ffacb4` |

El backdrop `#0009` usa el token `--backdrop`, con el mismo valor en ambos temas. Los colores no se redefinen en componentes. Contraste objetivo: 4,5:1 texto normal y 3:1 componentes/texto grande; medir los pares afectados al verificar.

## Espaciado, forma y layout

- Conservar `--s1` a `--s8`: 0,25 / 0,5 / 0,75 / 1 / 1,5 / 2 / 3 / 4 rem.
- Conservar `--radius: .5rem` y controles `--control: 3rem`; área táctil mínima 44 × 44 px.
- Encabezado/pie: ancho existente de 68 rem; contenido principal: 82 rem tanto en acceso como en workspace. El acceso usa dos regiones, con un panel compacto a la izquierda. Compartir el ancho exterior evita desplazar toda la página al resolver `/me`; se ajustó esta medida al detectar CLS en la verificación. Texto corrido: máximo 65 ch.
- Desktop desde 768 px; una columna bajo ese límite. CSS nativo no admite variables CSS en media queries: conservar el breakpoint literal documentado en vez de introducir herramientas de build.
- Bordes estructurales, grosor/offset de foco y z-index del skip link se centralizan en tokens; no agregar sombras decorativas.
- Formularios: etiquetas junto a campos; ayuda y errores debajo; acciones agrupadas. Sin scroll interno salvo el necesario para un diálogo que exceda el viewport.

## Tipografía

Conservar Segoe UI/system-ui y monoespaciada para IDs. Consolidar la escala existente en seis tamaños semánticos: secundario 0,875 rem; cuerpo 1 rem; título de región 1,125 rem; título de sección/marca 1,5 rem; cifra/contexto 2 rem; h1 fluido `clamp(2rem, 4vw, 2.75rem)`. La cita lateral usa el tamaño de sección; en móvil, el de región. Los pesos, interlineados y tracking se nombrarán como tokens reutilizables, conservando la jerarquía actual salvo estos dos ajustes menores de la cita lateral.

## Variantes y estados

| Elemento | Variantes existentes | Convención |
| --- | --- | --- |
| Botón | `.primary`, neutro, `.quiet`, `.danger` | Una acción principal por región; destructivo para retirar acceso; secundario antes de confirmar en diálogo. |
| Campo | input/select nativos | Label visible, ayuda asociada; error de campo con ID, `aria-invalid` y `aria-describedby`; conservar entrada. |
| Estado | `.badge`, status/alert | Texto explícito; no depender sólo del color. |
| Diálogo | `Confirm`, diálogo nativo | Objetivo, diferencia y consecuencias; foco inicial en volver a editar, Escape y restauración del foco. |
| Datos | Regiones de resumen/directorio | Carga, vacío, error y reintento; separar error parcial y falta de permiso de un conteo cero. |

Deshabilitar el envío sólo durante su operación, con texto que indique progreso. Mantener la protección de doble envío y los reintentos explícitos. Español en UI; fechas UTC explícitas; sin cambios de política de datos privados ni de permisos.

## Correcciones aprobadas

| Hallazgo | Resultado esperado | Validación prevista |
| --- | --- | --- |
| F-001 | Esta referencia consolida tokens, variantes y estados; enlazarla desde las referencias de interfaz. | Enlaces y correspondencia documento/CSS. |
| F-002 | Acceso anónimo en una columna dentro de su panel, explicación seguida de Iniciar sesión; contexto lateral en desktop y apilado en móvil. Reservar el layout de trabajo para los estados que lo necesitan. | Capturas 390/1280, teclado y CLS durante transición; no imponer altura vacía al acceso. |
| F-003 | Conservar únicamente anclas de navegación reconocidas al iniciar; retirar fragmentos de invitación antes de renderizar. Restaurar sección y foco sólo cuando el contexto autorizado esté disponible. | Recarga a anclas, destino no autorizado y regresión de custodia del código. |
| F-004 | Si una edición retira alcances issuer existentes, enumerar los alcances afectados y explicar que se perderá ese acceso antes de confirmar. | Caso específico con alcances existentes; cancelación y confirmación, sin habilitar asignaciones nuevas. |
| F-005 | Código de formato inválido conserva valor, recibe foco y error asociado. Un fallo de red permanece global y no marca el formato inválido. | Validación por teclado, atributos accesibles y recuperación tras fallo de red. |
| F-006 | Backdrop, tipografía y medidas reutilizables desde tokens; excepciones técnicas documentadas. | Búsqueda estática y capturas en claro/oscuro. |

Wireframe de acceso aprobado; no altera el paso delegado al IdP:

```text
Desktop
HukID                                      Consola de operadores
[ Accede a HukID                ]   Un acceso. El contexto correcto.
[ Explicación del acceso       ]   Contexto de organizaciones.
[ [[ Iniciar sesión ]]         ]

Móvil
HukID
[ Accede a HukID                ]
[ Explicación del acceso       ]
[ [[ Iniciar sesión ]]         ]
Contexto de organizaciones.
```

La carga conserva mensaje status; el error conserva explicación y recuperación explícita. Acceso pendiente y selección siguen siendo estados AUTH existentes. El ancho exterior común y la conservación de la geometría durante revalidación mantienen el CLS medido bajo el límite existente, sin añadir esperas artificiales ni conservar contenido privado.

## Cierre de implementación previsto

Ejecutar checks generales, build, smoke y suite de navegador del proyecto; añadir regresiones específicas de navegación, pérdida de alcances y error de campo. Revisar capturas de estados afectados en 390/1280 y temas claro/oscuro. Reauditar únicamente los hallazgos corregidos y registrar lo realmente verificado. Crear commit local del incremento validado; cualquier push requiere su aprobación independiente conforme a GitFlow.

Resultado ejecutado y límites: [reauditoría de correcciones](audits/2026-11-08-consola-correcciones.md). Los assets generados de pruebas se conservan localmente y se excluyen de Git.
