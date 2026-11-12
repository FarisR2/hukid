# Design system — HukID Console

Estado: **aprobado por el owner**, 2026-11-08. Documenta la base existente y concreta las correcciones de la [auditoría](audits/2026-11-08-consola.md). La aprobación del diseño no sustituye la evidencia de implementación y validación.

## Alcance y autoridad

Operadores humanos que acceden a una organización, consultan su resumen y administran miembros autorizados. Los flujos y permisos conservan la autoridad de las referencias [AUTH](../03-design/console-auth-interface.md), [USR](../03-design/console-members-interface.md) y [DASH](../03-design/console-dashboard-interface.md). Se usa la estructura documental existente; no se crea otra versión de esas especificaciones.

Alcance aprobado: conservar la identidad visual actual y corregir F-001–F-006 sin un rediseño general. El patrón es acceso con contexto lateral y consola por secciones semánticas, como ya establece el proyecto.

## Stack y componentes existentes

- React/TypeScript y CSS propio; fuentes del sistema. La infraestructura Tailwind v4/shadcn Base UI se incorpora según [ADR-0024](../decisions/ADR-0024.md), sin sustituir componentes en las fases 1 y 2.
- Tokens base en [styles.css](../../src/console/src/styles.css); extensiones de [USR](../../src/console/src/user-management/styles.css) y [DASH](../../src/console/src/dashboard/styles.css).
- Elementos nativos: botones, inputs, selectores, fieldsets y diálogo modal. Componentes existentes: AuthConsole, WorkspaceNavigation, Dashboard, MemberManagement, InviteForm, EditForm, Acceptance y Confirm.
- `src/console/components.json` configura `base-nova`, TSX y variables CSS. Las fases 1/2 dejaron preparada la infraestructura; el incremento de [acceso shadcn](../03-design/console-auth-interface.md#adaptación-shadcnbase-ui--2026-11-08) añade Button, Field, Native Select y sus dependencias Label/Separator por CLI. AUTH usa estas primitivas; USR/DASH conservan sus controles. No mezclar APIs Radix con Base UI.

## Color semántico existente

| Token | Uso | Claro | Oscuro |
| --- | --- | --- | --- |
| `--bg` | Fondo | `#f4f7fa` | `#11212d` |
| `--surface` | Superficie | `#fff` | `#182e3b` |
| `--text` | Texto | `#142d3d` | `#e6eff5` |
| `--muted-foreground` | Texto secundario (antes `--muted`) | `#4e6270` | `#b6c6d0` |
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

### Puente semántico shadcn — fases 1 y 2

El CSS global sigue siendo la fuente única. `background/foreground` referencia `bg/text`; `card` y `popover`, `surface/text`; `primary-foreground`, `on-primary`; `secondary` y `accent`, `badge-bg/badge-text`; `input`, `control-border`; `ring`, `focus`; `destructive`, `danger`. `--muted` ahora representa la superficie `--bg`; su texto usa `--muted-foreground`. La clase `.muted` mantiene su apariencia. Colores, radios y fuentes generados por el preset se adaptan a esta referencia, sin imponer su paleta neutral ni Geist.

Tailwind usa imports separados de tema/utilidades sin Preflight. El CSS previo vive en la capa `legacy`, anterior a utilidades, y sus selectores por elemento excluyen `data-slot`. Se mantiene el tema automático del sistema con `prefers-color-scheme`, también para `dark:`. La incorporación de cada componente verificará sus bases CSS locales, altura de controles de 3rem, contraste y foco: la infraestructura no acredita esos futuros componentes. Detalle, limitaciones del detector CLI y dependencias en [ADR-0024](../decisions/ADR-0024.md); resultados en la [evidencia](audits/2026-11-08-shadcn-infraestructura.md).

### Primitivas de acceso adaptadas

Button mantiene nombres de variante shadcn: `default` para primaria, `outline` para secundaria y `ghost` para salida/terciaria. `secondary`, `destructive` y `link` quedan coherentes con la misma paleta. Tamaños default/lg e icon de 48 px como mínimo; compactos de 44 px como mínimo. Tipografía de cuerpo, radio existente, hover primario mediante `--hover`, outline de foco de 3 px/offset 4 px. No animar ni trasladar el botón al pulsar. Las variantes compartidas viven en el componente; no duplicar wrappers de botones.

Native Select conserva el control del sistema y opciones, ocupa el ancho disponible y usa altura mínima de 48 px. Field agrupa etiqueta, selector y error, con data-invalid y aria-invalid vinculados. Las bases de foco/cursor se aplican a data-slot en la capa components, sin reset global. Label usa 16 px y peso de énfasis. El panel lateral muestra la secuencia del acceso con una lista ordenada, sin convertirla en un indicador de progreso activo.

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
| F-002 | (Sustituido el 2026-11-08: ya no existe acceso anónimo; sin sesión se redirige al proveedor.) Acceso en una columna dentro de su panel; contexto lateral en desktop y apilado en móvil. Reservar el layout de trabajo para los estados que lo necesitan. | Capturas 390/1280, teclado y CLS durante transición; no imponer altura vacía al acceso. |
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

**Ajuste 2026-11-08 (pendiente de aprobación del owner).** Se elimina por completo el estado anónimo y su tarjeta: sin sesión la consola redirige al proveedor de acceso (ADR-0025). Error, carga, selección y workspace conservan el layout anterior; el estado de recuperación «Acceso no completado» usa el layout de error. Con sesión activa, Cerrar sesión vive en el encabezado, junto a la etiqueta fija "Consola de operadores", y deja de estar al final del panel. Detalle en [AUTH interfaz](../03-design/console-auth-interface.md#encabezado-de-sesión-y-acceso-centrado--2026-11-08).

```text
Anónimo (desktop y móvil)            Con sesión
HukID          Consola de operadores HukID      Consola de operadores <Cerrar sesión>
      [ Accede a HukID        ]      [ contenido de trabajo ]
      [ Explicación           ]
      [ [[ Iniciar sesión ]]  ]
        Así accedes a tu espacio
```

La carga conserva mensaje status; el error conserva explicación y recuperación explícita. Acceso pendiente y selección siguen siendo estados AUTH existentes. El ancho exterior común y la conservación de la geometría durante revalidación mantienen el CLS medido bajo el límite existente, sin añadir esperas artificiales ni conservar contenido privado.

## Cierre de implementación previsto

Ejecutar checks generales, build, smoke y suite de navegador del proyecto; añadir regresiones específicas de navegación, pérdida de alcances y error de campo. Revisar capturas de estados afectados en 390/1280 y temas claro/oscuro. Reauditar únicamente los hallazgos corregidos y registrar lo realmente verificado. Crear commit local del incremento validado; cualquier push requiere su aprobación independiente conforme a GitFlow.

Resultado ejecutado y límites: [reauditoría de correcciones](audits/2026-11-08-consola-correcciones.md). Los assets generados de pruebas se conservan localmente y se excluyen de Git.
