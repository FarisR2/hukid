# Prototipo de la consola HukID (sidebar)

Estado: **aprobado para implementar por [ADR-0027](../../decisions/ADR-0027.md)** (2026-11-09). Este prototipo muestra cómo podría verse la consola con un menú lateral y una vista por sección. No reemplaza a [console-dashboard-interface.md](../console-dashboard-interface.md) ni a [console-members-interface.md](../console-members-interface.md), que siguen siendo la fuente normativa. La decisión está registrada en el ADR-0027 y reflejada en esas dos especificaciones (ver [Cambios respecto a lo implementado](#cambios-respecto-a-lo-implementado)).

Contenido de esta carpeta:

- [prototype.html](prototype.html): prototipo navegable en un solo archivo (HTML, CSS y JavaScript sin dependencias). Se abre con doble clic en el navegador.
- [screenshots](screenshots): capturas de todas las pantallas y estados, a 1440 px de ancho (las de móvil a 390 px).

El botón **Prototipo** (abajo a la derecha) cambia el rol, el estado de sesión, el tema y simula el conflicto 412. No forma parte del producto y no se implementa.

## Cómo usar este documento (para el agente)

1. Leer primero [AGENTS.md](../../../AGENTS.md), las specs de interfaz enlazadas arriba y los `tasks.md` de [FEAT-002](../../features/FEAT-002-user-management/tasks.md) y [FEAT-003](../../features/FEAT-003-dashboard/tasks.md).
2. Mirar las capturas de la sección que se vaya a implementar y abrir `prototype.html` para ver el comportamiento.
3. Implementar con los componentes y tokens existentes de `src/console`. **No copiar el HTML ni el CSS del prototipo.** Es referencia visual y de comportamiento.
4. No cambiar contratos de API, permisos ni textos normativos por lo que muestre el prototipo. Si el prototipo y la spec discrepan, manda la spec y se documenta la diferencia.

## Pantallas

### Espacio de trabajo (tenant_admin)

| Captura | Qué muestra |
| --- | --- |
| ![Resumen](screenshots/01-resumen.png) | **Resumen operativo.** Filtros de periodo, seis métricas con sus cinco estados y actividad reciente. |
| ![Resumen oscuro](screenshots/02-resumen-oscuro.png) | El mismo resumen en tema oscuro. |
| ![Error de periodo](screenshots/03-resumen-error-periodo.png) | Error en línea cuando el periodo supera 31 días. |
| ![Actividad](screenshots/04-actividad.png) | **Actividad.** Filtros por resultado y acción, tabla y paginación por cursor. |
| ![Miembros](screenshots/05-miembros.png) | **Miembros.** Filtros (prefijo, estado, rol), tabla y "Editar acceso". |
| ![Editar acceso](screenshots/06-editar-acceso.png) | Panel lateral de edición: roles, estado, razón y zona de peligro. |
| ![Revisar cambio](screenshots/07-revisar-cambio.png) | Diálogo de confirmación con antes/después y razón. |
| ![Último administrador](screenshots/08-ultimo-administrador.png) | Bloqueo por último administrador; "Revisar cambio" queda deshabilitado con explicación. |
| ![Conflicto 412](screenshots/09-conflicto-version-412.png) | Conflicto de versión con "Cargar versión actual". |
| ![Retirar acceso](screenshots/10-retirar-acceso.png) | Diálogo de retirada definitiva. |
| ![Invitaciones](screenshots/11-invitaciones.png) | **Invitaciones.** Filtro de entrega, tabla y "Revocar". |
| ![Invitar persona](screenshots/12-invitar-persona-error.png) | Diálogo "Invitar persona" con error de correo. |
| ![Aceptar invitación](screenshots/13-aceptar-invitacion-caducada.png) | Diálogo "Aceptar una invitación" con código caducado. |
| ![Revocar invitación](screenshots/14-revocar-invitacion.png) | Confirmación de revocación. |
| ![Menú de usuario](screenshots/15-menu-usuario.png) | Menú de usuario: roles, capacidades, aceptar invitación y cerrar sesión. |

### Vistas por rol

| Captura | Qué muestra |
| --- | --- |
| ![security_admin](screenshots/16-security-admin-miembros-solo-lectura.png) | `security_admin`: Miembros en solo lectura; Invitaciones no aparece en el menú. |
| ![issuer_operator](screenshots/17-issuer-operator-resumen.png) | `issuer_operator`: solo Resumen; métricas y actividad sin permiso explicadas. |
| ![Sin permiso](screenshots/18-support-readonly-sin-permiso.png) | Acceso directo a una sección sin capacidad: explicación y salida. |
| ![Sección futura](screenshots/19-seccion-futura-emisores.png) | Secciones futuras marcadas "Pronto" (Emisores, Definiciones, Solicitudes, Credenciales, Ajustes). |

### Móvil

| Captura | Qué muestra |
| --- | --- |
| ![Móvil](screenshots/20-movil-resumen.png) | Bajo 900 px el menú se oculta y aparece el botón de menú. |
| ![Menú móvil](screenshots/21-movil-menu.png) | Menú lateral abierto sobre la página. |

### Estados de sesión

Todos usan el mismo panel centrado: icono, título, mensaje y acciones.

| Captura | Estado | Acciones |
| --- | --- | --- |
| ![](screenshots/30-sesion-comprobando.png) | Comprobando sesión | Ninguna (carga) |
| ![](screenshots/31-sesion-seleccion-organizacion.png) | Selección de organización | Continuar |
| ![](screenshots/32-sesion-acceso-pendiente.png) | Acceso pendiente | Cerrar sesión, Tengo un código de invitación |
| ![](screenshots/33-sesion-acceso-no-completado.png) | Acceso no completado | Iniciar sesión de nuevo |
| ![](screenshots/34-sesion-no-pudimos-conectar.png) | No pudimos conectar | Comprobar acceso |
| ![](screenshots/35-sesion-demasiados-intentos.png) | Demasiados intentos | Comprobar acceso |
| ![](screenshots/36-sesion-no-autorizado.png) | No se pudo autorizar el acceso | Renovar sesión, Iniciar sesión de nuevo |
| ![](screenshots/37-sesion-organizacion-no-disponible.png) | Organización no disponible | Comprobar acceso, Elegir otra organización |
| ![](screenshots/38-sesion-verifica-identidad.png) | Verifica tu identidad | Verificar identidad |
| ![](screenshots/39-sesion-cerrada.png) | Sesión cerrada | Iniciar sesión |

## Estructura del layout

- **Sidebar** de 252 px, fondo `--bg`, borde derecho de 1 px. De arriba abajo:
  - Marca "HukID" y "Consola de operadores".
  - Selector de organización (select nativo superpuesto a una tarjeta con iniciales, nombre y referencia opaca).
  - Grupos de navegación con encabezado en mayúsculas pequeñas.
  - Al final, el usuario (iniciales, correo, rol). Al pulsarlo se abre un menú con roles, capacidades, "Aceptar una invitación" y "Cerrar sesión".
- **Grupos y capacidades:**

| Grupo | Ítem | Capacidad que lo muestra |
| --- | --- | --- |
| General | Resumen | `dashboard:read` |
| General | Actividad | `audit:read` |
| Acceso | Miembros (contador de no retirados) | `members:read` |
| Acceso | Invitaciones (contador de pendientes, entregadas y fallidas) | `invitations:read` |
| Emisión | Emisores, Definiciones, Solicitudes, Credenciales | Ninguna: marcados "Pronto", solo exploración |
| Organización | Ajustes | Ninguna: marcado "Pronto", solo exploración |

- **Barra superior** de 56 px, fija: botón de menú (solo móvil), migas `Organización / Grupo / Sección`, chip "Sesión activa" y, en el prototipo, el cambio de tema.
- **Contenido**: máximo 1200 px. Cada vista tiene su encabezado con un único `h1`, una descripción de una línea y las acciones primarias a la derecha.
- **Edición de acceso** en un panel lateral derecho de 480 px. Las confirmaciones y los formularios cortos van en diálogos modales nativos.
- **Mensajes** en banners en línea (`role="status"` o `role="alert"`), nunca toasts.

## Reglas de comportamiento que el prototipo demuestra

- Un ítem sin capacidad no aparece en el menú. Si se entra por URL, se muestra "Tu rol no permite ver…" con un enlace al resumen.
- Las métricas tienen cinco estados con texto e icono, nunca solo color: Disponible, Dato antiguo, Fuente no disponible, Error de la fuente y Sin permiso. Un valor ausente es "—", nunca 0.
- La paginación es por cursor: "Siguiente página" y "Volver al inicio" o "Reiniciar actividad". No hay números de página.
- **Editar acceso** valida antes de abrir la confirmación:
  - Si no hay cambios → aviso informativo.
  - Si falta la razón → error en el campo.
  - Si se quita el último `tenant_admin` activo → banner de error y botón deshabilitado.
- **Confirmar** con conflicto de versión → banner "Este miembro cambió mientras lo editabas." y "Cargar versión actual". Después se revisa de nuevo.
- **Retirar acceso** pide razón y es definitivo. Está bloqueado para el último administrador.
- Revocar una invitación solo es posible si está Pendiente, Entregada o Fallida.
- El periodo del resumen admite como máximo 31 días y "Desde" ≤ "Hasta".
- Elegir una organización no disponible lleva al estado "Organización no disponible".

## Correspondencia con el código actual

| Prototipo | Implementación en `src/console` |
| --- | --- |
| Variables de color (`--bg`, `--surface`, `--primary`…) | Tokens ya definidos en `src/styles.css` (`@theme inline` y capa `legacy`). Reutilizarlos; no crear una paleta nueva. |
| Botones primario, outline, ghost, peligro | `components/ui/button.tsx` (añadir variante de peligro si falta). |
| Campos, etiquetas, ayuda y error | `components/ui/field.tsx`, `label.tsx`. |
| Selects | `components/ui/native-select.tsx`. |
| Separadores | `components/ui/separator.tsx`. |
| Sidebar, Sheet, Table, Badge, Dialog | No existen todavía. Añadirlos con el registro shadcn `base-nova` (`components.json`) cuando se apruebe el cambio. |
| Iconos | `lucide-react` (ya instalado). El prototipo usa trazos equivalentes. |
| Navegación por hash con validación de capacidades | Hoy en `src/navigation.ts` (`sectionHashes`, `restoreSection`) con anclas de sección. |
| Resumen y actividad | `src/dashboard/Dashboard.tsx`, `WorkspaceNavigation.tsx`, `dashboard/client.ts`. |
| Miembros, invitaciones, editar acceso | `src/user-management/MemberManagement.tsx`, `forms.tsx`, `client.ts`. |
| Estados de sesión | `src/authentication/AuthConsole.tsx`, `authentication/client.ts`. |

## Cambios respecto a lo implementado

Estos puntos cambian decisiones documentadas y requieren acuerdo del owner y un ADR antes de tocar código:

1. **Navegación.** Hoy es una sola página con anclas (`#title`, `#overview`, `#members-title`). El prototipo propone un sidebar con una vista por sección (`#resumen`, `#actividad`, `#miembros`, `#invitaciones`). Afecta a `navigation.ts`, a las specs de interfaz y a las pruebas de navegador que restauran secciones.
2. **Actividad** pasa de subsección del resumen a vista propia, y el resumen conserva solo las cinco últimas entradas.
3. **Invitar persona** y **Aceptar una invitación** pasan de tarjetas fijas a diálogos.
4. **Editar acceso** pasa a un panel lateral.
5. **Tema.** La app actual sigue solo la preferencia del sistema (`@custom-variant dark`). El botón de tema del prototipo es una conveniencia de la demo y no se implementa salvo que se decida.
6. **Altura de controles.** El prototipo usa 40 px por densidad. El design system aprobado pide controles de 3 rem y áreas táctiles de 44 px; manda el design system salvo decisión contraria.
7. **Secciones "Pronto".** Emisión y Ajustes son exploración; no están en el roadmap acordado ([hukid-roadmap.md](../../05-delivery/hukid-roadmap.md)). No implementarlas como vistas reales.

## Qué no copiar del prototipo

- El panel "Prototipo" y sus controles.
- Los datos de ejemplo (personas, referencias, fechas) y la lógica simulada en memoria. Los datos vienen de los clientes existentes.
- Los permisos de `issuer_operator` y `support_readonly`: en el prototipo solo tienen `dashboard:read`, pero es una suposición. La fuente es [console-members-contract.md](../console-members-contract.md) y el backend.
- Los códigos de invitación de prueba que aparecen en el texto de ayuda.

## Orden sugerido de implementación

1. ADR y actualización de las specs de interfaz con el layout aprobado.
2. Shell: sidebar, barra superior, selector de organización y menú de usuario, con filtrado por capacidades y la vista "sin permiso".
3. Navegación por vistas en `navigation.ts`, conservando la regla de no restaurar fragmentos de invitación.
4. Resumen y Actividad como vistas separadas.
5. Miembros con el panel lateral de edición, conflicto 412 y último administrador.
6. Invitaciones con los diálogos de invitar, aceptar y revocar.
7. Estados de sesión con el panel centrado.
8. Responsive (menú lateral desplegable bajo 900 px) y revisión de accesibilidad: un `h1` por vista, foco visible, Escape en diálogos y estados con texto.

Cada paso se valida con `npm run check:console`, `npm run test:browser` y `npm run check:docs`, como indica [local-development.md](../../04-engineering/local-development.md).
