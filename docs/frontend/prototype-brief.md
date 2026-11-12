# Brief para prototipo de la consola de operadores

Estado: inventario de lo existente al 2026-11-09, pensado para pegarlo en un asistente (Claude chat) y obtener el prompt de un prototipo navegable. No es una especificación normativa: la autoridad sigue en [AUTH](../03-design/console-auth-interface.md), [USR](../03-design/console-members-interface.md), [DASH](../03-design/console-dashboard-interface.md) y el [design system](design-system.md). Los roles y permisos proceden de esos documentos y no se verificaron de nuevo contra el backend.

Copiar desde la sección siguiente hasta el final.

---

# Contexto: consola de operadores de HukID (para generar el prompt de un prototipo)

## Qué es
HukID es una plataforma para que instituciones emitan credenciales verificables, que los titulares guardan en una wallet. La **consola** es la aplicación web para operadores humanos de una institución (organización o "tenant"). Es un producto distinto de Events. Todo el texto de la UI va en español.

## Qué existe hoy (implementado en React + TypeScript)
Es una sola página (SPA) con secciones, sin rutas. La navegación usa anclas (`#title`, `#overview`, `#members-title`).

1. **Acceso (sin pantalla propia):** no hay landing ni formulario. Sin sesión, la consola redirige al proveedor de identidad (Keycloak), que muestra el formulario y el TOTP. Si falla, aparece "Acceso no completado" con el botón "Iniciar sesión de nuevo".
2. **Estados de sesión** (panel centrado con título, mensaje y acciones):
   - Comprobando sesión (carga).
   - Error: "No pudimos conectar", "Demasiados intentos", "No se pudo autorizar el acceso", "Organización no disponible", "Verifica tu identidad".
   - Acciones: Comprobar acceso, Renovar sesión, Verificar identidad, Iniciar sesión de nuevo.
3. **Selección de organización:** un select "Organización" con badge "Selección requerida". Si el usuario no tiene ninguna: "Acceso pendiente / Sin organización asignada".
4. **Espacio de trabajo** (con organización activa). El título es el nombre de la organización, con badge "Sesión activa" y los roles y capacidades del usuario. Hay dos secciones:
   - **Resumen operativo (dashboard):**
     - Filtros: Desde/Hasta (UTC, máximo 31 días), selector de emisor autorizado y botón "Aplicar periodo".
     - Seis métricas, cada una con valor, estado, alcance y fecha "Datos al…":
       - Miembros activos
       - Emisores activos
       - Versiones publicadas
       - Solicitudes creadas
       - Credenciales emitidas
       - Cambios de estado pendientes
     - Estados de cada métrica: Disponible, Dato antiguo, Fuente no disponible, Error de la fuente, Sin permiso. Un valor ausente se muestra como "—", nunca como 0.
     - "Actividad reciente": lista de eventos de auditoría con acción, resultado (Correcto, Denegado o Fallido), hora y referencia opaca. Tiene paginación por cursor y los botones "Reiniciar actividad" y "Siguiente página de actividad".
   - **Miembros e invitaciones:**
     - Directorio de miembros con filtros por estado, rol y prefijo de identificador.
     - Pestaña de invitaciones con filtro de entrega.
     - Formulario "Invitar persona" (correo y roles).
     - "Editar acceso": roles, estado y razón cerrada, con un diálogo de confirmación ("Revisar cambio") antes de escribir.
     - "Aceptar una invitación" con un campo de código.
     - Revocar invitación y retirar acceso (definitivo).
     - Manejo de conflictos (412 "Cargar versión actual") y de "último administrador".
5. **Encabezado:** marca "HukID" a la izquierda y, a la derecha, la etiqueta "Consola de operadores" más el botón "Cerrar sesión" (solo con sesión).

## Roles y permisos (según la documentación)
- `tenant_admin`: lee el resumen, la actividad, miembros e invitaciones, y escribe sobre ellos.
- `security_admin`: lee miembros; no ve invitaciones ni escribe.
- `issuer_operator` y `support_readonly`: no ven directorios y reciben una explicación de falta de permiso.
- Los enlaces del espacio de trabajo aparecen según capacidades (`dashboard:read`, `audit:read`, `members:read`, `invitations:read`).

## Design system aprobado
- **Estilo:** sobrio, institucional y accesible. Un patrón de panel de contexto más secciones. Sin sombras decorativas. Tema claro y oscuro automático.
- **Colores (claro / oscuro):**

| Token | Claro | Oscuro |
| --- | --- | --- |
| Fondo | `#f4f7fa` | `#11212d` |
| Superficie | `#fff` | `#182e3b` |
| Texto | `#142d3d` | `#e6eff5` |
| Primario (verde azulado) | `#075e67` | `#87d5d1` |
| Hover primario | `#034650` | `#abe9e5` |
| Badge fondo | `#e1f0ef` | `#25454a` |
| Foco | `#1265b3` | `#8bc1ff` |
| Peligro | `#a12435` | `#ffacb4` |

- **Tipografía:** Segoe UI / fuente del sistema. Seis tamaños, de 0,875 a 2 rem, más un h1 fluido.
- **Forma:** radio de 0,5 rem, controles de 3 rem de alto, áreas táctiles de 44 px como mínimo. Contenido de hasta 82 rem. Una columna bajo 768 px.
- **Componentes:** shadcn con Base UI (`base-nova`) y Tailwind v4. Hay Button (default, outline, ghost), Field, Native Select, Label y Separator.
- **Accesibilidad:** un solo h1, foco visible, `role=status` y `role=alert`, estados con texto (no solo color), diálogo nativo con Escape.

## Qué NO existe todavía
- Pantalla de login propia. Es de Keycloak, con su tema por defecto y sin la marca de HukID.
- Emisión de credenciales, gestión de emisores y definiciones, solicitudes y estado de credenciales (revocación o suspensión). Las métricas existen, pero esas fuentes aún no están conectadas.
- Rutas múltiples, menú lateral, buscador global y notificaciones.
- Producción, despliegue y HTTPS. Solo existe el entorno local.

## Lo que quiero
Dame un prompt que pueda usar para que una herramienta de diseño o IA genere un **prototipo navegable** de esta consola. Debe cubrir los estados anteriores y respetar el design system. Dime también qué pantallas extra convendría prototipar para el futuro (emisores, definiciones, credenciales, ajustes).
