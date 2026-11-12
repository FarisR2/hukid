# Auditoría — encabezado de sesión y acceso centrado (2026-11-08)

Alcance: mover Cerrar sesión al encabezado, presentar el estado anónimo como tarjeta centrada y actualizar [ADR-0024](../../decisions/ADR-0024.md). Detalle de diseño en [AUTH interfaz](../../03-design/console-auth-interface.md#encabezado-de-sesión-y-acceso-centrado--2026-11-08). El ajuste visual está **pendiente de aprobación del owner**.

## Cambios

- `AuthConsole.tsx`: botón Cerrar sesión (mismo callback y nombre accesible) dentro de `.header-session`; se elimina el bloque `.logout` del panel. El botón siempre ocupa su espacio y usa `invisible` sin sesión.
- Clase `anonymous` en `<main>` para el estado anónimo; reglas en `styles.css` (capa `components`).
- Se descartó mostrar el nombre de la organización en el encabezado: al cambiar el ancho de la etiqueta tras `/me` añadía desplazamiento (CLS 0,0706–0,1001 en las pruebas intermedias). La etiqueta queda fija.

## Verificación ejecutada

| Comprobación | Resultado |
| --- | --- |
| `npm run check:console` (tsc) | Pasa. |
| `npm run build` | Pasa. |
| `npm run check:docs` | Pasa. |
| `npm run test:browser` (dos ejecuciones finales) | Pasa: login, pendiente, tenant, sesión, dashboard y miembros, incluido el botón único "Cerrar sesión". |
| Rendimiento sintético | LCP 312–328 ms, CLS 0,088146875, interacción máxima 32–40 ms. El CLS es idéntico al registrado en [login shadcn](2026-11-08-login-shadcn.md); el umbral de la prueba es 0,1. |
| Capturas revisadas | `login-desktop.png` (tarjeta centrada) y `session-1440.png` (Cerrar sesión arriba, visible sin desplazarse). |

## No verificado

- Capturas de 390 px, tema oscuro y estados error/pendiente del acceso con el nuevo encabezado: generadas por la suite, no revisadas una a una.
- El CLS está cerca del umbral (0,088 de 0,1); la fuente restante es el título y el pie al cargar el workspace, anterior a este cambio.
- No se probó con lector de pantalla ni dispositivo físico. No acredita MFA real ni un IdP productivo.
- Sin commit ni push.
