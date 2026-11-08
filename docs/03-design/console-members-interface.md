# Interfaz de miembros e invitaciones — USR-T08

Estado: UI React conectada al BFF de laboratorio. Continúa [FEAT-002](../features/FEAT-002-user-management/spec.md), sin nuevas rutas, capacidades, dependencias ni migraciones. [ADR-0018](../decisions/ADR-0018.md) registra la custodia del intento de aceptación y la recuperación de conflictos. El [contrato de miembros](console-members-contract.md) conserva la autoridad normativa de campos, roles, errores y lifecycle.

## Uso

1. Iniciar sesión y seleccionar explícitamente la organización mediante [AUTH](console-auth-interface.md).
2. En «Miembros e invitaciones», consultar miembros por estado, rol o prefijo de identificador; las invitaciones añaden filtro de entrega. La paginación usa el cursor opaco del servidor. Actualizar, limpiar filtros o volver al inicio permite recuperar páginas vencidas.
3. Abrir «Invitaciones» y «Invitar persona». Introducir el correo autorizado y roles. Una invitación nueva reemplaza una pendiente del mismo destinatario según el contrato. La lista conserva sólo identificadores y destinatario protegido; nunca devuelve enlaces o códigos. La entrega enviada no acredita aceptación.
4. El destinatario autenticado abre el enlace de su invitación o introduce el código en «Aceptar una invitación». No requiere organización previa ni acceso al directorio. Tras aceptar, /me se relee y se pide seleccionar organización; la aceptación no la selecciona automáticamente.
5. En «Miembros», abrir «Editar acceso», elegir roles y/o estado y una razón cerrada. «Revisar cambio» muestra objetivo, estado, roles y razón en un diálogo antes de escribir. La revocación de invitaciones usa el mismo patrón. Revocar acceso es definitivo para su lifecycle; el reingreso necesita una invitación nueva.

El administrador de seguridad puede leer miembros, sin invitaciones ni escrituras. Soporte y operador de issuer ven una explicación de falta de permiso sin que la UI solicite esos directorios. Las capacidades de /me orientan los controles; el backend reautoriza cada petición y replay. Los alcances issuer existentes se muestran y un cambio de estado los conserva. La asignación de emisores permanece inhabilitada mientras no exista una fuente confiable; quitar issuer_operator elimina esos alcances mediante un reemplazo explícito de roles.

## Escritura y recuperación

El cliente comparte el carril Web Locks de AUTH, cookies same-origin, no-store y redirect:error. POST/PATCH agregan CSRF e Idempotency-Key, y las ediciones If-Match fuerte de la revisión observada. Una solicitud exacta conserva su key tras una respuesta perdida; el navegador no reintenta automáticamente ni anuncia éxito antes de recibir respuesta satisfactoria. Cambiar el payload o la revisión produce otra key. Las claves y huellas sólo viven en memoria; no hay persistencia de borradores.

412 conserva roles, estado y razón. Impide confirmar de nuevo hasta «Cargar versión actual»: consulta el registro por el listado autorizado, muestra revisión/roles/estado actuales y mantiene la propuesta para comparar. No reaplica automáticamente. Un registro revocado/terminal o ausente queda sin escritura. El backend sigue comprobando ETag y último administrador al confirmar otra vez.

403 por MFA pide verificar identidad; las verificaciones OIDC y comprobaciones de acceso pueden desmontar los formularios, por lo que el mensaje avisa de que habrá que introducir de nuevo los cambios. 401/404/403, último administrador, invitación inválida, cursor vencido, rate limit, operación en curso y dependencia tienen mensajes seguros. El botón «Comprobar acceso» vuelve a cargar la autoridad. Tras una mutación exitosa se releen /me y el listado; cambios de actor/tenant/revisión desmontan el contexto anterior. AbortController descarta resultados de componentes retirados; ocultar/salir de la página elimina la UI privada conforme a AUTH.

## Custodia del código de aceptación

La forma concreta de enlace de UI es `/#invitation=<código>`; no se admite código en query ni path. Antes de renderizar React se elimina cualquier fragmento con replaceState. Un fragmento válido se transfiere una vez al componente y sólo a memoria; el campo password no serializa su valor como atributo HTML. El código sólo sale en el body POST same-origin a /console/api/invitation-acceptances. No se envía al directorio, al IdP, a logs ni a storage. Dev/preview conserva no-referrer/no-store; no se incorporan analytics ni scripts externos.

Si no hay sesión válida, se descarta el código y se pide reabrir la invitación después del login. Verificar identidad, salir u ocultar la página también descarta el intento. No se transporta por returnTo ni se guarda en localStorage/sessionStorage. Un reintento de aceptación tras fallo incierto conserva la misma key mientras permanezca el componente; recargar pierde ese intento y no promete recuperar un replay ya consumido.

El proveedor de laboratorio sigue sin enviar correo real. El navegador de pruebas recibe el código exclusivamente por stdin desde el proveedor sintético del worker. La UI administrativa nunca lo recupera de la API ni lo muestra como enlace compartible.

## Verificación y calidad

La referencia visual común es el [design system](../frontend/design-system.md). La confirmación de un reemplazo de roles enumera los alcances issuer existentes que se retirarán y explica la pérdida de operación sobre esos emisores. Esto no habilita asignaciones nuevas. En aceptación, un código de formato inválido conserva el valor, recibe foco y muestra error asociado mediante `aria-invalid` y `aria-describedby`; un error de red permanece global y no declara inválido el formato.

El patrón es listado CRUD con edición explícita y diálogo nativo; reutiliza paleta, espaciado y controles AUTH. La región anuncia carga, vacío, resultados, error y permisos mediante status/alert. Los registros son filas semánticas con acciones contextuales, estados en badges, fechas UTC y códigos opacos con reflow. El diálogo empieza en «Volver a editar», atrapa el foco nativo, admite Escape y restaura foco al cerrar. Los campos tienen etiquetas, validación nativa al enviar y foco inicial de formulario sin robarlo al escribir; el código de aceptación usa la validación local asociada descrita arriba, también al salir del campo no vacío.

La suite `npm run test:browser` conserva AUTH y añade [journey USR](../../tests/browser/members.py): API/BFF Go y PostgreSQL descartables, dos identidades OIDC sintéticas, creación, respuesta perdida/replay, entrega por worker/proveedor falso, aceptación sin membership, selección explícita, roles, MFA denegada, 412 recuperable, suspensión, reactivación, revocación terminal, último administrador, revocación de invitación, expiración efectiva y recuperación de dependencia. Incluye teclado y capturas 320/360/768/1024/1440, tema oscuro y reflow 200%. Los casos de error inyectados se distinguen de los comandos reales en el test.

| Checklist ISO/IEC 25010 | Evidencia / límite |
| --- | --- |
| A–B: jerarquía y operación | Un h1, navegación de directorio con aria-pressed, filas/acciones contextuales y controles táctiles heredados de AUTH. |
| C–D: protección y asistencia | Confirmación con objetivo/razón; cancelación/Escape; borrador recuperable en 412; estados y mensajes en español. |
| E–G: coherencia, inclusión y responsive | Tokens AUTH, contraste heredado, foco visible, screenshots/reflow de laboratorio. No certifica WCAG ni lector físico. |
| H: fiabilidad/seguridad | Idempotencia comprobada tras pérdida de respuesta, permisos negativos, fragmento retirado, storage vacío, sin código serializado en HTML/logs/audit. Métricas sintéticas en `.cache/browser-auth/performance.json`; no son INP de campo ni SLA productivo. |

P2: lector de pantalla/dispositivos físicos y automatización axe/Lighthouse continúan pendientes. USR-T09 conserva el gate integral, retención y operación. No acredita IdP/MFA/email reales, ownership issuer, carga/restore ni producción. Para retirar la UI, volver al binario/bundle compatible previo sin borrar identidades, membresías, historial o migraciones; no se ha ensayado rollback binario en este incremento.
