# Interfaz del dashboard — DASH-T04

Estado: implementación de laboratorio. Referencias: [spec](../features/FEAT-003-dashboard/spec.md), [API/BFF](console-dashboard-http.md), [contrato](console-dashboard-contract.md) y [ADR-0022](../decisions/ADR-0022.md).

## Contexto y navegación

La consola reutiliza la sesión AUTH y el tenant seleccionado de GET /console/api/me. Muestra el nombre de la organización, roles actuales y capacidades; los enlaces a resumen y miembros aparecen sólo con las capacidades correspondientes. La selección y los controles de sesión siguen disponibles. Los enlaces llevan a secciones semánticas de la misma página; no añaden rutas SPA ni dominios inexistentes. Las URLs BFF conservan autorización en servidor.

El contrato de contexto anterior incluía capacidades, issuerIds y revisión, pero omitía roles aunque AC01 los solicita. DASH-T04 añade roles al contexto BFF/Management, obtenidos de la misma membresía viva que calcula las capacidades. El schema admite el campo opcional para compatibilidad con respuestas anteriores; el servidor actual lo emite siempre. No se infiere un rol desde sus permisos, no cambia la matriz y no se aceptan roles como entrada del navegador. Sin el campo, un servidor anterior muestra las capacidades disponibles.

## Datos y controles

El cliente dashboard consulta únicamente los GET BFF reales, con credenciales same-origin, no-store, redirects rechazados y el carril compartido de solicitudes de sesión. No contiene fixtures operativos, persistencia local ni caché compartida. Valida tenant, emisor, ventana y forma de los datos antes de renderizar.

El rango inicial es de 24 horas, con entradas explícitas UTC y límite de 31 días, incluyendo el inicio y excluyendo el fin. La UI convierte valores datetime-local a timestamps UTC con segundos, incluso si el navegador normaliza segundos cero. El servidor mantiene la validación definitiva. Las opciones issuer sólo proceden de issuerIds de /me; no hay catálogo issuer ni posibilidad de escribir un selector libre. Sin ownership confiable, el backend conserva su rechazo cerrado.

Las seis métricas muestran fuente, alcance temporal, estado y asOf cuando existe; el encabezado muestra generatedAt y ventana aplicada. available con valor 0 se presenta como cero; unavailable/error/notAuthorized conservan valor ausente, sin inventar conteos. stale mantiene el valor con advertencia de antigüedad. Miembros, emisores, definiciones y publicación de estado son snapshots actuales, no históricos del periodo. Las fuentes futuras siguen desconectadas.

La actividad sólo se solicita con audit:read, muestra eventos allowlisted y referencias opacas del contrato, sin identidad personal ni payload. Incluye vacío, siguiente página con cursor en memoria y reinicio de paginación. Un error de actividad no elimina el resumen disponible. Actualizar resumen reintenta las lecturas y reinicia el cursor; Reiniciar actividad recupera el feed por separado, incluido cursor vencido o inválido.

## Invalidación y errores

El componente se identifica por actor, tenant, revisión, capacidades y scopes issuer. Un cambio de contexto desmonta la generación anterior. Cada lectura usa AbortController, timeout de 12 segundos y comprueba la cancelación antes de actualizar el estado; los cambios de filtros también descartan respuestas anteriores. Los eventos AUTH de visibilidad, historial, salida y notificaciones entre pestañas desmontan los datos al revalidar /me.

401 retira el dashboard y muestra el login, sin reintento automático. 403/404 solicitan revalidar /me y mantienen una recuperación explícita; no convierten el rechazo en datos parciales ni reintentan indefinidamente un contexto sin cambios. Una revisión distinta reconstruye la vista con permisos actuales. Errores de transporte, 422 y 503 conservan los filtros y ofrecen reintento. Los mensajes no exponen errores SQL ni payloads internos.

## Accesibilidad y verificación

La corrección de vigencia [ADR-0023](../decisions/ADR-0023.md) mantiene las marcas asOf/generatedAt del overview base en el mismo reloj PostgreSQL. Evita 503 intermitentes por diferencias entre el reloj de Go y el de la fuente; no cambia el cliente ni los estados mostrados.

Un único h1 de organización, navegación con aria-current, etiquetas visibles, foco de teclado, estado busy y mensajes status/alert. Los conteos usan lista de definiciones; la actividad es una lista ordenada. Reutiliza tokens, controles y colores claro/oscuro de AUTH/USR; los estados tienen texto y no dependen del color. El rango inválido conserva el borrador y enfoca el inicio. La grilla pasa a una columna en móvil.

El harness Chromium se amplía con la credencial/clave dashboard efímeras propias. Los conteos, revalidación de roles y errores de permisos usan API/DB reales; las degradaciones y respuestas tardías se inyectan de forma explícita sólo en pruebas. Comandos y evidencia ejecutada: [tareas](../features/FEAT-003-dashboard/tasks.md). Las capturas se guardan bajo .cache/browser-auth, fuera del código distribuido.

No acredita auditoría WCAG certificada, lector de pantalla físico, carga/SLO, CI remoto ni producción. DASH-T05 conserva adaptadores futuros y DASH-T06–T08 la matriz ampliada, mediciones y operación. El perfil permanece draft y el roadmap HK sigue abierto.
