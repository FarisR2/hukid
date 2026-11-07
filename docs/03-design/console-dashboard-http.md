# API y BFF del dashboard

Estado: DASH-T03 implementada para laboratorio, 2026-11-06. [ADR-0021](../decisions/ADR-0021.md). Conecta las cuatro lecturas del [contrato](console-dashboard-contract.md) sobre la [lectura base autorizada](console-dashboard-reads.md). La interfaz continúa en DASH-T04.

## Rutas y perímetro

GET `/v1/operator/tenants/{tenantId}/overview` y `/activity` autentican exclusivamente Bearer operator con operator:read. Sus pares bajo `/console/api/tenants/{tenantId}` autentican una única cookie de sesión server-side, verifican el access token y ligan la identidad local. Un Bearer no sustituye la cookie ni una cookie sustituye el Bearer. No se exige step-up para estas lecturas.

BFF revalida el selector antes de comparar la selección: tenant inexistente/inaccesible devuelve 404; tenant accesible pero distinto del seleccionado, o sin selección, devuelve 403. Esto conserva el 404 cuando AUTH acaba de retirar una selección por suspensión. Después, el store dashboard vuelve a comprobar membership, revisión, roles y scopes dentro del snapshot de lectura. El BFF sólo toca la actividad idle de la sesión; no la renueva ni selecciona tenant desde la ruta.

Filtros, ventana UTC [from,to), máximo de 31 días, query de 4096 bytes y límite activity 1–100 proceden del parser compartido. Parámetros desconocidos, repetidos, vacíos o mal codificados devuelven 400 invalid_request; forma/rangos inválidos 422 invalid_input; cursor no válido 422 invalid_cursor. El contrato mantiene 401 invalid_credential, 403 forbidden, 404 resource_not_found y 503 dependency_unavailable. Sólo Management incluye el challenge Bearer ante 401. No se añade rate limiter propio; 429 conserva la representación contractual para infraestructura futura.

DASH-T06 conserva la precisión de hasta nueve decimales admitida por el contrato: al consultar recorded_at (microsegundos), el adaptador eleva ambos límites from/to al microsegundo siguiente si tienen fracción adicional. Sobre esa fuente discreta, `>= ceil(from)` y `< ceil(to)` preservan exactamente [from,to); truncarlos incluía eventos anteriores a from o excluía eventos anteriores a to. La ventana devuelta y el binding del cursor mantienen los valores originales. No cambia esquema, límite, permiso ni precisión de los registros existentes.

Éxitos y errores llevan Cache-Control: no-store, Referrer-Policy: no-referrer y correlación UUID generada por servidor, compartida con el middleware AUTH. Problem Details usa title/code fijos y no incluye diagnóstico SQL, tokens ni mensajes externos. Cada petición tiene timeout de cinco segundos. La observación de lectura registra operación, resultado, duración y correlación; no registra URL, filtros, IDs de actor/tenant, filas o credenciales. Los rechazos previos conservan la observación y auditoría AUTH existentes.

## Paginación autenticada

[Activity](../../src/platform/internal/dashboard/activity.go) cifra/autentica el cursor con AES-256-GCM, nonce aleatorio y AAD exclusivo de dashboard/activity/v1. Un digest SHA-256 liga operación, actor, tenant, revisión, roles, conjunto issuer ordenado y filtros normalizados, incluido limit. El digest acota el tamaño incluso con cien scopes; no sustituye al cifrado autenticado. El token guarda además versión, posición keyset, asOf y deadline.

Se decodifica sólo dentro del callback del snapshot, tras reautorizar. Manipulación, cambio de actor/tenant/revisión/grants/filtros/límite, clave distinta o vencimiento producen invalid_cursor. Si se perdió acceso/capacidad, prevalece el 404/403 de autorización. Una selección issuer sin ownership verificable conserva el 503 de DASH-T02; no se inventa atribución issuer.

La primera página fija asOf y deadline=asOf+900 segundos. Las siguientes mantienen ambos; no renuevan TTL. Requieren from/to explícitos tomados de la ventana devuelta, y ordenan por `(recorded_at,event_id)` descendente con posición estricta y lookahead limit+1. Un feed vacío exitoso devuelve items=[] y nextCursor=null; una fuente fallida devuelve 503. No garantiza snapshot entre páginas frente a commits tardíos ni sirve de exportación exhaustiva.

## Disponibilidad real

Overview devuelve seis secciones. activeMembers usa el conteo real de memberships activas cuando hay members:read; las capacidades de los otros cinco dominios siguen reservadas y sus secciones son notAuthorized para los roles actuales. Los fixtures de parcial/unavailable/stale siguen probando la semántica del contrato; no habilitan fuentes ficticias en runtime. Con una sola fuente conectada autorizada, su fallo devuelve 503 global: todavía no existe una segunda fuente válida para mantener un 200 parcial con error. Leer actividad no emite eventos de negocio; el middleware AUTH puede registrar rechazos.

## Configuración y retirada

Aplicar migraciones hasta 0011 antes del binario. Conservar toda la configuración AUTH. Dashboard es opcional: sin sus tres variables no registra rutas; una configuración parcial falla antes del listener.

| Variable | Valor requerido |
| --- | --- |
| HUKID_DASHBOARD_DATABASE_URL | Base PostgreSQL loopback hukid_test_* con login dedicado miembro de hukid_dashboard_runtime; OpenRuntimePool rechaza privilegios peligrosos o roles runtime combinados. |
| HUKID_DASHBOARD_POLICY | Ruta a src/platform/config/dashboard.test.json, perfil test estricto sin propiedades adicionales ni JSON posterior. |
| HUKID_DASHBOARD_CURSOR_KEY | Clave exclusiva de 32 bytes aleatorios en Base64 estándar, suministrada externamente; no reutilizar claves AUTH/USR. |

Sólo HUKID_ENV=test con AUTH completa. El API no crea logins, aplica migraciones ni carga .env. El harness provisiona credenciales y clave efímeras propias; no modifica una base existente. La credencial dashboard no puede leer sesiones, identidad global, ciphertext de invitaciones ni escribir datos.

Para retirar, quitar las tres variables y reiniciar el API; mantener migración, auditoría y datos. Rotar la clave invalida cursores existentes y permite reiniciar la paginación, sin afectar sesiones. No hay key ring multiversión ni despliegue productivo.

## Verificación y límites

Unitarias cubren binding, manipulación, vencimiento, reloj, cambios de roles/revisión y rotación de clave; pruebas HTTP/PostgreSQL usan binario API, IdP sintético y DB descartable para ambos transportes, paginación/bordes, permisos vivos, errores y proyección. Las respuestas HTTP reales se validan contra el JSON Schema estricto. El conjunto conserva las pruebas RLS y aislamiento de DASH-T02.

Comandos: npm run check, npm run test:postgres, npm run build, npm run smoke y git diff --check. Evidencia ejecutada en [tareas](../features/FEAT-003-dashboard/tasks.md). No hay UI nueva, Chromium nuevo, dominios futuros, carga/SLO, CI remoto ni aprobación productiva. DASH-T04 conserva interfaz; DASH-T05 fuentes futuras; DASH-T06–T08 matriz ampliada, navegador y operación.
