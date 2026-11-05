# Lectura de miembros e invitaciones — USR-T03

Estado: implementación de laboratorio de cuatro GET del [contrato de miembros](console-members-contract.md), según [ADR-0013](../decisions/ADR-0013.md). Las ocho mutaciones, entrega, aceptación y UI siguen pendientes. No hay migraciones nuevas ni cambios de grants AUTH.

## Rutas y autorización

Management expone `GET /v1/operator/tenants/{tenantId}/memberships` e `invitations`; BFF expone las mismas rutas bajo `/console/api`. No se añade GET individual: el contrato vigente sólo define listados y búsqueda por prefijo de ID. La lista contiene revisión; ETag corresponde a las futuras respuestas individuales de mutación.

Management verifica Bearer operator y resuelve identidad con los puertos AUTH. BFF lee una única cookie de sesión, verifica el access token custodiado y la igualdad de identidad, y exige que el tenant de ruta coincida con el contexto seleccionado. El navegador no puede cambiar de tenant alterando la URL; debe usar el selector AUTH. GET no exige Origin/CSRF, que siguen siendo obligatorios para comandos. Bearer no sustituye cookie en BFF y cookie no sustituye Bearer en Management.

La credencial `hukid_members_runtime` es independiente de las tres credenciales AUTH y se valida al abrir el pool. Cada lectura inicia una transacción `REPEATABLE READ READ ONLY`, fija actor/tenant con parámetros locales, consulta tenant y membership activos y calcula permisos desde `capabilities.json`. Sólo entonces consulta el directorio en el mismo snapshot. `tenant_admin` lee ambas listas; `security_admin` sólo miembros; `issuer_operator` y `support_readonly` reciben 403 sin leer el directorio. Actor sin pertenencia activa o tenant ajeno/inactivo recibe 404. Cada petición y continuación reautoriza; el cursor no concede permisos.

El snapshot mantiene coherencia dentro de una petición; un cambio confirmado durante ella puede ser visible sólo en la siguiente. RLS añade aislamiento tenant, sin sustituir la autorización. Rollback, cancelación y commit liberan las variables locales antes de reutilizar la conexión. No se toman locks de escritura ni se alteran roles/sesiones por leer el directorio.

## Filtros y paginación

| Lista | Filtros admitidos |
| --- | --- |
| memberships | state active/suspended/revoked, role de la matriz, query prefijo de membershipId u operatorIdentityId. |
| invitations | state pending/accepted/revoked/expired y deliveryState queued/sent/failed. |
| Ambas | limit 1–100, default 25 y cursor. La política puede reducir el máximo; un limit superior se rechaza. |

`query` admite 8–36 caracteres de un prefijo UUID canónico minúsculo, con guiones en sus posiciones. No busca email, nombre ni identidad global. Estado/rol/límite/prefijo inválidos devuelven 422 invalid_input; parámetros desconocidos, repetidos, vacíos o mal codificados devuelven 400 invalid_request. La query completa está acotada a 4096 bytes. SQL usa parámetros, no interpolación del filtro.

El orden es `(createdAt,id)` ascendente; se solicitan limit+1 filas y la continuación usa comparación estricta con la última fila entregada. Una página vacía devuelve items `[]` y nextCursor `null`. Empates de fecha se resuelven por UUID. No hay conteo total ni snapshot entre páginas: los cambios concurrentes pueden exigir recargar.

El cursor es JSON cifrado/autenticado con AES-256-GCM, nonce CSPRNG de 96 bits y AAD de propósito/versionado. Viaja en base64url canónico sin padding y no revela IDs ni filtros. Incluye versión, actor, tenant, operación, filtros normalizados, limit, última posición y deadline. Duración explícita de política test: quince minutos; se conserva el deadline original al continuar. Manipulación, expiración exacta, cambio de actor/tenant/operación/filtros/límite o clave devuelven 400 invalid_cursor antes del SQL de directorio. Cambiar la clave invalida continuaciones y permite empezar otra lista.

## Minimización y errores

Membership sólo contiene los diez campos del schema compartido, con roles/issuerIds ordenados y arrays vacíos como `[]`. Invitación sólo contiene los doce campos públicos del schema. `recipientHint` es la máscara fija `***`; se usa `redacted` si falta el destinatario cifrado o ya alcanzó su deadline de retención. Esta primera lectura no descifra ni recupera el correo, por lo que no distingue destinatarios por fragmentos visibles. El cliente puede usar invitationId para identificar la fila.

La consulta no selecciona email, hash/HMAC, ciphertext/nonce, envelope de entrega, subject, claims ni tokens. SQL consulta únicamente la presencia del ciphertext para decidir la máscara. Una invitación almacenada pending con `now >= expiresAt` se devuelve y filtra como expired, sin persistir un cambio ni alterar deliveryState. Esto no sustituye el worker/purga de tareas posteriores.

Todas las respuestas de estas lecturas incluyen no-store, no-referrer y correlación opaca. Los errores usan Problem Details sin reflejar entradas. 401 invalid_credential incluye challenge Bearer sólo en Management; 403 forbidden, 404 resource_not_found, 400 invalid_cursor/invalid_request y 422 invalid_input conservan los códigos del contrato USR. Dependencias fallidas devuelven 503 con Retry-After. El wrapper de auditoría existente conserva evidencia de denegaciones best effort sin copiar ruta/query/cursor ni payload. Lecturas exitosas no generan mutación/outbox.

Las memberships legacy con grants estructuralmente incompletos (por ejemplo issuer_operator sin issuerIds) devuelven 503 al entrar en la página. No se inventan alcances ni se ocultan filas para aparentar una lista completa; corregir esos datos requiere un procedimiento autorizado. La validación de forma al leer no acredita ownership issuer ni concede permisos.

## Configuración y reversión

Además de AUTH completo en `HUKID_ENV=test`, configurar conjuntamente:

| Variable | Valor externo |
| --- | --- |
| HUKID_MEMBERS_DATABASE_URL | Login independiente miembro de hukid_members_runtime; base hukid_test_* en IP loopback. |
| HUKID_MEMBERS_POLICY | Ruta a config/user-management.test.json de Platform, explícita. |
| HUKID_MEMBERS_CURSOR_KEY | Clave externa aleatoria de 32 bytes codificada en base64 estándar. |

Las tres variables ausentes mantienen sólo AUTH; alguna presente exige las tres válidas, entorno test y AUTH completo. Una credencial con roles mezclados, privilegios elevados o permisos de propietario impide arrancar. La clave de cursor tiene propósito propio; no reutilizar claves de sesión/entrega. No incluir DSN/clave en ejemplos, logs ni commits. El provisioning existente permite crear el rol/login de laboratorio; API nunca provisiona ni migra al arrancar.

Para retirar el incremento, apagar el proceso y quitar las tres variables; tras reiniciar, las rutas no se registran y AUTH conserva su configuración. El esquema 0007 y los datos permanecen. La rotación de clave descarta cursores, sin reactivar invitaciones ni cambiar memberships.

## Verificación y límites

Unitarias Go prueban filtros, matriz y binding/deadline/alteración/rotación de cursores; PostgreSQL real prueba orden con empate, aislamiento entre tenants con pool reutilizado, filtros, permisos vivos, cancelación, estados efectivos y retención de la máscara. Una prueba retira SELECT de invitaciones para demostrar que la denegación ocurre antes de consultar esa tabla. La integración HTTP arranca API/IdP/DB propios con configuración USR y prueba ambas superficies, headers, campos mínimos, filtros/errores, roles y suspensión. La suite AUTH se mantiene.

Comandos: `npm run check`, `npm run test:postgres`, `npm run build`, `npm run smoke` y `git diff --check`. La evidencia ejecutada se registra en [tareas FEAT-002](../features/FEAT-002-user-management/tasks.md). No hay interfaz nueva que verificar visualmente. Sin prueba de carga/índices a escala, restore, IdP/MFA productivos, rate limiting propio del directorio ni despliegue. El rol members conserva permisos de escritura preparados por 0007, aunque este incremento sólo registra GET y usa transacciones de lectura. USR-T04 continúa con invitación y entrega cifrada/idempotente; USR-T08 conserva la UI.
