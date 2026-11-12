# Desarrollo local de HukID

Estado: AUTH-T01–T05 entregan bootstrap, contratos, PostgreSQL, [login/callback OIDC](../03-design/console-oidc-login.md) y [middleware operator y /me](../03-design/console-operator-context.md) de laboratorio. AUTH-T06/T07 añaden [ciclo de sesión](../03-design/console-session-lifecycle.md) y [MFA/step-up/contexto](../03-design/console-reauthentication.md). AUTH-T08 conecta [interfaz y navegador](../03-design/console-auth-interface.md) al BFF. AUTH-T09 integra [auditoría y exclusión de secretos](../03-design/console-auth-audit.md).

Existe [contrato y laboratorio OIDC](../03-design/console-auth-contract.md), con política test, matriz y reglas Go. El IdP sólo se inicia desde tests y simula MFA; no arranca con Platform. AUTH-T04 conecta HTTP con la [persistencia de consola](../03-design/console-persistence.md) cuando se proporciona configuración test completa.

## Estructura acordada

El owner confirmó esta distribución el 2026-11-03:

| Ruta | Contenido actual |
| --- | --- |
| `src/platform/cmd/api` | Proceso HTTP local y cierre ordenado. |
| `src/platform/cmd/worker` | Lote explícito de invitaciones con proveedor sintético y purga USR-T04. |
| `src/platform/internal/bootstrap` | Configuración loopback, liveness y pruebas del perímetro inicial. |
| `src/platform/internal/adapters/postgres` | Migraciones, roles/RLS, pools y contexto transaccional, descubrimiento mínimo y bootstrap test-only. |
| `src/platform/cmd/testdb` | CLI restringido para migrar/provisionar una base de pruebas explícita. |
| `src/console` | Workspace React/TypeScript con Vite, autenticación visual y proxy BFF local AUTH-T08. |
| `scripts/platform.mjs` | Comandos Go portables, control de versión y caché local. |

No crear módulos vacíos de autenticación, emisión, wallet o Events. Se incorporan al implementar cada tarea con su contrato validado. El nombre de módulo `hukid.local/platform` es local al repositorio; no declara un dominio de despliegue ni una ruta pública de distribución.

## Versiones y dependencias

| Herramienta | Versión fijada |
| --- | --- |
| Node.js | 24.22.1 como baseline (`.node-version`); engines admite versiones posteriores de la rama 24. |
| npm | 11.19.1 como baseline (`packageManager`); engines admite versiones posteriores de la rama 11. |
| Go | 1.27.3 exacta; el runner usa `GOTOOLCHAIN=local`, sin descarga implícita. |
| React / React DOM | 19.3.1 |
| TypeScript | 7.0.2 |
| Vite | 8.3.5 |
| Tipos React / React DOM | 19.3.0 |
| pgx | 5.12.0; módulos y checksums en `src/platform/go.mod` / `go.sum`. |
| go-oidc / oauth2 / go-jose | 3.21.0 / 0.36.0 / 4.1.4; cliente OIDC y verificación de tokens Go, ADR-0005. |
| PostgreSQL de laboratorio | 18.6; binarios portables EDB 18.6-5 usados en Windows x64. |

Las versiones npm directas son exactas y `package-lock.json` fija las transitivas. Se consultaron el registro npm y fuentes oficiales de [Go](https://go.dev/dl/), [React](https://react.dev/versions) y [Vite](https://vite.dev/guide/). AUTH-T03 añade pgx y un runner de migraciones propio pequeño, sin ORM; AUTH-T04 las librerías OIDC fijadas. Go descarga módulos verificados por `go.sum`; el runner guarda caches en `.cache`. `.gitattributes` conserva LF en Go para que gofmt no falle tras checkout Windows con autocrlf.

Instalar Node/npm y Go de estas versiones antes de ejecutar los comandos. Go puede estar en PATH o indicado mediante `HUKID_GO` (ruta del ejecutable). En Windows el runner también detecta `.cache/toolchains/go1.27.3/go/bin/go.exe`. Esa instalación local no forma parte del checkout y no cambia PATH global.

Para reproducir la instalación portable Windows x64 utilizada aquí, descargar `go1.27.3.windows-amd64.zip` desde Go y verificar SHA-256 `f26081f438319757f8a1b46d7d0b2c5ec7583d4038e485e0aa725cfde7885fff` antes de extraerlo en `.cache/toolchains/go1.27.3/`. En otros sistemas usar el archivo y checksum oficial de su plataforma.

## Checkout limpio y checks

Desde la raíz, después de instalar las herramientas:

```sh
npm ci --ignore-scripts
npm run check
npm run build
npm run smoke
```

`check` verifica formato Go sin modificar archivos, ejecuta `go vet`, pruebas Go sin caché de resultados, typecheck TypeScript, `test:auth` y validación documental (enlaces/anclas locales inline, bloques de código y presencia de los nueve archivos de features). Los enlaces de referencia y la semántica de contratos/tareas requieren revisión adicional. Para corregir formato, ejecutar `go fmt ./...` desde `src/platform`. `build` genera `.cache/build/hukid-api` (o `.exe`) y `src/console/dist/`; el binario incluye login/callback habilitables sólo con configuración test completa.

Los scripts usan rutas relativas al propio archivo y funcionan desde un checkout en otra ubicación. No requieren Docker. Hay pruebas de contrato, IdP y login HTTP con DB; no son pruebas de navegador ni factores reales.

`npm run test:postgres` es separado y obligatorio para cambios de persistencia. AUTH-T04 amplía el harness con el binario API real, fixture IdP, credenciales/claves efímeras y pruebas de callback/cookies/sesión inicial. `npm run check` no simula ni salta una DB ausente. Para verificar el incremento completo ejecutar también `test:postgres`, además de build/smoke.

`smoke` requiere build previo: rechaza configuración productiva/parcial, arranca el binario Go sin autenticación en loopback:18080 y Vite preview en loopback:14173, comprueba liveness 204/no-store, login deshabilitado 404 y HTML/JS, y termina sus procesos. Requiere esos puertos libres. `test:postgres` verifica el login habilitado con el binario real. Ambas son pruebas HTTP, sin evaluación visual ni navegador.

## PostgreSQL descartable y comandos AUTH-T03

El harness fue validado en Windows x64 con PostgreSQL 18.6. Obtener el [archivo portable EDB](https://get.enterprisedb.com/postgresql/postgresql-18.6-5-windows-x64-binaries.zip) desde la [página de binarios](https://www.enterprisedb.com/download-postgresql-binaries), verificar SHA-256 `e2246ba91d22345bc3d017586c09ede52d9df180b1eeb480f050445f1cad84e2` antes de extraerlo en `.cache/toolchains/postgresql-18.6-5/`; debe quedar `pgsql/bin/postgres.exe`. El [checksum confirmado por EDB](https://github.com/EnterpriseDB/edb-installers/issues/746) identifica el archivo usado. No se instala un servicio ni se modifica PATH global.

Como alternativa, indicar `HUKID_PG_BIN` con el directorio de binarios de una instalación PostgreSQL 18.6 confiable. El script verifica la versión; si usa el archivo portable en la ubicación predeterminada, también verifica su checksum. Otros sistemas operativos no se han validado en esta ejecución.

```sh
npm run test:postgres
```

El comando crea su propio clúster en `.cache/postgres-tests/run-*`, usa puerto libre/loopback y password administrativo aleatorio en memoria. Borra el archivo temporal de inicialización, ejecuta las pruebas Go con tag integration y finalmente elimina sólo bases/logins creados por las pruebas y detiene su servidor. Conserva el directorio ignorado y `postgres.log` para diagnóstico. No lee `HUKID_DATABASE_URL` de una aplicación existente, ni necesita Docker. La inicialización puede tardar en el primer arranque.

El arranque usa `pg_ctl -w` con espera de hasta 30 segundos; en Windows permite reducir los privilegios del proceso servidor cuando la terminal es administrativa. El workflow concede al SID del runner permisos heredables sólo sobre `.cache/postgres-tests`, para que el proceso restringido pueda escribir sus clústeres. La salida del controlador va a `startup.log`, evitando pipes heredados que impedirían terminar el comando. Ante fallo de arranque se muestra un diagnóstico acotado; no se vuelcan logs tras ejecutar pruebas de autenticación.

Los comandos manuales siguientes requieren una base test ya creada por el operador y credenciales externas al repo; no crean ni seleccionan una automáticamente:

```sh
npm run db:migrate:test
npm run db:bootstrap:test
```

Exigen `HUKID_ENV=test`, `HUKID_TEST_DATABASE=1` y `HUKID_DATABASE_URL` explícita: IP loopback, nombre `hukid_test_*`, un solo destino sin fallbacks y `sslmode=disable` sólo para este laboratorio local. El bootstrap exige al administrador del clúster descartable; un runtime login o flags productivos se rechazan. No se muestran DSN ni passwords en salida. La API no ejecuta estos comandos ni expone provisioning HTTP. Detalle de roles, límites y recuperación forward-only en persistencia de consola.

## Arranque de API y consola

USR-T01 añade el [contrato de miembros y política test](../03-design/console-members-contract.md). Sus pruebas se incluyen en `npm run test:auth` y `npm run check:platform`, ambos dentro de `npm run check`. No agrega variables runtime, rutas habilitadas ni migraciones. No se habilitan escrituras por colocar el nuevo archivo de política junto a auth.test.json.

USR-T02 añade [persistencia de miembros](../03-design/console-members-persistence.md) y migración 0007, aplicada por el mismo CLI/harness. El rol hukid_members_runtime requiere credencial backend independiente. El runtime de AUTH conserva sus tres credenciales y permisos. USR-T03 conecta [lecturas autorizadas](../03-design/console-members-directory.md) mediante HUKID_MEMBERS_DATABASE_URL, HUKID_MEMBERS_POLICY y HUKID_MEMBERS_CURSOR_KEY: las tres ausentes mantienen sólo AUTH; configuración parcial/ajena/productiva se rechaza. Usar login separado hukid_members_runtime y clave externa propia de 32 bytes base64. USR-T04 añade las escrituras y el worker descritos abajo; USR-T05 conecta [aceptación/reingreso con evidencia OIDC](../03-design/console-invitation-acceptance.md); USR-T06 conecta [cambios de membresías con ETag](../03-design/console-members-lifecycle.md); USR-T07 conecta [revalidación/reconciliación de contexto](../03-design/console-authorization-revalidation.md); USR-T08 conecta [UI administrativa y aceptación](../03-design/console-members-interface.md); gate USR-T09 pendiente.

En dos terminales desde la raíz:

```sh
npm run dev:platform
```

```sh
npm run dev:console
```

- Platform: `http://127.0.0.1:8080/healthz`, GET/HEAD devuelve 204 sin cuerpo. Es liveness del proceso, no readiness de dependencias.
- Vite: `http://127.0.0.1:5173/`, interfaz de autenticación AUTH-T08. Sin configuración test completa del backend, muestra indisponibilidad; no hay bypass de login.
- Cerrar Platform con Ctrl+C inicia shutdown ordenado, con límite de cinco segundos.
- `HUKID_LISTEN_ADDR` permite otro IP loopback/puerto (por ejemplo `127.0.0.1:8081` o `[::1]:8081`). Un host abierto, nombre DNS o puerto inválido impide arrancar.
- Vite usa loopback y puerto estricto. AUTH-T08 configura proxy same-origin para /console/ sin reescribir Origin; no habilita CORS. Sus servidores dev/preview son locales.

## Worker de invitaciones USR-T04

Aplicar migraciones con el CLI test existente; 0008 añade únicamente los recibos sin payload del proveedor sintético. La API requiere la configuración AUTH completa y las tres variables members de las lecturas. Para habilitar creación/revocación, añadir las tres variables siguientes juntas; si están ausentes se conservan sólo las lecturas:

| Variable | Valor requerido |
| --- | --- |
| HUKID_INVITATION_KEY | Clave AES de 32 bytes base64, distinta de AUTH, cursor y HMAC. |
| HUKID_INVITATION_HMAC_KEY | Clave HMAC de 32 bytes base64, estable para deduplicar destinatarios. |
| HUKID_INVITATION_KEY_VERSION | Identificador externo no vacío de hasta 128 bytes. |

No guardar claves/DSN en el repositorio ni sustituirlas en cada arranque: las invitaciones pendientes requieren las claves originales. No hay rotación multiversión implementada. Política: src/platform/config/user-management.test.json; ambiente exclusivamente HUKID_ENV=test, PostgreSQL loopback y base hukid_test_* con credencial members separada.

Con esas variables ya proporcionadas por el operador, ejecutar desde la raíz:

```sh
node scripts/platform.mjs worker:test 20000000-0000-4000-8000-000000000001 10000000-0000-4000-8000-000000000001
```

Los UUID del ejemplo son actor/tenant A del bootstrap sintético; usar los IDs confiables de la base explícita. El worker requiere HUKID_MEMBERS_DATABASE_URL, HUKID_MEMBERS_POLICY y los tres secretos de invitación. No usa sesión de navegador ni selecciona una DB automáticamente. Procesa un lote de hasta cien entregas y purga el tenant indicado, con límite de proceso de treinta segundos. Repetir el comando para más lotes o reintentos. No hay scheduler ni SLA de purga; incluso sin nuevas entregas hay que ejecutar el lote para aplicar retención. Un tenant inactivo no entrega mensajes, pero permite mantenimiento.

El proveedor falso sólo registra un recibo persistente y no envía email. Revisar las invitaciones mediante los GET autorizados existentes: queued/sent/failed son independientes de pending/revoked/expired. Tras un error de proveedor se conserva el mismo secreto vigente para reintentar; una vez agotado requiere POST nuevo con otra key. El CLI sólo muestra un error fijo y sale con código 1 ante un fallo del lote, sin DSN, email, token ni errores internos. Los errores de entrega quedan reflejados como failed; no se interpretan como aceptación fallida del usuario.

build genera también .cache/build/hukid-worker(.exe). Para retirar el incremento, detener el worker y quitar las tres variables de invitación del API; mantener la migración y los recibos. [Referencia completa, límites y pruebas](../03-design/console-invitation-delivery.md).

## Configuración e IdP

Sin configuración sólo se expone liveness. Con configuración test completa se habilitan las nueve operaciones del OpenAPI de consola/operator. No contiene credenciales, no carga `.env` automáticamente y no tiene modo productivo. Los cuatro comandos refresh/logout/step-up/tenant-context están implementados para laboratorio desde AUTH-T06/T07. El endpoint operativo `/healthz` no sustituye el OpenAPI de AUTH-T02.

AUTH-T02 configura un fixture `oidc-provider` en `tests/fixtures`. La configuración base usa `127.0.0.1:19090`; desde la corrección de frontend del 2026-11-08, `npm run test:auth` sustituye únicamente en su copia de política el issuer por un puerto loopback libre propio, para no interferir con un laboratorio manual. El runner establece explícitamente `NODE_ENV=test` y `HUKID_TEST_IDP=1`; el fixture rechaza flags productivos, genera claves y secreto de cliente en memoria y termina al finalizar. El cliente confidencial usa `client_secret_basic` con secreto efímero; esto no selecciona autenticación de cliente productiva. El fixture usa adapter en memoria y emite una advertencia esperada. Las interacciones automáticas del harness no autentican a personas ni comprueban OTP reales.

Las dependencias Node de laboratorio son únicamente de desarrollo y están fijadas en package/lock: `oidc-provider` 9.13.3, `jose` 6.2.15, `@apidevtools/swagger-parser` 13.1.0, `ajv` 8.20.0 y `ajv-formats` 3.0.1. No forman parte del binario Go ni del bundle React. Las librerías OIDC Go seleccionadas en AUTH-T04 sí forman parte del backend.

La validación previa al listener se puede ejecutar desde la raíz en PowerShell:

```powershell
$env:HUKID_ENV = 'test'
$env:HUKID_AUTH_POLICY = (Resolve-Path src/platform/config/auth.test.json).Path
npm run dev:platform
```

Este ejemplo está incompleto para el runtime actual y falla antes de escuchar: desde AUTH-T04 se exige también configuración de credenciales/clave, y desde AUTH-T05 tres DSN separados. La configuración completa se describe en [login](../03-design/console-oidc-login.md#http-y-configuración) y [contexto operator](../03-design/console-operator-context.md#sesión-y-dependencias). Sin variables de autenticación se conserva liveness-only. Operación y retirada/reactivación en el [runbook AUTH-T10](console-auth-runbook.md). Para volver a ese modo, retirar todas las variables HUKID de autenticación de la terminal. HTTP/Secure=false sólo se permite en este laboratorio loopback. Los TTL/MFA productivos siguen sin aprobarse.

Decisiones y alcance: [ADR-0002](../decisions/ADR-0002.md), [FEAT-001](../features/FEAT-001-authentication/plan.md), [pendientes](../05-delivery/documentation-gaps.md).

## Evidencia del bootstrap — 2026-11-03

Las secciones de evidencia siguientes son snapshots de cada incremento. Las frases «siguiente tarea», las cantidades de pruebas y las funciones pendientes corresponden a la fecha de ese incremento; para continuar usar las [tareas vigentes de miembros](../features/FEAT-002-user-management/tasks.md) y el [plan global](../05-delivery/implementation-plan.md). AUTH-T01–T10 y la foundation USR-T01–T02 ya están entregadas para laboratorio; USR-T03 es la siguiente tarea.

Entorno: Windows x64, Node 24.22.1, npm 11.19.1, Go 1.27.3 portable con checksum oficial verificado. Se validó también una copia del árbol fuente en otra ubicación sin `node_modules`, `dist` ni cachés previas; Go se indicó mediante `HUKID_GO`.

| Comprobación | Resultado |
| --- | --- |
| `npm ci --ignore-scripts` | Instalación desde lockfile aprobada; auditoría npm sin vulnerabilidades reportadas en esa ejecución. |
| `npm run check` | Formato, vet, pruebas Go, typecheck y validación documental aprobados. |
| `npm run build` | Binario Go y distribución de consola generados. |
| `npm run smoke` | Liveness 204/no-store, login ausente (404), HTML y JS compilado 200; procesos de prueba terminados. |

La copia limpia valida el bootstrap de los archivos actuales, todavía sin commit; no es una ejecución CI remota. No se hicieron pruebas visuales, de navegador, OIDC/MFA, DB/RLS, carga ni conformidad. El entry point de React vacío sólo acredita compilación, sin flujo operativo. A0 y FEAT-001 siguen abiertos hasta sus siguientes tareas.

## Evidencia AUTH-T02 — 2026-11-03

En la rama `feature/hukid-console-bootstrap` se ejecutó `npm ci --ignore-scripts` con el lockfile actualizado y sin vulnerabilidades reportadas por npm en esa ejecución. `npm run check` aprobó formato/vet/pruebas Go, typecheck, nueve pruebas Node de contrato/IdP y validación documental. `npm run build` generó ambos artefactos. `npm run smoke` comprobó rechazo previo al listener de configuración productiva/incompleta, liveness con política test y disponibilidad del bundle. El smoke inicial tuvo un fallo puntual de espera del proceso; la ejecución final pasó con un timeout de diez segundos y diagnóstico de salida explícito.

Ese laboratorio resolvió A0 sólo para desarrollo/pruebas: no acreditaba MFA real, handlers, DB/RLS, cookies/CSRF de navegador ni el flujo de login. Al terminar AUTH-T02 los cambios estaban sin commit; posteriormente se guardaron en `1638953` antes de iniciar AUTH-T03.

## Evidencia AUTH-T03 — 2026-11-03

Se verificó el SHA-256 publicado de PostgreSQL portable 18.6-5 y su versión nativa 18.6. `npm run test:postgres` aprobó ocho pruebas de integración en clúster descartable, incluidas migración desde vacío/previa con datos, RLS/roles/FK, pool sin contexto residual, bootstrap atómico/idempotente y el CLI real. La prueba de una misma conexión física compara su backend PID al alternar contextos; cancelación puede descartar una conexión y verifica igualmente que el pool no conserve contexto. Las bases/logins de prueba se eliminaron y el servidor propio se detuvo.

`npm run check`, `npm run build` y `npm run smoke` aprobaron con el nuevo adaptador; también se ejecutó `go mod verify` sobre el module cache y todos los módulos se verificaron. Los enlaces/anclas, estructura y bloques Markdown se comprobaron con el validador documental, y `git diff --check` aprobó. La API sigue sin rutas de autenticación, por lo que el smoke espera 404 en login.

AUTH-T03 se entrega en `feature/hukid-console-bootstrap`, con implementación y documentación en commits separados consultables en el historial Git. No hay publicación ni migración de una base existente. El siguiente trabajo es AUTH-T04: librería/puerto OIDC y callback de un uso, con identidad local y autorización integradas en tareas posteriores. Cifrado operativo, familias de sesión, MFA real, restore/carga y navegador continúan pendientes según los gates de cada tarea.

## Evidencia AUTH-T04 — 2026-11-04

`npm run check`, `npm run test:postgres`, `npm run build` y `npm run smoke` aprobaron en el laboratorio Windows. Go verificó los módulos fijados mediante `go mod verify`. Las diez pruebas PostgreSQL incluyen las ocho de foundation y dos nuevas para login real y upgrade/privilegios/rollback, con subcasos negativos. No se usaron servicios o bases existentes; el harness detuvo sus procesos y eliminó sus bases/logins.

Para reproducir la verificación del login no hace falta aprovisionar un IdP manual ni copiar secretos: instalar dependencias/toolchains indicados y ejecutar `npm run test:postgres`. Arranca un binario Go compilado desde este checkout, un IdP sintético y PostgreSQL propios en puertos loopback libres. Las pruebas HTTP no ejecutan React ni un navegador.

Para una ejecución manual de laboratorio se necesitan IdP test registrado, DB test migrada y login SQL runtime provisionados por separado. Las variables, cookies y limitaciones se mantienen en [login AUTH-T04](../03-design/console-oidc-login.md), con decisión en [ADR-0005](../decisions/ADR-0005.md). `npm run dev:platform` sin variables conserva liveness solamente. Una política aislada sin credenciales/clave ya no habilita el proceso: falla antes de escuchar.

El incremento posterior AUTH-T05 se describe abajo. AUTH-T06 conserva actividad/rotación de sesiones, refresh y logout. No se han validado factores reales, proveedor productivo, purga/rotación de claves, navegador, carga o restore; la consola y el gate A4 siguen pendientes.

## Evidencia AUTH-T05 — 2026-11-04

Se verifican middleware Bearer, contexto tenant y composición /console/api/me mediante checks Go y pruebas PostgreSQL/HTTP con binario e IdP reales de laboratorio. La suite DB contiene once pruebas superiores con subcasos: añade roles, dos tenants, revalidación de suspensión/revocación y conexión reutilizada sin contexto residual. Los tests HTTP recorren acceso pendiente, selección provisionada sólo por test, rechazo de tenant ajeno, suspensión con credencial vigente y expiración. Tokens y cookie no aparecen en respuestas de identidad.

El runtime exige HUKID_CONTEXT_DATABASE_URL y HUKID_TENANT_DATABASE_URL adicionales a la configuración AUTH-T04, para la misma base de laboratorio con credenciales distintas y roles hukid_context_runtime/hukid_tenant_runtime. No hay migraciones nuevas ni provisioning HTTP; el harness genera los tres logins. Los pools rechazan roles runtime combinados. Detalle único de comportamiento/límites: [AUTH-T05](../03-design/console-operator-context.md).

`npm run check`, `npm run test:postgres`, `npm run build` y `npm run smoke` aprobaron en Windows con los toolchains locales fijados. El validador documental comprobó 74 Markdown y sus enlaces/anclas. Los procesos/clúster de las pruebas se detuvieron al finalizar. El sandbox bloqueó inicialmente temporales/caché; las ejecuciones finales Go/PostgreSQL/build usaron permisos externos al sandbox, sin cambiar controles del repositorio.

El siguiente trabajo es AUTH-T06. /me todavía no extiende idle ni renueva access tokens. No se ejecutó navegador ni MFA real y no se habilitaron comandos de sesión o despliegue productivo.

## Evidencia AUTH-T06 — 2026-11-04

La rama `feature/auth-t06-session-lifecycle-v2` parte de develop integrado hasta AUTH-T05. `npm run test:postgres` añade pruebas de ciclo de sesión y flujo HTTP de refresh/logout con IdP/DB descartables. La migración 0004 añade lease e índice de generación activa; el API ejecuta purga acotada. [Referencia de sesión](../03-design/console-session-lifecycle.md) y [ADR-0007](../decisions/ADR-0007.md) contienen los límites y la evidencia por escenario. No se usaron bases existentes ni factores reales.

Validación final AUTH-T06: `npm run check`, `npm run test:postgres`, `npm run build`, `npm run smoke` y `git diff --check` aprobados en Windows. La suite PostgreSQL contiene trece pruebas Go superiores con subcasos; incluye upgrade 0003→0004 conservando la sesión y rechazo de dos generaciones activas. No hubo publicación ni cambios sobre bases existentes.

## Evidencia AUTH-T07 — 2026-11-05

`npm run check`, `npm run test:postgres`, `npm run build` y `npm run smoke` aprobados en Windows. Las trece pruebas superiores PostgreSQL amplían subcasos de upgrade 0004→0005, binding de generación, concurrencia/logout/refresh/rollback y comandos HTTP step-up/contexto con API e IdP de biblioteca. El upgrade conserva sesión y transacción login pendientes. La suite HTTP comprueba selección A→B→B→A, rotación CSRF/cookie y suspensión viva. Unitarias verifican evidencia MFA reciente, identidad y límites con reloj controlado. Ver [detalle AUTH-T07](../03-design/console-reauthentication.md).

No cambia la configuración runtime; aplicar migraciones mediante el CLI restringido de laboratorio antes del API. Las nueve operaciones OpenAPI quedan habilitadas únicamente con la configuración test completa existente. No hay pantallas ni factores reales: AUTH-T08 añade UI/navegador y AUTH-T09/T10 auditoría/operación. Las futuras mutaciones privilegiadas de FEAT-002 deberán aplicar el gate de freshness y sus capacidades locales. No se publicaron cambios ni se migraron bases existentes.

## Evidencia AUTH-T08 — 2026-11-05

Consola de autenticación en español con UI conectada y pruebas Chromium headless: acceso pendiente/selector/contexto, refresh/step-up/logout, suspensión/expiración, fallos recuperables, teclado, historial, pestañas, almacenamiento y capturas responsive/oscuro. Los procesos API/IdP/Vite y PostgreSQL de `npm run test:browser` son propios y descartables. Requiere build previo y Python con [requirements](../../tests/browser/requirements.txt) y Chromium; instrucciones, limitaciones y capturas en [referencia AUTH-T08](../03-design/console-auth-interface.md).

El proxy usa HUKID_CONSOLE_API_TARGET (default http://127.0.0.1:8080). En el API configurar HUKID_CONSOLE_PROXY_ORIGIN igual a consoleOrigin de la política (por ejemplo http://127.0.0.1:5173), y registrar redirectUri bajo ese origen. La igualdad directa origen/listener sigue siendo el default sin proxy explícito. No se toman forwarded headers ni se habilita producción.

Checks generales, PostgreSQL, builds, smoke y navegador forman la evidencia del incremento. MFA real, auditoría/redacción integrada, carga/restore y gate operativo siguen pendientes.

## Evidencia AUTH-T09 — 2026-11-05

Migración 0006 y auditoría/outbox de autenticación integradas y probadas. npm run check, npm run test:postgres, npm run build, npm run smoke y npm run test:browser aprobados en Windows con herramientas fijadas. La suite DB incorpora catorce pruebas superiores con subcasos; agrega historia/permisos, rollback por fallo de auditoría y logout concurrente idempotente. El binario HTTP y Chromium verifican presencia de eventos y ausencia de secretos en sus canales observados. No cambia la configuración runtime ni se añade una dependencia; aplicar migraciones con el CLI restringido antes de arrancar el binario nuevo. No se migró una base existente. [Referencia](../03-design/console-auth-audit.md) mantiene garantías y límites. AUTH-T10 es el siguiente incremento.

## Gate y operación AUTH-T10

Desde un checkout con los requisitos previos instalados, npm run test:auth:gate encadena check/build/PostgreSQL/smoke/Chromium, se detiene ante fallos y genera .cache/auth-gate/latest.json con alcance laboratorio, HEAD, dirty, digest y resultados sin logs/entorno. Rechaza cambios de fuente durante la ejecución. El [workflow Windows](../../.github/workflows/authentication.yml) ejecuta el mismo comando; una ejecución local no acredita CI remoto.

npm run db:invalidate-auth:test se usa sólo para retirada offline del laboratorio, con administrador, HUKID_ENV=test, HUKID_TEST_DATABASE=1 y HUKID_DATABASE_URL externos. Conserva esquema y evidencia, revoca sesiones y cancela callbacks pendientes. Preparación, orden, efectos y diagnóstico en el [runbook](console-auth-runbook.md); criterios/evidencia en el [gate A4](../05-delivery/authentication-gate.md).

Evidencia 2026-11-05: gate completo aprobado en Windows; ensayo API/IdP/DB de retirada/reactivación, rollback ante outbox fallida, roles/flags/cancelación e idempotencia. El instalador portable verificó archivo existente sin descarga/extracción nueva; workflow YAML validado localmente, sin ejecución GitHub Actions. Sin nueva migración, UI, restore, MFA real ni producción. Siguiente: USR-T01.

## Aceptación USR-T05

Aplicar migración 0009 antes del binario nuevo. Mantener configuración AUTH/members y secretos USR-T04; no hay variables nuevas. La política test AUTH solicita email. Sesiones previas o renovadas por refresh necesitan login/step-up Code/PKCE nuevo para obtener evidencia de destinatario. Management también exige evidencia cifrada server-side ligada al access token. El canje no selecciona tenant ni rota cookie. Detalle, errores y rollback en [referencia USR-T05](../03-design/console-invitation-acceptance.md); decisión en [ADR-0015](../decisions/ADR-0015.md). Sin UI nueva ni proveedor real.

## Cambios de membresías USR-T06

No hay migración ni variables nuevas: usar el esquema hasta 0009 y la configuración AUTH/members de USR-T04/T05. Los dos PATCH quedan conectados al habilitar esa configuración completa. Requieren MFA reciente, capability local, Idempotency-Key e If-Match; BFF requiere además Origin/CSRF y tenant seleccionado. Detalle y límites en [USR-T06](../03-design/console-members-lifecycle.md) y [ADR-0016](../decisions/ADR-0016.md). Los grants issuer no vacíos devuelven 503 sin ownership confiable. La UI y la invalidación completa de contexto siguen en USR-T08 y USR-T07.

## Revalidación de contexto USR-T07

Aplicar la secuencia de migraciones hasta 0010 mediante el CLI/harness existente antes de arrancar el binario nuevo. No hay variables ni credenciales nuevas. La migración añade sólo SELECT/RLS de scopes propios a hukid_tenant_runtime; session/members mantienen su separación. Tras retirar acceso, /console/api/me devuelve selección/contexto null con la misma sesión y los tenants restantes. Detalle en [USR-T07](../03-design/console-authorization-revalidation.md) y [ADR-0017](../decisions/ADR-0017.md). Validar con check, test:postgres, build, smoke y test:browser.

## Gate y operación USR-T09

`npm run test:members:gate` ejecuta check/build/PostgreSQL/smoke/Chromium con regresión AUTH y USR completas. Reutiliza el runner AUTH y genera `.cache/members-gate/latest.json`, con digest estable y metadatos sin logs ni entorno. El workflow Windows ejecuta este comando; su éxito remoto se acredita por separado. Mantiene `npm run test:auth:gate` y su informe propio. Alcance/matriz en el [gate U4](../05-delivery/members-gate.md); preparación, entrega/purga por tenant, diagnóstico y retirada en el [runbook de miembros](console-members-runbook.md). No cambia DDL, API ni permisos. Siguiente DASH-T01; producción NO-GO.

## API/BFF dashboard DASH-T03

Aplicar migraciones hasta 0011 y suministrar la configuración AUTH completa. Habilitar opcionalmente HUKID_DASHBOARD_DATABASE_URL (login exclusivo hukid_dashboard_runtime), HUKID_DASHBOARD_POLICY (src/platform/config/dashboard.test.json) y HUKID_DASHBOARD_CURSOR_KEY (32 bytes aleatorios Base64 exclusivos). Todo permanece restringido a test/loopback/hukid_test_*. El API no provisiona logins ni migra automáticamente. Sin las tres variables no registra rutas; configuración parcial falla antes del listener. [Referencia](../03-design/console-dashboard-http.md) mantiene contrato, preparación, cursor, retirada y límites. La interfaz queda en DASH-T04.

## Gate dashboard DASH-T08

npm run test:dashboard:gate ejecuta check, build, PostgreSQL, smoke y Chromium incluyendo regresión AUTH/USR, matriz DASH base y medición de consultas. Guarda metadata y digest de fuentes en .cache/dashboard-gate/latest.json. [Matriz D4 y límites](../05-delivery/dashboard-gate.md); [fuentes, rollout y retirada](console-dashboard-runbook.md). No deja un entorno manual persistente ni acredita CI remoto o producción.

## Entorno local persistente (perfil `local`, ADR-0025)

Alternativa al laboratorio descartable: PostgreSQL 18.6 persistente (puerto 54329, base `hukid_local`), Keycloak 26.8.2 como IdP y un operador real. Estado y secretos en `.cache/local/` (ignorado por git). Requiere JDK y los toolchains de `.cache/toolchains`.

```
node scripts/local-env.mjs init           # crear o actualizar clúster, migraciones, cinco roles y claves
node scripts/local-env.mjs keycloak-init  # crear o reconciliar realm, cliente, flujo MFA y mappers
node scripts/local-env.mjs start          # PostgreSQL + Keycloak + API + consola; Ctrl+C detiene los procesos
node scripts/local-env.mjs bootstrap      # con Keycloak activo: vincula operador.local a un tenant (idempotente)
```

Orden recomendado tras `init` y `keycloak-init`: `start`, `bootstrap` en otra terminal y abrir `http://127.0.0.1:5173/`. En el primer login Keycloak pedirá configurar TOTP; tras el enrolamiento puede ser necesario volver a HukID e iniciar sesión de nuevo con contraseña y OTP para completar la evidencia requerida. Los puertos 8080, 5173 y 8081 deben estar libres (detener el demo sintético antes).

Acceso en la raíz: la consola no tiene pantalla de acceso (ADR-0025). Abrir `/` sin sesión redirige directamente al formulario de Keycloak, que siempre pide credenciales (`prompt=login consent`); cerrar sesión vuelve a ese formulario. Se intenta un login automático por minuto y pestaña; si la ida y vuelta falla, aparece «Acceso no completado» con «Iniciar sesión de nuevo» en lugar de un bucle. `start` compila la consola en `.cache/local/console-dist`, separada de `dist/`. Diagramas de piezas, arranque y login en [flujo global](flujo-global.md).

El [perfil Keycloak implementado](../03-design/console-local-keycloak.md), según [ADR-0026](../decisions/ADR-0026.md), conserva las validaciones operator y configura ES256/at+jwt, clase/grant y MFA por ejecuciones reales. `bootstrap` autentica cada operación administrativa, sin sesión kcadm previa. `start` conecta AUTH, miembros/invitaciones y dashboard con cinco credenciales runtime separadas. Actualizar instalaciones existentes repitiendo `init` y `keycloak-init`, sin borrar `.cache/local`.

`npm run test:keycloak` añade un gate real separado, con realm, clúster, API y consola propios; requiere Keycloak activo, build previo y Python/Playwright. Metadatos en `.cache/keycloak-tests/latest.json`; alcance y evidencia vigente en [tareas AUTH](../features/FEAT-001-authentication/tasks.md). Límites: HTTP sin cookie `Secure`, correo sintético, sin rotación operativa, backup/restore ni producción. Los snapshots históricos anteriores no acreditan estas correcciones.
