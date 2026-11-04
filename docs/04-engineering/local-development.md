# Desarrollo local de HukID

Estado: AUTH-T01/T02/T03 entregan bootstrap, baseline contractual y foundation PostgreSQL de laboratorio. Hay un servidor local Go con liveness y un entry point React compilable. La consola aún no renderiza pantallas; handlers de login/BFF/Management y store operativo de sesión siguen pendientes de AUTH-T04 y tareas posteriores.

Existe [contrato y laboratorio OIDC](../03-design/console-auth-contract.md), con política test, matriz y reglas de política Go. El IdP sólo se inicia dentro de pruebas Node y simula MFA; no arranca con Platform. AUTH-T03 añade [persistencia de consola](../03-design/console-persistence.md), sin conectar todavía PostgreSQL a la API HTTP.

## Estructura acordada

El owner confirmó esta distribución el 2026-11-03:

| Ruta | Contenido actual |
| --- | --- |
| `src/platform/cmd/api` | Proceso HTTP local y cierre ordenado. |
| `src/platform/internal/bootstrap` | Configuración loopback, liveness y pruebas del perímetro inicial. |
| `src/platform/internal/adapters/postgres` | Migraciones, roles/RLS, pools y contexto transaccional, descubrimiento mínimo y bootstrap test-only. |
| `src/platform/cmd/testdb` | CLI restringido para migrar/provisionar una base de pruebas explícita. |
| `src/console` | Workspace npm React/TypeScript con Vite; entry point sin pantalla funcional. |
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
| PostgreSQL de laboratorio | 18.6; binarios portables EDB 18.6-5 usados en Windows x64. |

Las versiones npm directas son exactas y `package-lock.json` fija las transitivas. Se consultaron el registro npm y las fuentes oficiales de [Go](https://go.dev/dl/), [React](https://react.dev/versions) y [Vite](https://vite.dev/guide/). AUTH-T03 añade pgx y un runner de migraciones propio pequeño, sin ORM. La primera ejecución de Go necesita descargar los módulos verificados por `go.sum`; `scripts/platform.mjs` guarda module/build cache dentro de `.cache`. La librería OIDC del backend Go sigue pendiente de AUTH-T04.

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

`check` verifica formato Go sin modificar archivos, ejecuta `go vet`, las pruebas Go sin caché de resultados, el typecheck TypeScript, `test:auth` y la validación documental (enlaces/anclas locales inline, bloques de código y presencia de los nueve archivos de features). Los enlaces de referencia y la semántica de contratos/tareas requieren revisión adicional. Para corregir formato, ejecutar `go fmt ./...` desde `src/platform`. `build` genera `.cache/build/hukid-api` (o `.exe`) y `src/console/dist/`. No genera handlers de autenticación.

Los scripts usan rutas relativas al propio archivo y funcionan desde un checkout en otra ubicación. No requieren Docker para este incremento. Existen pruebas de contrato e IdP de laboratorio; el login integrado y navegador requieren sus implementaciones.

AUTH-T03 incorpora DB/RLS con `npm run test:postgres`, comando separado y obligatorio para cambios de persistencia. `npm run check` conserva sus checks Go/TypeScript/contrato/docs y no simula ni salta una DB ausente. Para verificar el incremento completo ejecutar también `test:postgres`, además de build/smoke. No hay login integrado ni pruebas de navegador.

`smoke` requiere el build previo: rechaza arranque con política productiva/incompleta, arranca temporalmente el binario Go con política test en loopback:18080 y Vite preview en loopback:14173, comprueba HTTP 204/no-store, ausencia de login y disponibilidad del HTML/JS compilado, y termina sus procesos. Requiere esos puertos libres. Es una prueba HTTP, sin evaluación visual ni ejecución de navegador.

## PostgreSQL descartable y comandos AUTH-T03

El harness fue validado en Windows x64 con PostgreSQL 18.6. Obtener el [archivo portable EDB](https://get.enterprisedb.com/postgresql/postgresql-18.6-5-windows-x64-binaries.zip) desde la [página de binarios](https://www.enterprisedb.com/download-postgresql-binaries), verificar SHA-256 `e2246ba91d22345bc3d017586c09ede52d9df180b1eeb480f050445f1cad84e2` antes de extraerlo en `.cache/toolchains/postgresql-18.6-5/`; debe quedar `pgsql/bin/postgres.exe`. El [checksum confirmado por EDB](https://github.com/EnterpriseDB/edb-installers/issues/746) identifica el archivo usado. No se instala un servicio ni se modifica PATH global.

Como alternativa, indicar `HUKID_PG_BIN` con el directorio de binarios de una instalación PostgreSQL 18.6 confiable. El script verifica la versión; si usa el archivo portable en la ubicación predeterminada, también verifica su checksum. Otros sistemas operativos no se han validado en esta ejecución.

```sh
npm run test:postgres
```

El comando crea su propio clúster en `.cache/postgres-tests/run-*`, usa puerto libre/loopback y password administrativo aleatorio en memoria. Borra el archivo temporal de inicialización, ejecuta las pruebas Go con tag integration y finalmente elimina sólo bases/logins creados por las pruebas y detiene su servidor. Conserva el directorio ignorado y `postgres.log` para diagnóstico. No lee `HUKID_DATABASE_URL` de una aplicación existente, ni necesita Docker. La inicialización puede tardar en el primer arranque.

Los comandos manuales siguientes requieren una base test ya creada por el operador y credenciales externas al repo; no crean ni seleccionan una automáticamente:

```sh
npm run db:migrate:test
npm run db:bootstrap:test
```

Exigen `HUKID_ENV=test`, `HUKID_TEST_DATABASE=1` y `HUKID_DATABASE_URL` explícita: IP loopback, nombre `hukid_test_*`, un solo destino sin fallbacks y `sslmode=disable` sólo para este laboratorio local. El bootstrap exige al administrador del clúster descartable; un runtime login o flags productivos se rechazan. No se muestran DSN ni passwords en salida. La API no ejecuta estos comandos ni expone provisioning HTTP. Detalle de roles, límites y recuperación forward-only en persistencia de consola.

## Arranque de API y consola

En dos terminales desde la raíz:

```sh
npm run dev:platform
```

```sh
npm run dev:console
```

- Platform: `http://127.0.0.1:8080/healthz`, GET/HEAD devuelve 204 sin cuerpo. Es liveness del proceso, no readiness de dependencias.
- Vite: `http://127.0.0.1:5173/`, HTML con entry point React vacío. La ausencia de pantalla es esperada hasta AUTH-T08; no existe un botón de login simulado.
- Cerrar Platform con Ctrl+C inicia shutdown ordenado, con límite de cinco segundos.
- `HUKID_LISTEN_ADDR` permite otro IP loopback/puerto (por ejemplo `127.0.0.1:8081` o `[::1]:8081`). Un host abierto, nombre DNS o puerto inválido impide arrancar.
- Vite usa loopback y puerto estricto. No se configura proxy, CORS ni autorización hasta materializar los contratos. Sus servidores dev/preview son locales.

## Configuración e IdP

Este bootstrap no acepta tokens, no almacena sesiones, no contiene credenciales, no carga `.env` automáticamente y no tiene modo productivo. Las rutas `/console/auth`, `/console/api` y `/v1/operator` no están implementadas. El endpoint operativo `/healthz` no sustituye el OpenAPI de AUTH-T02.

AUTH-T02 configura un fixture `oidc-provider` en `tests/fixtures`, ligado a `127.0.0.1:19090` durante `npm run test:auth`. Requiere ese puerto libre. El runner establece explícitamente `NODE_ENV=test` y `HUKID_TEST_IDP=1`; el fixture rechaza flags productivos, genera claves y secreto de cliente en memoria y termina al finalizar. El cliente confidencial usa `client_secret_basic` con secreto efímero; esto no selecciona autenticación de cliente productiva. El fixture usa adapter en memoria y emite una advertencia esperada. Las interacciones automáticas del harness no autentican a personas ni comprueban OTP reales.

Las dependencias nuevas son únicamente de desarrollo y están fijadas en package/lock: `oidc-provider` 9.13.3, `jose` 6.2.15, `@apidevtools/swagger-parser` 13.1.0, `ajv` 8.20.0 y `ajv-formats` 3.0.1. No forman parte del binario Go ni del bundle React. La selección de librería OIDC para Go corresponde a AUTH-T04.

La validación previa al listener se puede ejecutar desde la raíz en PowerShell:

```powershell
$env:HUKID_ENV = 'test'
$env:HUKID_AUTH_POLICY = (Resolve-Path src/platform/config/auth.test.json).Path
npm run dev:platform
```

Esto valida la política y sólo arranca liveness; no conecta el IdP ni habilita login. Si se configura cualquiera de esas variables, ambas son obligatorias. Configuración inexistente, incoherente o entorno distinto de `test` falla antes de abrir el puerto. Sin ambas variables sigue disponible el bootstrap liveness-only. Para volver a ese modo en la misma terminal, usar `Remove-Item Env:HUKID_ENV,Env:HUKID_AUTH_POLICY -ErrorAction SilentlyContinue`. HTTP/Secure=false sólo se permite en este laboratorio loopback. Los TTL/MFA productivos siguen sin aprobarse.

Decisiones y alcance: [ADR-0002](../decisions/ADR-0002.md), [FEAT-001](../features/FEAT-001-authentication/plan.md), [pendientes](../05-delivery/documentation-gaps.md).

## Evidencia del bootstrap — 2026-11-03

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
