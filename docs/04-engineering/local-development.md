# Desarrollo local de HukID

Estado: bootstrap AUTH-T01. Hay un servidor local Go con liveness y un entry point React compilable. La consola aún no renderiza pantallas; login, IdP, BFF, Management, PostgreSQL y migraciones siguen pendientes de AUTH-T02 y tareas posteriores.

## Estructura acordada

El owner confirmó esta distribución el 2026-11-03:

| Ruta | Contenido actual |
| --- | --- |
| `src/platform/cmd/api` | Proceso HTTP local y cierre ordenado. |
| `src/platform/internal/bootstrap` | Configuración loopback, liveness y pruebas del perímetro inicial. |
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

Las versiones npm directas son exactas y `package-lock.json` fija las transitivas. Se consultaron el registro npm y las fuentes oficiales de [Go](https://go.dev/dl/), [React](https://react.dev/versions) y [Vite](https://vite.dev/guide/). El backend usa sólo la biblioteca estándar; no necesita `go.sum` todavía. No se eligen librerías OIDC, SQL o migración antes de AUTH-T02.

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

`check` verifica formato Go sin modificar archivos, ejecuta `go vet`, las pruebas Go sin caché de resultados, el typecheck TypeScript y la validación documental (enlaces/anclas locales inline, bloques de código y presencia de los nueve archivos de features). Los enlaces de referencia y la semántica de contratos/tareas requieren revisión adicional. Para corregir formato, ejecutar `go fmt ./...` desde `src/platform`. `build` genera `.cache/build/hukid-api` (o `.exe`) y `src/console/dist/`. No genera servicios de autenticación ni contratos.

Los scripts usan rutas relativas al propio archivo y funcionan desde un checkout en otra ubicación. No requieren Docker para este incremento. Las pruebas de integración DB, contrato, IdP y navegador se incorporan con las tareas que implementen esos comportamientos; estos checks iniciales no prueban login ni aislamiento tenant.

`smoke` requiere el build previo: arranca temporalmente el binario Go en loopback:18080 y Vite preview en loopback:14173, comprueba HTTP 204/no-store, ausencia de login y disponibilidad del HTML/JS compilado, y termina sus procesos. Requiere esos puertos libres. Es una prueba HTTP, sin evaluación visual ni ejecución de navegador.

## Arranque local

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

Este bootstrap no acepta tokens, no almacena sesiones, no contiene credenciales, no carga `.env` automáticamente y no tiene modo productivo. Las rutas `/console/auth`, `/console/api` y `/v1/operator` no están implementadas. El endpoint operativo `/healthz` no sustituye el contrato OpenAPI de AUTH-T02.

En AUTH-T02 se elegirá y configurará un IdP de pruebas aislado, con issuer/client/usuarios sintéticos propios, sin exportar claves ni secretos al repo. Se comprobarán token class/audience y `amr`/`acr`/`auth_time` antes de conectar el login. No existe fixture IdP en este incremento ni configuración de producción que pueda reutilizarlo por accidente. No se aprueban TTL/MFA, un proveedor productivo ni un bypass local de autenticación.

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
