# Interfaz de autenticación — AUTH-T08

Consola React/TypeScript de laboratorio sobre el BFF existente. Decisión: [ADR-0009](../decisions/ADR-0009.md). Requisitos y cierre: [FEAT-001](../features/FEAT-001-authentication/tasks.md). El contrato ejecutable está en [OpenAPI](../../src/platform/contracts/console-auth.openapi.json).

## Flujo y estados

`/` comprueba `/console/api/me` antes de mostrar contexto. Sin sesión presenta Iniciar sesión; con cero memberships presenta Acceso pendiente y permite comprobar acceso o cerrar sesión. Con memberships muestra selector etiquetado y no selecciona autoridad unilateralmente: Continuar envía tenant-context y vuelve a leer `/me`. Con tenant activo muestra su nombre real y acciones de cambio, renovación, verificación de identidad y logout. No presenta miembros ni métricas todavía ausentes.

Los errores 401, 403, tenant no disponible, rate limit, conflicto y dependencia/red se muestran con acciones explícitas. No se inicia una cadena automática login/refresh/reintentos. La renovación usa el CSRF en memoria; una recarga con access token expirado exige nuevo login. Si se pierde una respuesta rotatoria, comprobar acceso o iniciar sesión recupera el flujo sin repetir ciegamente el comando.

La selección invalida la vista antes de enviar el comando; las respuestas de una generación anterior se descartan. No hay caches de datos privados ni storage JS. Cambio entre pestañas, ocultamiento/restauración e historial fuerzan revalidación antes de mostrar contexto. Web Locks coordina las peticiones de sesión entre pestañas del mismo origen y evita lecturas de actividad superpuestas a rotaciones. Se requiere un navegador moderno con Web Locks/BroadcastChannel en contexto seguro; HTTP loopback se limita al laboratorio. Las validaciones server-side de cada petición siguen siendo obligatorias.

## Interacción y presentación

Interfaz en español, un h1 por estado, foco de entrada al título, skip link y mensajes status/alert. Selector con label visible, error asociado y foco al control; botones deshabilitados sólo durante la operación. Tamaños táctiles de 48 px, reflow móvil, paleta clara/oscura según sistema y respeto de reduced motion. Tokens CSS centralizados; sin tipografías ni recursos de terceros.

El patrón es una superficie de acceso con contexto lateral que se apila en móvil. La pantalla no recibe contraseñas ni declara MFA completada mediante datos del navegador: delega ambas al IdP/BFF. Los identificadores opacos y capacidades no se muestran como datos de negocio.

## Desarrollo local

Vite sirve la consola y proxy `/console/` hacia `http://127.0.0.1:8080` por defecto. Para otro listener, definir `HUKID_CONSOLE_API_TARGET` al iniciar Vite. La política test debe usar el origen visible de Vite como consoleOrigin y ese mismo origen más `/console/auth/callback` como redirectUri. Configurar `HUKID_CONSOLE_PROXY_ORIGIN` en el API con ese origen exacto; no reescribir Origin ni habilitar CORS. El resto de credenciales/pools sigue en [desarrollo local](../04-engineering/local-development.md).

Sin IdP, DB y configuración test completa la UI muestra indisponibilidad; el arranque liveness-only no permite iniciar sesión. No hay bypass ni datos operativos simulados en la consola. Para verificar el flujo completo sin configurar servicios existentes se usa el harness siguiente.

## Pruebas reproducibles

Tras instalar Python 3.13, desde la raíz:

```sh
python -m venv .cache/browser-venv
```

En Windows:

```powershell
.cache/browser-venv/Scripts/python.exe -m pip install -r tests/browser/requirements.txt
.cache/browser-venv/Scripts/python.exe -m playwright install chromium
npm run build
npm run test:browser
```

En otros sistemas usar `.cache/browser-venv/bin/python`; no se ha verificado allí. `HUKID_BROWSER_PYTHON` permite indicar un intérprete existente con esas dependencias. La suite requiere PostgreSQL 18.6 y Go fijados según desarrollo local. No se omiten pruebas cuando falta Python/Chromium/build.

`test:browser` crea su propio clúster PostgreSQL, API, IdP sintético y Vite preview en loopback con puertos libres. El runner Python Playwright usa Chromium headless. El secreto que permite completar interacciones sintéticas sólo se transmite por stdin y cabecera limitada al path del IdP; no se introduce en React. Las mutaciones de fixtures las ejecuta el proceso Go administrador de su propia DB y no un endpoint del producto. Los servicios se terminan al finalizar.

Capturas ignoradas en `.cache/browser-auth/`: acceso de escritorio; sesión a 320/360/768/1024/1440 px; esquema oscuro. No hay trazas ni dumps que guarden tokens. Estas capturas y comprobaciones no acreditan certificación WCAG, MFA real, rendimiento en dispositivo físico, carga o restore. Auditoría integrada y gate operativo siguen en AUTH-T09/T10.

## Revisión de calidad — 2026-11-05

Patrón de acceso con panel estable y contexto lateral. Se verificaron operabilidad, claridad de estados, recuperación, confidencialidad del contexto y adaptación visual.

| Grupo de checklist ISO 25010 frontend | Resultado / evidencia |
| --- | --- |
| A — Jerarquía y claridad | Pass: un h1 y una acción principal por estado; selector y acceso pendiente explícitos. |
| B — Operación | Pass: login/selector/continuar mediante teclado; objetivos ≥44 px medidos en navegador; sin scroll interno. |
| C — Prevención de errores | Pass: doble envío bloqueado, selección inválida conserva valor y mueve foco al control. Sin operaciones destructivas en este incremento. |
| D — Estados y asistencia | Pass: labels, mensajes status/alert, error asociado, expiración, permisos y dependencia recuperables en español. |
| E — Coherencia visual | Pass: tokens únicos, tipografía local, revisión de capturas desktop/móvil/oscuro. |
| F — Accesibilidad | Pass para el alcance verificado: semántica, foco, teclado, reflow 320 px/200%, temas y reduced motion. Contrastes de texto de la paleta entre 5,91:1 y 14,26:1 en pares revisados. No certifica la totalidad de WCAG ni pruebas con lector físico. |
| G — Responsive | Pass: 320/360/768/1024/1440 px sin overflow horizontal; capturas revisadas. |
| H — Fiabilidad, seguridad y rendimiento | Pass de laboratorio: cookies HttpOnly, storage vacío, contexto obsoleto descartado, peticiones coordinadas y recuperación explícita. |

Medición Chromium con CPU ralentizada 4× y servicios loopback: LCP 96 ms, CLS 0,0045 y mayor duración de evento de interacción observada 16 ms. Se corrige el salto inicial (CLS 0,12) manteniendo una posición estable del panel. PerformanceObserver registra métricas en `.cache/browser-auth/performance.json`; la duración máxima observada es una comprobación de interacción sintética, no un INP de campo ni un SLA. No se midió dispositivo móvil físico. P2 pendiente: ampliar la revisión con lector de pantalla y dispositivos físicos; automatizar axe/Lighthouse en el gate operativo.
