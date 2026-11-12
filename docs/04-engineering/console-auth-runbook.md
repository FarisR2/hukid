# Operación de autenticación de consola — laboratorio

Owner: Team 5, backend/seguridad y plataforma. Alcance: AUTH-T01–T10 en Windows x64 y recursos sintéticos aislados. Esta guía opera el panel administrativo; no habilita Events, wallet ni emisión. [Gate A4](../05-delivery/authentication-gate.md) registra evidencia y límites. Producción permanece bloqueada por los requisitos allí enumerados.

## Preparación y configuración

Usar un checkout de la revisión validada y las versiones de [desarrollo local](local-development.md). Instalar desde package-lock con npm ci --ignore-scripts. El [workflow](../../.github/workflows/authentication.yml) usa Windows y los mismos comandos locales, sin credenciales de despliegue.

Los binarios PostgreSQL portables pueden verificarse/instalarse en Windows desde la raíz:

```powershell
./scripts/install-test-postgres.ps1
```

El script descarga sólo el archivo EDB fijado y verifica el SHA-256 antes de extraer. No crea servicio, base ni modifica PATH. Go, Node/npm y Python/Chromium requieren preparación independiente según desarrollo local.

Hay tres modos:

| Modo | Configuración | Resultado esperado |
| --- | --- | --- |
| Deshabilitado | Sin variables de autenticación; listener loopback explícito. | Sólo /healthz 204, rutas de auth/operator 404. El panel no permite operar. |
| Laboratorio habilitado | Política, IdP test registrado, clave y tres credenciales runtime completas. | Nueve operaciones BFF/Management; IdP y DB no los inicia el API. |
| Incompleto/productivo | Variables parciales, entorno diferente de test, origen o roles inválidos. | Falla antes de escuchar; no hay fallback para operar. |

La [tabla de configuración](../03-design/console-oidc-login.md#http-y-configuración) es la fuente única para variables runtime. Los pools requieren roles separados session/context/tenant, una misma DB hukid_test_* en IP loopback y sin fallbacks. Nunca usar al administrador como credencial del API. La clave externa tiene 32 bytes y versión; conservarla junto con el entorno privado mientras sus envelopes sean necesarios. El loader sólo admite una clave: cambiarla no constituye rotación compatible.

El comando de bootstrap mínimo se limita al administrador del clúster test. No crea IdP ni sesiones y no vuelve a conceder acceso suspendido. FEAT-002 aún no administra miembros. No pegar DSN, client secret, clave, cookie ni salida de /me en tickets o logs; CSRF también es secreto.

Para demostrar el flujo integrado sin preparar manualmente secretos, usar el gate y sus harnesses descartables. No existe una demo persistente de un comando: los recursos de las pruebas se detienen al terminar.

## Rollout del laboratorio

1. Validar revisión y árbol de trabajo. Ejecutar npm ci --ignore-scripts y el gate descrito abajo. Revisar la matriz y las limitaciones; un resultado passed no autoriza producción.
2. Detener todas las instancias del API de ese laboratorio y el acceso al panel. Confirmar que los procesos propios terminaron; no cambiar esquema bajo peticiones activas.
3. Con HUKID_ENV=test, HUKID_TEST_DATABASE=1 y HUKID_DATABASE_URL externos apuntando a la DB test, ejecutar npm run db:migrate:test. El CLI usa migraciones forward-only con checksum; el API no migra al arrancar. No editar SQL ya aplicado ni intentar down.
4. Sólo para una DB sintética nueva ejecutar npm run db:bootstrap:test. Configurar IdP test, cliente y tres logins SQL separados mediante el proceso restringido de laboratorio; el API no provisiona ni emite membresías.
5. Suministrar la configuración runtime completa mediante el entorno privado y arrancar npm run dev:platform. Arrancar npm run dev:console con el proxy explícito si su origen difiere del API. No habilitar CORS ni confiar en forwarded headers.
6. Comprobar /healthz y después el journey real: login con MFA sintética, acceso pendiente o selección autorizada, /me, tenant, refresh, step-up y logout. /healthz acredita proceso vivo; no es readiness de DB/IdP.
7. Revisar eventos de autenticación y outbox con acceso administrativo autorizado. Confirmar que 401/403/404/429/503 se manejan sin bucles y sin secretos en diagnóstico. Conservar el informe del gate ligado a su revisión y entorno.

No usar la configuración sintética en un despliegue externo. Preparar proveedor/factores reales, HTTPS, secretos, observabilidad y recuperación requiere otro incremento acordado.

## Retirada y recuperación segura

La reversión ensayada es retirar el acceso, invalidar autenticación y reactivar la misma revisión validada sobre el mismo esquema. No es bajar migraciones, restaurar backups ni volver a un binario anterior.

1. Detener el API y todas sus réplicas/proxies de ese entorno antes de invalidar. Una instancia que siga aceptando login puede crear familias nuevas después del comando; el comando no es un feature flag durable.
2. En una terminal de mantenimiento aislada, suministrar HUKID_ENV=test, HUKID_TEST_DATABASE=1 y HUKID_DATABASE_URL externos del administrador de la DB test. Ejecutar:

```powershell
npm run db:invalidate-auth:test
```

3. Exigir salida exitosa. El comando rechaza runtime/no administrador, flags o destino no permitidos. En una transacción bloquea escrituras de auth, revoca familias, borra envelopes/digests/leases y consume transacciones OIDC pendientes sin conservar verifier. Genera auth.family.revoked/outbox por transición activa y mantiene identidades, memberships, esquema, eventos e historial. Repetirlo no duplica eventos de revocación. La cancelación/fallo de DB/auditoría revierte todo; no declarar la invalidación completada ante error.
4. Cerrar la terminal de mantenimiento. Para iniciar sólo liveness desde otra terminal, retirar toda configuración HUKID heredada; en el laboratorio PowerShell puede limpiarse el entorno del proceso actual así:

```powershell
Get-ChildItem Env:HUKID_* | ForEach-Object { Remove-Item -LiteralPath ('Env:' + $_.Name) }
$env:HUKID_LISTEN_ADDR = '127.0.0.1:8080'
npm run dev:platform
```

Esta limpieza sólo afecta la terminal actual; no elimina secretos de otros procesos ni almacenes. No combinar una retirada parcial de variables con credenciales antiguas.
5. Confirmar /healthz 204 y /console/auth/login, /console/api/me y /v1/operator/me 404 incluso con cookie anterior. Mantener el acceso retirado si falla la invalidación.
6. Para reactivar, detener el modo liveness, corregir la causa y volver a cargar la configuración completa válida del entorno privado. Arrancar el mismo binario revisado, con esquema conservado. La cookie anterior debe fallar con 401 y el callback pendiente con 400; un login nuevo debe completar /me. No rehabilitar familias ni reusar code/state/refresh.
7. Ante sospecha de compromiso, revisar y revocar credenciales/grants en el IdP por su procedimiento propio. La invalidación local no revoca un Bearer operator ya emitido ni todos los grants del IdP; Management directo sigue validando esos tokens mientras sean válidos. Retirar todos los listeners durante el incidente y no reabrir ese plano sin resolverlo.

El CLI tiene deadline de 30 segundos y es offline para laboratorios pequeños; no hay presupuesto de carga aprobado. La prueba automatizada termina sus propios procesos para ensayar la retirada en Windows; no acredita drenado por señales, cero interrupción, alta disponibilidad o restore.

## Diagnóstico e incidentes

Registrar únicamente revisión, hora, código estable de error, status y correlationId generado por servidor. El [contrato de auditoría](../03-design/console-auth-audit.md) mantiene campos y garantías; correlación no equivale a trazado distribuido.

| Señal | Comprobación y respuesta |
| --- | --- |
| Arranque falla | Revisar presencia y coherencia de configuración sin imprimir valores. Confirmar listener/origen explícito, roles runtime separados, DB migrada y discovery IdP. Corregir el entorno completo; no omitir validaciones. |
| /healthz 204 y /me falla | Revisar status del flujo autenticado; liveness no verifica autorización ni dependencias continuas. |
| 401 sesión/token inválido | Iniciar login nuevo. No recuperar una generación vieja ni insistir con refresh incierto. |
| 403 csrf/origin | Releer contexto cuando sea válido y revisar origen/proxy; no desactivar CSRF. MFA/step-up se resuelven mediante reautenticación en IdP. |
| 404 tenant | Verificar membership/tenant vigente en ese entorno con autoridad administrativa. No conceder roles desde el navegador. |
| 409 refresh en curso | Respetar Retry-After y volver a validar sesión; no paralelizar intercambios. |
| 429 | Respetar Retry-After; el limitador es local al proceso, no distribuido. |
| 503 dependencia | Revisar DB/IdP y clave disponible sin revelar DSN/tokens. El estado de un comando puede ser incierto: revalidar o exigir nuevo login, no repetir ciegamente. |
| auth audit unavailable | Se perdió o pudo perderse evidencia de rechazo. Conservar correlación y retirar acceso si no se puede observar el entorno. No registrar el error SQL ni afirmar completitud de denegaciones. |
| http server failure | Diagnóstico fijo de net/http; investigar con revisión y contexto sanitizado. No habilitar volcados de requests/panic para recuperar secretos. |
| Crecen expirados/outbox | Revisar purga/dependencias. Purga corre cada minuto en lotes de 100; falla sin ampliar validez. Outbox no tiene publisher y su crecimiento es esperado: no marcar published ni borrar historia para ocultarlo. |

No hay dashboard operativo, métricas exportadas, alertas automatizadas ni on-call productivo. Las siguientes consultas son observación manual, sólo con un administrador test autorizado, sin recuperar payload/identidades:

```sql
SELECT state, count(*) FROM console_auth.session_families GROUP BY state;
SELECT count(*) AS pending_oidc FROM console_auth.oidc_transactions
 WHERE consumed_at IS NULL AND expires_at <= now();
SELECT action, outcome, count(*) FROM platform.audit_events
 WHERE recorded_at >= now() - interval '1 hour' GROUP BY action, outcome;
SELECT count(*) AS unpublished FROM platform.outbox_events WHERE published_at IS NULL;
SELECT count(*) AS missing_outbox FROM platform.audit_events a
 LEFT JOIN platform.outbox_events o USING(event_id) WHERE o.event_id IS NULL;
```

No añadir lecturas audit al runtime para ejecutar estas consultas. La política institucional de retención no está aprobada: no purgar audit/outbox ni asociar su retención al TTL de sesión.

## Gate reproducible

```sh
npm run test:auth:gate
```

Ejecuta en secuencia check → build → test:postgres → smoke → test:browser y se detiene ante el primer fallo. No se salta PostgreSQL o Chromium ausentes. Sobrescribe .cache/auth-gate/latest.json con estados, tiempos, HEAD, indicador dirty y SHA-256 de las fuentes; rechaza cambios de fuente durante la ejecución. El informe no contiene entorno, logs ni secretos. Si dirty=true, acredita el árbol identificado por digest, no sólo el HEAD base.

Requisitos: herramientas fijadas, Python/Playwright y Chromium instalados, IP loopback y puertos libres del smoke/fixture. Los harnesses crean sus propios recursos; el gate no usa DB existente. No ejecutar dos gates en el mismo checkout a la vez. Las capturas se mantienen en el directorio ignorado descrito en [interfaz](../03-design/console-auth-interface.md).

El workflow CI usa el mismo gate y acciones oficiales fijadas a SHA: [checkout](https://github.com/actions/checkout/tree/v6.0.2), [setup-node](https://github.com/actions/setup-node/tree/v6.5.0), [setup-go](https://github.com/actions/setup-go/tree/v6.3.0) y [setup-python](https://github.com/actions/setup-python/tree/v6.1.0). Python sigue la rama 3.13 del runner; los paquetes del navegador están fijados en requirements. El resultado local no prueba una ejecución GitHub Actions ni configura reglas de protección de rama.
