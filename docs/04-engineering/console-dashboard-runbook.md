# Operar el dashboard base en laboratorio

Owner: Team 5. Alcance: D1/D2 de FEAT-003, sólo test/loopback con identidades y MFA sintéticas. Este procedimiento sirve al desarrollador que prepara, diagnostica o retira un laboratorio; no es un despliegue productivo. El [gate D4](../05-delivery/dashboard-gate.md) mantiene la matriz de aceptación y límites de DoD. El [contrato](../03-design/console-dashboard-contract.md) conserva la semántica normativa.

## Preparar y activar

1. Usar un checkout identificado y las versiones de [desarrollo local](local-development.md). Instalar dependencias bloqueadas con `npm ci --ignore-scripts` y disponer del toolchain Go/PostgreSQL/Python/Chromium allí indicado.
2. Ejecutar desde la raíz `npm run test:dashboard:gate`. El harness crea sus clústeres descartables, logins separados, claves efímeras y dos contextos tenant; arranca API/BFF, IdP sintético y consola. No necesita ni modifica una base existente. Es el camino reproducible desde checkout para probar el incremento.
3. Revisar `.cache/dashboard-gate/latest.json`: status=passed, los cinco pasos aprobados y sourceDigest estable. Revisar por separado las mediciones de consultas/navegador descritas en [DASH-T07](../05-delivery/reviews/dashboard-t07-laboratory.md). Un gate fallido o source_changed impide aceptar ese checkout.
4. Para un laboratorio manual previamente provisionado, aplicar las migraciones hasta 0011 con `npm run db:migrate:test`, con las restricciones y variables explícitas del CLI en desarrollo local. Conservar AUTH completa y provisionar externamente el login dashboard exclusivo; la API no crea usuarios SQL ni migra. El harness de pruebas no deja un entorno manual persistente ni credenciales reutilizables.
5. Suministrar juntas HUKID_DASHBOARD_DATABASE_URL, HUKID_DASHBOARD_POLICY y HUKID_DASHBOARD_CURSOR_KEY según la [referencia API/BFF](../03-design/console-dashboard-http.md#configuración-y-retirada). No copiar DSN, claves ni tokens a documentos, shell history o tickets. Arrancar API y consola con los comandos de desarrollo local. No ampliar grants ni usar fixtures para poblar métricas operativas.
6. Con una sesión autorizada, seleccionar el tenant de prueba y abrir Resumen. Comprobar roles vivos, miembros activos y actividad permitida; cambiar tenant y verificar que se retiran datos previos. Sin audit:read no debe aparecer el feed; sin members:read no se muestra un conteo protegido. Probar un rango vacío y un rango inválido con recuperación. La suite Chromium automatiza estos casos; esta comprobación manual no reemplaza el gate.

La activación es configuración del proceso completo, sin feature flag por tenant. Limitar el laboratorio mediante su provisionamiento y autorización AUTH/USR; no prometer un rollout selectivo productivo. Ausencia de las tres variables retira rutas; configuración parcial impide arrancar.

## Fuentes habilitadas y diferidas

El [catálogo ejecutable](../../src/platform/contracts/dashboard-metrics.json) define permisos y significado. El inventario operativo de este incremento es:

| Fuente / owner | Consumidor activo | Alcance temporal y autorización |
| --- | --- | --- |
| tenancy.memberships / tenancy Team 5 | activeMembers | Snapshot actual de membresías activas; dashboard:read y members:read, tenant autorizado. Ignora el periodo del filtro. |
| platform.audit_events / audit Team 5 | activity | Sólo success allowlisted, [from,to), techo asOf y paginación keyset; dashboard:read y audit:read. Sin payload ni correo. |
| AUTH/USR / identidad y tenancy Team 5 | Shell, selección y roles/capacidades | Sesión y membresía vivas; no son métricas nuevas ni claims confiados desde el navegador. |

activeIssuers, publishedDefinitionVersions, createdRequests, issuedCredentials y pendingStatusChanges no tienen adaptador. Las capacidades issuer:read/definition:read/issuance:read/status:read siguen reservadas y sin grants en los roles actuales: esas cinco secciones devuelven notAuthorized con value/asOf null. unavailable es el estado de una fuente autorizada desconectada en el contrato, no un permiso concedido por este runbook. No hay propiedad issuer verificable: filtros/scopes que la requieren fallan cerrados con 503; un selector fuera de alcance da 404. No diagnosticarlo concediendo más roles.

D3 permanece abierto en DASH-T05. Cada fuente futura necesita owner, política/contrato y ADR cuando corresponda, fixtures propios, matriz negativa y nuevo gate. No hay emisión, status público, Events, wallet, exportación ni consulta live a KMS/IdP para calcular las métricas.

## Diagnóstico y recuperación

| Síntoma | Comprobación y acción |
| --- | --- |
| Proceso no inicia | Revisar presencia conjunta de las tres variables, perfil test, AUTH completa y login exclusivo/privilegios. No imprimir valores. Configuración parcial, productiva o pool inseguro se rechaza antes del listener. |
| Rutas 404 | Confirmar activación del proceso. Con rutas activas, 404 de recurso oculta tenant/issuer inexistente o inaccesible; verificar membresía por el flujo autorizado de miembros, sin enumerar IDs. |
| 401 / 403 | Reingresar con AUTH ante 401. Ante 403 revalidar /me/selección y capacidades una vez; no repetir en bucle ni fabricar capacidades cliente. |
| 422 invalid_input | Corregir ambos límites UTC [from,to), sin futuro y hasta 31 días. Miembros sigue siendo un snapshot, aunque cambie el periodo. |
| 422 invalid_cursor | Reiniciar actividad; conservar el nuevo rango efectivo. Expiración de 900 s, cambio de contexto/revisión/filtros/límite o rotación de clave invalidan páginas anteriores. No copiar cursor a logs o tickets. |
| 503 | Verificar conectividad y privilegios del pool exclusivo, autorización y ausencia de scope issuer no soportado. Fallo de audit no contamina overview; fallo de autorización cierra ambas lecturas. Reintentar la región tras resolver la dependencia. Nunca sustituir por cero/lista vacía. |
| Lentitud / datos aparentemente antiguos | Correlacionar operación/resultado/duración con X-Correlation-Id generado por servidor. Comprobar asOf por sección y rango; no hay caché compartida ni snapshot entre páginas. Medir volumen/concurrencia reales antes de añadir índices o SLO. |

Los logs de lectura contienen operación, resultado, duración y correlación, no URL/query, filas, DSN, tokens ni claims. Compartir sólo esa metadata necesaria y los metadatos del gate. El gate no acredita colector, alertas/on-call ni redacción en proxies/infraestructura externa. No hay scheduler, purga ni publisher nuevos: auditoría/retención conserva los [límites de miembros](console-members-runbook.md).

## Retirar y reactivar sin borrar datos

1. Detener el API del laboratorio y quitar juntas las tres variables HUKID_DASHBOARD_* de su configuración de arranque. No tocar AUTH/USR, datos ni migraciones. Reiniciar el mismo binario y comprobar /healthz=204 y las cuatro rutas dashboard=404; liveness por sí sola no acredita disponibilidad del dashboard.
2. El shell no tiene un flag de retirada: con sesión/contexto válidos puede seguir visible y sus solicitudes recibirán 404. Informar al operador y comprobar que no quedan métricas antiguas visibles; la UI tiene recuperación de contexto/error, no una promesa de ocultación por feature flag.
3. Mantener 0011, auditoría e índice; no ejecutar down, borrar eventos ni alterar estados de negocio. Si el laboratorio termina, retirar la credencial dedicada mediante el administrador del clúster y su procedimiento de gestión de secretos, después de cerrar el pool.
4. Para reactivar, restaurar las tres variables con login separado válido y clave dashboard exclusiva, arrancar y repetir las comprobaciones de activación. Rotar sólo esa clave invalida cursores existentes: reiniciar paginación; no invalida sesiones AUTH ni modifica datos.

Este procedimiento de retirada está definido para configuración de laboratorio. El gate comprueba configuración, rutas habilitadas, permisos/errores reales y rotación de cursor en pruebas; no acredita un ensayo manual completo de retirada/reactivación del proceso ni rollback binario, restore o DR. No se ofrece un script destructivo para resolver fallos.
