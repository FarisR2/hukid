# Contrato de lectura del dashboard

Estado: baseline DASH-T01, 2026-11-06, contrato y reglas de laboratorio según [ADR-0019](../decisions/ADR-0019.md). DASH-T02 añade [caso de uso/lectura SQL autorizada](console-dashboard-reads.md) y credencial separada según [ADR-0020](../decisions/ADR-0020.md). DASH-T03 conecta las cuatro rutas [API/BFF y cursor autenticado](console-dashboard-http.md) según [ADR-0021](../decisions/ADR-0021.md); UI sigue en DASH-T04.

## Artefactos y consumidores

- [OpenAPI 3.1](../../src/platform/contracts/console-dashboard.openapi.json): dos GET Management bajo `/v1/operator/tenants/{tenantId}` y sus pares BFF bajo `/console/api/tenants/{tenantId}`, terminados en `/overview` y `/activity`.
- [Schemas estrictos](../../src/platform/contracts/dashboard.schema.json): overview, sección, actividad, ventana y Problem Details; sin propiedades adicionales.
- [Catálogo de métricas](../../src/platform/contracts/dashboard-metrics.json): fuente, capacidad, periodo, filtro issuer y definición por métrica. Es la fuente de detalle de las métricas; los nombres no implican módulos implementados.
- [Política test](../../src/platform/config/dashboard.test.json) y [schema](../../src/platform/contracts/dashboard-policy.schema.json): perfil cerrado de laboratorio; no autoriza despliegue productivo.
- [Reglas Go](../../src/platform/internal/dashboard/request.go): análisis de filtros/ventanas sin efectos, compartido por los adaptadores HTTP.
- [Ejemplos](../../tests/fixtures/dashboard/responses.json) y [dataset](../../tests/fixtures/dashboard/dataset.json) sintéticos para pruebas. No se importan en API, worker ni consola.

Management acepta sólo Bearer operator válido con `operator:read`, además de membership y permisos locales vivos. BFF reutiliza sesión AUTH server-side y sus reglas de expiración/refresh; no transporta Bearer al navegador. Ambos exigen `dashboard:read`; activity exige además `audit:read`. No requieren step-up por ser lecturas. No aceptan tenant/rol/capacidad alternativos por body o cabecera. El BFF rechaza primero un tenant inexistente/inaccesible con 404 y exige que un selector accesible coincida con el seleccionado; una discrepancia o selección ausente devuelve 403. Esta precedencia se concreta en [ADR-0021](../decisions/ADR-0021.md), incluida la selección retirada por AUTH. Management autoriza el tenant de ruta sin depender de una selección de navegador.

## Autorización y fuentes

Se revalida actor, membership activa, capacidades, revisión y scope issuer antes de leer datos o reutilizar cursor. Tenant inexistente o inaccesible da el mismo 404; falta de capacidad en un contexto autorizado da 403. Un issuer ajeno al tenant o al alcance actual devuelve 404 sin datos parciales. Un selector válido sin fuente confiable de ownership devuelve 503, nunca una autorización inferida del UUID.

Sin issuerId, un operador con alcance issuer sólo puede agregar la intersección de sus issuers asignados y los pertenecientes al tenant, verificados por la fuente propietaria. Un conjunto vacío nunca significa todos. Los roles se combinan por capacidades, pero una capacidad genérica no amplía por sí sola el alcance issuer. Las políticas futuras de dominio deben distinguir autoridad tenant de grants issuer y verificar propiedad antes de agregar; tenant_admin no implica autoridad global.

La matriz AUTH/USR permanece sin cambios. `issuer:read`, `definition:read`, `issuance:read` y **`status:read`** quedan reservadas en el catálogo y no se conceden a ningún rol actual. DASH-T05 requerirá política de dominio y decisión compatible antes de activarlas. Para cada sección se evalúa permiso primero: sin él se devuelve `notAuthorized` con value/asOf null, aunque tampoco exista la fuente. Así no se revela disponibilidad de datos protegidos. Con permiso y sin módulo: `unavailable/source_not_connected`. El fixture future supone permisos futuros sólo para probar esta representación; no es una respuesta de los roles actuales.

Miembros es un snapshot tenant, nunca un conteo de miembros por issuer: con `members:read` y filtro issuer devuelve `unavailable/scope_not_applicable`. Sin `members:read`, devuelve `notAuthorized`. La comprobación global del selector issuer sigue siendo obligatoria incluso si ninguna tarjeta es aplicable.

## Ventana, límites y frescura

`from` y `to` se suministran juntos en RFC3339 UTC con sufijo Z, segundos obligatorios y hasta nueve decimales. El intervalo es **[from,to)**: incluye from y excluye to. Debe cumplir from < to <= reloj servidor y durar como máximo 31 días (2 678 400 segundos). Sin ambos se usa [now−24h,now). No hay límite de antigüedad adicional. Respuesta devuelve los límites efectivos, `timeZone: UTC` y `bounds: [from,to)`; las páginas siguientes reutilizan esos límites explícitos.

Se rechazan parámetros desconocidos, duplicados, vacíos o mal codificados y query mayor de 4096 bytes. `issuerId` usa UUID canónico en minúsculas. Activity acepta limit entero de 1 a 100, predeterminado 25. Overview no acepta cursor/limit. El parser valida forma, no autenticidad del cursor ni autoridad issuer.

`generatedAt` es el momento UTC de composición. Cada lectura exitosa declara su propio `asOf` <= generatedAt; no se promete snapshot común. Fuentes snapshot ignoran periodo y se etiquetan como tales; las fuentes window aplican [from,to). Una observación de hasta 300 segundos de antigüedad es available; una anterior es stale, conserva el último valor válido y su asOf con `source_stale`. Sin observación válida no se inventa stale: se devuelve error o unavailable según causa. No se interpreta asOf de la sección status como instante de publicación pública: la métrica mide pendientes desired≠published, nunca revocaciones efectivas. Una futura métrica de publicación necesitará watermark publicado propio.

| Estado | value | asOf | reasonCode |
| --- | --- | --- | --- |
| available | Entero exacto no negativo; 0 sólo tras lectura exitosa vacía. | Observación válida. | null |
| stale | Último entero válido, puede ser 0. | Observación antigua. | source_stale |
| unavailable | null | null | source_not_connected o scope_not_applicable |
| error | null | null | source_failed |
| notAuthorized | null | null | capability_required |

Los conteos no exceden el entero seguro JSON 9 007 199 254 740 991; overflow se trata como source_failed. Error de una fuente autorizada puede producir 200 parcial sin afectar otras. Un error en autorización/contexto o caída que impida validarlos devuelve 503 global; 401/403/404 nunca se convierten en secciones. Un overview sin tarjetas autorizadas sigue siendo válido y no revela registros. Si todas las fuentes autorizadas fallan y ninguna tiene dato válido, devolver 503; unavailable y notAuthorized no son fallos de dependencia.

## Actividad y cursor

El feed permite exclusivamente las acciones success enumeradas en el catálogo. Expone eventId, action, outcome, occurredAt, actorId nullable y targetId opacos. `occurredAt` procede de `recorded_at` (confirmación registrada por DB, no hora de ocurrencia externa). No devuelve tenant por fila, subject, nombre, correo, hint de destinatario, claims, códigos, tokens, correlación interna ni payload. Cada fila pertenece al tenant autorizado y cumple el mismo scope antes de paginar. No se consulta el feed sin audit:read; un fallo de su única fuente devuelve 503 y nunca items vacío.

La auditoría actual AUTH/USR tiene tenant_id nullable y carece de issuer_id. Se excluyen eventos globales, login previo a selección y denegaciones sin tenant verificado. Los eventos AUTH ya tenant-scoped y los de miembros permiten actividad mínima real en DASH-T02. Una fila sin atribución issuer **no** se considera de todos los issuers: se excluye al filtrar por issuer o bajo alcance restringido de issuer. Atribución issuer futura requiere fuente/diseño propietario; el dataset incluye ejemplos futuros identificados, sin añadir esa columna al DDL actual.

Orden descendente `(recorded_at,event_id)`; posición de página estrictamente menor que la última fila. Primera lectura fija asOf y deadline; páginas siguientes conservan ambos, aplican recorded_at <= asOf y autorización viva. El cursor opaco debe estar cifrado/autenticado y ligar versión, operación, actor, revisión de autorización, tenant, conjunto issuer autorizado, issuerId, from/to normalizados, limit, asOf, posición y deadline. TTL de 900 segundos sin renovación al paginar. Reutilizarlo en otro contexto, manipularlo o dejarlo expirar da 422 invalid_cursor. Con cursor son obligatorios from/to explícitos; no recalcular el periodo predeterminado. Cambio de permisos impide replay: reautorizar antes de validar el binding. No se garantiza snapshot entre transacciones/páginas frente a confirmaciones tardías; no es una exportación exhaustiva.

## Errores, observación y compatibilidad

| HTTP | code | Comportamiento |
| --- | --- | --- |
| 400 | invalid_request | Query desconocida/duplicada/vacía/mal codificada o demasiado larga. |
| 401 | invalid_credential | Bearer/sesión inválidos; Management incluye WWW-Authenticate: Bearer. Browser vuelve al flujo AUTH. |
| 403 | forbidden | Sin capacidad o contexto BFF distinto del seleccionado; refrescar /me una vez, sin bucle. |
| 404 | resource_not_found | Selector tenant/issuer inexistente o fuera de acceso, indistinguibles. |
| 422 | invalid_input / invalid_cursor | Forma/rango/limit inválidos o cursor inválido, sin diagnóstico interno. |
| 429 | rate_limited | Reintento según Retry-After; no establece un nuevo rate limiter en DASH-T01. |
| 503 | dependency_unavailable | Contexto/ownership no verificable, feed caído o todas las fuentes autorizadas fallidas. |

Todos los éxitos y errores llevan no-store, no-referrer y X-Correlation-Id generado por servidor; errores usan Problem Details sin texto externo. No hay caché compartida. Las lecturas no emiten auditoría de negocio ni publican status; el middleware AUTH puede registrar rechazos como hasta ahora. Los futuros adapters medirán duración/resultado/correlación con etiquetas acotadas, sin URL/query/payload sensibles ni llamadas live a Events, IdP o KMS para calcular métricas.

Contrato propio nuevo v0.1-draft, aditivo respecto a AUTH/USR. DASH-T03 implementa las cuatro rutas en laboratorio; cambiar grants, ampliar el allowlist, incorporar status efectivo o alterar semántica requiere revisar contrato, historias y ADR. Las pruebas de fixtures no acreditan RLS, consultas, carrera de permisos ni cancelación de UI. DASH-T02/03 añaden pruebas de lecturas y perímetro HTTP real; DASH-T04 interfaz; DASH-T05 dominios futuros; DASH-T06–T08 cierran pruebas y operación.

La propuesta inicial de FEAT-003 mencionaba solicitudes por estado. Este baseline concreta únicamente el total createdRequests, sin inventar un enum de estados para un dominio aún ausente; el desglose se difiere al contrato propietario y DASH-T05. La spec refleja esta diferencia. Asimismo, la propuesta de mostrar la última publicación status se mantiene diferida: pendingStatusChanges y su asOf no representan un watermark de publicación. Ninguna de estas fuentes está conectada por DASH-T01.
