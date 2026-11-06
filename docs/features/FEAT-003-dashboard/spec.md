# FEAT-003 — Dashboard operativo del tenant

- Producto: HukID Console / Team 5.
- Estado: DASH-T01 contractual y DASH-T02 lectura base autorizada implementadas en laboratorio; endpoints e interfaz pendientes.
- Depende de: identidad/contexto [FEAT-001](../FEAT-001-authentication/spec.md) y matriz [FEAT-002](../FEAT-002-user-management/spec.md).
- Salidas: [plan](plan.md), [tareas](tasks.md).

## Objetivo y alcance

Al entrar a un tenant, el operador ve dónde está, qué puede hacer y un resumen operativo confiable. El primer incremento muestra tenant, rol/capacidades, accesos autorizados y actividad mínima disponible de auth/memberships.

Cuando existan módulos issuer/definition/issuance/status, se conectan sus lecturas agregadas. Esta feature no implementa emisión ni presenta números ficticios para aparentar módulos terminados.

Fuera: dashboard de asistencia Events, inventario de wallet, historial de presentaciones directas, BI global, exportaciones sensibles y comandos de revocación/firma desde tarjetas.

## Requisitos y aceptación

| ID | Comportamiento verificable | Criterio de aceptación |
| --- | --- | --- |
| DASH-FR01 | Mostrar contexto y navegación efectiva del operador. | AC01: tenant/nombre/rol y accesos proceden de /me; acciones sin capacidad no aparecen y su URL directa sigue protegida server-side. |
| DASH-FR02 | Mostrar resumen agregado sólo del tenant y alcance issuer autorizado. | AC02: issuer_operator asignado a A no obtiene conteos ni actividad de B. TenantId/issuerId ajenos dan rechazo sin datos parciales. |
| DASH-FR03 | Definir cada métrica y distinguir cero de no disponible. | AC03: fuente implementada sin registros devuelve 0; módulo no conectado o fallido devuelve value null con estado explícito; no se suman offers, requests y credentials como si fueran la misma entidad. |
| DASH-FR04 | Filtrar por ventana temporal y issuer autorizado de forma consistente. | AC04: from/to se interpretan como intervalo UTC [from,to); cambios de filtros afectan todas las tarjetas aplicables y muestran periodo/zona. Rango inválido o excesivo se rechaza según política configurada. |
| DASH-FR05 | Mostrar actividad reciente mínima según capacidad. | AC05: sólo eventos permitidos, con action/outcome/occurredAt e IDs opacos; sin nombre del holder, correo de invitado, claims, códigos ni tokens. Sin permiso audit:read no se carga el feed. |
| DASH-FR06 | Expresar vigencia de datos y publicación de status. | AC06: respuesta/vista indican generatedAt y asOf por sección. Un cambio desired pendiente no aparece como published efectivo; datos antiguos muestran antigüedad sin prometer tiempo real. |
| DASH-FR07 | Manejar vacío, error parcial, forbidden y reintento seguro. | AC07: fallo de una fuente no se convierte en cero; tarjetas restantes siguen visibles si están autorizadas. 401 retorna al login y 403 actualiza capacidades sin bucle. |
| DASH-FR08 | Evitar mezcla de respuestas al cambiar tenant/filtro. | AC08: si responde tarde una petición del tenant A tras cambiar a B, no se renderiza en B. Se cancelan/descartan peticiones y se separan cachés por contexto. |
| DASH-FR09 | Mantener consultas sólo de lectura y observables. | AC09: leer dashboard no crea emisión, refresca status públicamente ni consulta Events. Registra latencia/errores/correlación sin payload sensible ni auditoría duplicada de negocio. |

## Métricas propuestas y disponibilidad por etapa

| Sección | Semántica / fuente | Condición |
| --- | --- | --- |
| Contexto | Tenant y capacidades actuales; FEAT-001. | Siempre tras sesión/contexto válidos. |
| Miembros | Memberships activas al asOf; tenancy. Snapshot actual, no filtrado por periodo. | Sólo members:read, desde FEAT-002. |
| Issuers | Issuers activos visibles al asOf. Snapshot actual. | Cuando exista módulo y issuer:read. |
| Definitions | Versiones publicadas visibles al asOf; distintas de definitions draft. | Cuando exista módulo y definition:read. |
| Solicitudes | DASH-T01 fija createdRequests como total de requests creados en [from,to), todos los estados al asOf; oferta tiene su estado separado. El desglose por estado se difiere al contrato del módulo propietario en DASH-T05. | Cuando exista módulo y issuance:read. |
| Credenciales emitidas | Artefactos confirmados con issuedAt en [from,to), no offers escaneadas. | Cuando exista módulo y lectura autorizada issuance:read. |
| Publicación status | Pendientes desired≠published y último asOf disponible, sin afirmar revocación efectiva prematura. | Cuando exista módulo y capacidad de lectura de status definida en contrato. |
| Actividad | Eventos permitidos ocurridos en [from,to), paginados. | audit:read y restricciones por issuer. |

La ausencia de permiso no revela que existan registros: omitir sección o devolver estado notAuthorized definido por contrato sin conteo/metadata de terceros. No prometer proyección snapshot común entre fuentes: cada sección declara su asOf.

## Calidad y permisos

| ID | Restricción | Verificación |
| --- | --- | --- |
| DASH-QR01 | Consultas acotadas por límite/periodo y sin llamadas live KMS/IdP/Events para calcular métricas. | Contrato de límites y pruebas de repositorio; no se acoplan dependencias de emisión a lectura. |
| DASH-QR02 | No cachear públicamente ni cruzar rol/tenant/issuer/rango. | Tests de dos operadores/tenants, cambios de roles y respuestas fuera de orden. |
| DASH-QR03 | Tarjetas, filtros y tablas legibles por teclado/lector y en móvil. | E2E de foco, nombres accesibles, loading y errores; información no depende sólo de color. |
| DASH-QR04 | Valores exactos en fixtures y degradación honesta. | Dataset sintético con límites de tiempo/status conocidos; pruebas de unavailable/partial/stale/0. |

No se fija nuevo p95 de dashboard hasta medir un perfil de carga. Los objetivos Integration API/Credential Endpoint no se aplican automáticamente a esta vista.

## Trazabilidad y decisiones

[Arquitectura HukID](../../03-design/hukid-architecture.md) define consola, entidades y autoridad; [seguridad/operación](../../04-engineering/hukid-security-and-operations.md) y HK-005/054 fundamentan auditoría/observabilidad. El dashboard y sus métricas son diseño nuevo de esta feature, no un panel ya descrito endpoint por endpoint.

Las fuentes de lectura, límites y capacidad reservada status:read se concretan en el [contrato DASH-T01](../../03-design/console-dashboard-contract.md) y [ADR-0019](../../decisions/ADR-0019.md), sin ampliar la matriz vigente. El incremento base no depende de implementar HK-010–025/050: las secciones sin permiso devuelven notAuthorized; con permiso y sin fuente real devuelven unavailable.

La [lectura base DASH-T02](../../03-design/console-dashboard-reads.md) conecta tenancy/audit mediante credencial separada y snapshot autorizado según [ADR-0020](../../decisions/ADR-0020.md). No cambia requisitos, grants o semántica contractual; HTTP/BFF y cursor público siguen en DASH-T03.
