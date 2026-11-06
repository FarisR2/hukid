# FEAT-003 — Plan técnico

Referencia: [spec](spec.md), [tareas](tasks.md), [autenticación](../FEAT-001-authentication/plan.md), [miembros](../FEAT-002-user-management/plan.md).

DASH-T01 materializa el [contrato y reglas de lectura](../../03-design/console-dashboard-contract.md), con [ADR-0019](../../decisions/ADR-0019.md). Las rutas de la tabla ya tienen OpenAPI contract-only; los componentes de runtime siguientes permanecen propuestos.

## Arquitectura de lectura

Añadir un caso de uso GetTenantOverview y puertos de lectura por dominio dentro del backend modular. No crear un microservicio de analytics ni leer la base Events.

| Componente propuesto | Responsabilidad |
| --- | --- |
| Platform internal/dashboard | Definiciones de métricas, ventana, composición y estados de disponibilidad. |
| Platform internal/authorization | Reutilizar actor, TenantContext y alcance issuer de FEAT-001/002. |
| Platform adapters/privateapi y console | Contrato de overview/activity y proxy BFF. |
| Platform adapters/postgres | Agregados autorizados, cursor/índices y watermark/asOf. |
| Console src/dashboard | Shell tenant, filtros, tarjetas y estados accesibles. |

Comenzar con queries contra tablas propias existentes; evolucionar a proyecciones internas si la medición lo requiere. No replicar claims para construir conteos ni otorgar al dashboard rol SQL propietario.

## Contratos nuevos propuestos

| Ruta Management | Entrada | Salida |
| --- | --- | --- |
| GET /v1/operator/tenants/{tenantId}/overview | from, to, issuerId opcional; valores/límites validados. | tenantId, generatedAt, window y sections con value/state/asOf/reasonCode. |
| GET /v1/operator/tenants/{tenantId}/activity | from, to, issuerId opcional, cursor, limit. | Eventos allowlisted + nextCursor/asOf; exige audit:read. |

Ambas exigen operator Bearer y membership/issuer scope actuales. Browser usa proxy bajo /console/api con sesión. No aceptar un tenant alternativo por body/header; ruta/filtro son selectores sometidos a autorización.

Estados de sección propuestos: available, unavailable, stale, error y notAuthorized. value es null si no hay un dato válido; 0 sólo para consulta exitosa vacía. notAuthorized no lleva conteo/asOf de fuente protegida. Errors/reasonCode no incluyen detalles internos SQL ni PII. OpenAPI fija campos y semántica antes del handler.

Respuesta global puede ser 200 con secciones parciales autorizadas; 401/403/404 de autorización no se transforman en éxito parcial. Si ninguna fuente base puede validarse por caída DB, usar error recuperable, no un dashboard de ceros.

## Consistencia y datos

Aplicar tenant y conjunto de issuers autorizado antes de agrupar; usar el mismo predicado para totales y actividad. Rol/issuer scope se revalida en servidor y no procede de opciones del navegador.

El periodo se aplica a requests createdAt, credenciales issuedAt y eventos occurredAt. Miembros/issuers/definitions son snapshots actuales al asOf, etiquetados sin fingir histórico. Status compara desired/published al asOf. No sumar métricas de entidades distintas ni interpretar issued como guardado permanente en wallet.

Paginación estable por tiempo/ID con cursor ligado al contexto y filtros. En la primera entrega usar no-store y evitar caché compartida; si se introduce caché posteriormente, incluir tenant/actor-capabilities-revision/issuer/rango en la clave e invalidar por cambio de autorización.

No se requieren tablas de credenciales para el incremento base. Fuentes ausentes se representan explícitamente como unavailable. Incorporar índices sólo tras fijar consultas/planes; cualquier proyección posterior tiene migración/owner y eventos propios.

## Hitos y dependencia real

| Hito | Requisitos previos | Gate |
| --- | --- | --- |
| D0 — Contrato y fixtures | AUTH-T02/T05; USR-T01 | DASH-T01 completada: contrato, reglas puras y fixtures; sin handlers ni fuentes conectadas. |
| D1 — Shell con contexto | AUTH-T08 | Tenant, capacidades y navegación reales; sin métricas simuladas en runtime. |
| D2 — Overview base | USR-T03/T07 y auditoría mínima | Miembros/actividad autorizada y estados de fuentes futuras. |
| D3 — Fuentes por dominio | Módulo propietario implementado | Cada tarjeta cumple AC02/03/04/06 con dataset conocido. |
| D4 — QA/operación | D1/D2 y fuentes comprometidas | Seguridad, respuestas tardías, accesibilidad, logs y DoD. |

D3 se entrega por adaptador disponible y no bloquea D1/D2. No declarar D3 completo si se muestran placeholders; el contrato deja visible qué fuentes están conectadas.

## Verificación

Unit tests de ventanas/estados/composición y reloj; integración con fixtures de dos tenants y varios issuers; contract tests de parciales/errores; navegador con respuestas fuera de orden y cambio de roles; pruebas accesibles de filtros/tabla.

Los comandos se toman del toolchain registrado en AUTH-T01. Medir consultas y latencia con datos del piloto antes de añadir una meta de rendimiento. El feed de actividad muestra registros de auditoría existentes; leerlo no vuelve a emitir eventos de negocio.

## Rollout y reversión

Activar shell/overview por tenant de pruebas; conectar fuentes gradualmente, con capability checks. Si una fuente falla se degrada esa sección; si falla autorización se bloquea el acceso completo. Revertir UI/adapter o deshabilitar sección sin borrar datos ni cambiar estados de emisión. No requiere KMS ni firma para el incremento base.
