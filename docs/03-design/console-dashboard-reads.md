# Lectura base autorizada del dashboard

Estado: DASH-T02 implementada para laboratorio, 2026-11-06. [ADR-0020](../decisions/ADR-0020.md). Implementa el caso de uso y las lecturas tenancy/audit del [contrato DASH-T01](console-dashboard-contract.md). DASH-T02 no habilitó rutas HTTP ni UI; DASH-T03 conecta [API/BFF y cursor](console-dashboard-http.md) como incremento posterior. Las secciones siguientes describen el corte DASH-T02.

## Caso de uso y autorización

[Service](../../src/platform/internal/dashboard/service.go) recibe actor autenticado, tenant selector y filtros; reutiliza el parser UTC y la matriz AUTH/USR sin nuevos grants. Overview compone seis secciones; ReadActivity abre una lectura autorizada cuyo consumidor trabaja dentro del mismo snapshot. Callback y store son puertos internos de confianza, no interfaces para el navegador.

[DashboardStore](../../src/platform/internal/adapters/postgres/dashboard.go) abre una transacción READ ONLY / REPEATABLE READ y establece operator_id/tenant_id mediante parámetros SET LOCAL. Revalida tenant/membership activos y carga roles, revisión y scopes antes de llamar al caso de uso. Éste comprueba dashboard:read y, para actividad, audit:read antes de consultar fuentes. No recibe capacidades desde claims o parámetros cliente. Una lectura en curso conserva su snapshot; la siguiente vuelve a leer permisos y revisión. El pool no conserva contexto al terminar, fallar o cancelar.

Tenant ajeno, inexistente o suspendido y membership no activa usan el mismo error de recurso inaccesible. Capacidad insuficiente usa forbidden; autorización incompleta o infraestructura fallida usa dependency. DASH-T03 conserva la traducción HTTP, Bearer/sesión BFF, no-store, correlación y medición de duración/resultado. RLS no autentica JWT ni valida sesiones.

## Fuentes conectadas

| Fuente | Lectura | Límites |
| --- | --- | --- |
| tenancy.memberships | COUNT de memberships activas, una vez por membership. | Tenant y members:read; snapshot actual independiente del periodo. asOf de transaction_timestamp() y generatedAt del reloj de composición. |
| platform.audit_events | eventId/action/outcome/occurredAt/actorId/targetId. | Tenant, success del allowlist, ventana UTC [from,to), techo asOf y posición descendente estricta (recorded_at,event_id), antes del límite. |

Actividad consulta como máximo limit+1 filas (limit entre 1 y 100) para detectar continuación. El puerto devuelve filas y lookahead, no una respuesta HTTP ni un cursor. DASH-T03 debe fijar asOf/deadline iniciales y autenticar el cursor ligado a actor, revisión/scopes, tenant y filtros **dentro del callback**, después de reautorizar y antes de consultar filas. Cifrado de cursor y respuesta paginada siguen pendientes; Position nunca se toma directamente de un cliente.

Las consultas no recuperan correlation_id, subject, correo, invitaciones, ciphertext, sesiones, claims o payload. No descifran datos ni llaman a Events, IdP o KMS. No emiten auditoría/outbox de negocio ni publican status.

## Issuers y disponibilidad

La auditoría no tiene atribución issuer. El adaptador excluye sus filas al recibir filtro o scopes issuer; una fila tenant no pertenece automáticamente a todos los emisores. Antes de agregar, el caso de uso rechaza un selector fuera de grants conocidos como recurso inaccesible. Un selector dentro de grants, uno de actor tenant o un conjunto issuer implícito requieren ownership confiable y fallan dependency porque ese dominio no existe. Combinar tenant_admin con issuer_operator no amplía alcance. Grants legacy incompletos fallan cerrados.

Las cinco secciones futuras son notAuthorized para los roles actuales, con value/asOf null: las capacidades issuer/definition/issuance/status siguen reservadas. La composición distingue permiso ausente de fuente autorizada desconectada (unavailable/source_not_connected), dando prioridad al permiso. Las pruebas puras cubren ambas representaciones sin conceder capacidades futuras al runtime.

SourceSection mantiene cero sólo para observación válida, marca stale después de 300 segundos y rechaza overflow JSON, negativos y observaciones futuras/ausentes. No hay caché ni último valor persistido. Si falla activeMembers, única fuente conectada del overview, se devuelve dependency global; no hay otra fuente válida para sostener un parcial. Un fallo del feed tampoco se convierte en lista vacía.

## Persistencia y reversión

[Migración 0011](../../src/platform/internal/adapters/postgres/migrations/0011_console_dashboard.sql) es aditiva: crea hukid_dashboard_runtime NOLOGIN sin escritura, ownership o BYPASSRLS; SELECT tenancy para revalidación/conteo y SELECT por columnas de auditoría con RLS tenant/allowlist. No permite identidad global, sesiones, invitaciones, correlation_id u outbox. Añade índice tenant/recorded_at/event_id descendente para la consulta keyset fijada, sin crear tablas de dominio o atribución issuer.

OpenRuntimePool admite esta credencial por separado y rechaza combinarla con roles AUTH/USR. El GUC tenant es contexto interno confiable; el caso de uso conserva la autoridad de actor/capacidad. No exponer pool o callback al cliente.

Antes de usar el store, aplicar la secuencia hasta 0011 con el CLI de migración de laboratorio. DASH-T02 no añade variables ni conecta una credencial al API: DASH-T03 deberá aprovisionar un login dedicado con este rol y validar su pool. Para revertir, retirar consumidor y login, conservando migración y datos históricos. No ejecutar down ni borrar auditoría. No se migró una base existente en esta entrega.

## Verificación

[Pruebas Go](../../src/platform/internal/dashboard/service_test.go) cubren permisos, precedencia de disponibilidad, null/0, frescura, overflow y fuente fallida. [Integración PostgreSQL](../../src/platform/internal/adapters/postgres/dashboard_integration_test.go) usa dos tenants y credenciales descartables: conteos sin duplicar roles, bordes UTC, allowlist, eventos globales/ajenos/denegados, orden/posición/asOf/lookahead, proyección mínima, roles/revisión vivos, snapshot consistente, suspensión, scopes issuer, pooling/cancelación, upgrade 0010→0011 y SQL/RLS. Comprueba rechazo de escritura incluso ante grant accidental, ausencia de nuevos audit/outbox y fallo explícito del feed caído.

Ejecutar `npm run check`, `npm run test:postgres`, `npm run build` y `npm run smoke` desde la raíz. Evidencia fechada en [tareas FEAT-003](../features/FEAT-003-dashboard/tasks.md). Estas pruebas no acreditan HTTP dashboard, cursor autenticado, navegador nuevo, carga, CI remoto ni producción; DASH-T03/T04 y el gate posterior conservan esos alcances.
