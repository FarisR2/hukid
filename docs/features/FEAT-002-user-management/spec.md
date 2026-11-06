# FEAT-002 — Gestión de miembros de tenant

- Producto: HukID Console / Team 5.
- Estado: USR-T01 materializa contrato/reglas y USR-T02 la [persistencia ampliada](../../03-design/console-members-persistence.md) de laboratorio; USR-T03 añade [lecturas autorizadas](../../03-design/console-members-directory.md); mutaciones, entrega y UI pendientes.
- Depende de: [FEAT-001](../FEAT-001-authentication/spec.md).
- Salidas: [plan](plan.md), [tareas](tasks.md).

## Objetivo y alcance

Permitir que un administrador gestione quién opera dentro de su tenant: consultar miembros, invitar, asignar roles/alcance issuer, suspender, reactivar y revocar acceso, con concurrencia y auditoría.

Usuario significa operador humano de la consola. No es el holder de Flutter, un participante Events ni un integration client. Una identidad puede tener memberships independientes en varios tenants; gestionar una no modifica automáticamente las demás.

No incluye alta pública de tenants, passwords, account recovery, borrado global de identidad, impersonation, creación de issuer/keys ni grants de integración. La primera membership administrativa procede del bootstrap restringido de FEAT-001.

## Matriz de capacidades

Esta matriz se materializa en la [fuente única de capacidades](../../../src/platform/contracts/capabilities.json) y el [contrato USR-T01](../../03-design/console-members-contract.md). Los roles provienen de la seguridad HukID; capabilities no reemplazan scopes/audience de los tokens ni implementan handlers por sí solas.

| Rol local | Miembros e invitaciones | Auditoría | Operación de issuer / dashboard |
| --- | --- | --- | --- |
| tenant_admin | Leer, invitar, modificar roles/alcance/estado y revocar con step-up. | Leer eventos autorizados del tenant. | Resumen de recursos del tenant; otras acciones requieren policy del dominio. |
| security_admin | Leer miembros y estado de acceso; sin escribir memberships en este incremento. | Leer eventos de seguridad autorizados. | Resumen de seguridad permitido; no emitir por defecto. |
| issuer_operator | Sin directorio de miembros ni invitaciones. | Sólo datos explícitamente concedidos por policy; no audit global. | Lectura operativa de issuers asignados. |
| support_readonly | Sin directorio de miembros ni invitaciones. | Sin audit por defecto. | Resumen técnico mínimo sin claims/PII de terceros. |

Las capacidades de escritura son members:invite, members:update, members:revoke e invitations:revoke; members:read habilita lectura e invitations:read la consulta de invitaciones. Sólo tenant_admin puede conceder roles de esta matriz en su tenant tras step-up. No puede otorgar permisos globales ni issuer IDs ajenos. El scope operator:read permite evaluar una credencial operator; no concede por sí solo ninguna de estas operaciones.

## Requisitos y aceptación

| ID | Comportamiento verificable | Criterio de aceptación |
| --- | --- | --- |
| USR-FR01 | Listar/buscar miembros del tenant con paginación y campos mínimos autorizados. | AC01: filtros por estado/rol y cursor sólo devuelven ese tenant; issuer_operator/support_readonly reciben denegación sin obtener directorio. |
| USR-FR02 | Crear invitación para destinatario, roles y alcance válidos. | AC02: administrador con MFA reciente crea invitación pending, expirable y de un uso. Email inválido, rol desconocido o issuer ajeno se rechazan antes del commit. |
| USR-FR03 | Aceptar invitación con identidad OIDC correcta. | AC03: token válido + sesión operator + email verificado conforme a policy del IdP crea exactamente una membership para ese tenant. Token expirado/revocado/usado o destinatario distinto falla sin revelar el invitado. |
| USR-FR04 | Consultar/revocar invitaciones y reintentar entrega sin duplicar altas. | AC04: reintento exacto reproduce resultado seguro; cambio de payload con misma key falla. Error de email conserva estado de entrega separado; nueva invitación revoca la anterior antes de activar otro token. |
| USR-FR05 | Modificar roles y alcance issuer con control de revisión. | AC05: PATCH autorizado cambia revisión y auditoría; If-Match obsoleto devuelve 412 sin cambio. El actor no puede conceder autoridad fuera del tenant/matriz. |
| USR-FR06 | Suspender/reactivar/revocar membership. | AC06: active↔suspended; active/suspended→revoked. Revoked es terminal; reingreso requiere invitación nueva bajo policy sin restaurar permisos implícitos. No se elimina identidad global. |
| USR-FR07 | Conservar un tenant_admin activo. | AC07: dos transacciones que intentan quitar/suspender a los últimos administradores no dejan el tenant sin ninguno. Auto-reducción permitida sólo si queda otro activo; solicitud imposible devuelve 409. |
| USR-FR08 | Aplicar cambios de acceso en peticiones siguientes. | AC08: tras commit, /me y cada API revalidan membership/revisión. Sesión de contexto revocado se invalida o vuelve al selector sin afectar accesos independientes a otros tenants. |
| USR-FR09 | Auditar mutación y publicación transaccionalmente. | AC09: audit/outbox registran actor, target opaco, acción, resultado y correlación; fallo de commit no deja membership sin evidencia. No se guardan enlaces/códigos en logs. |
| USR-FR10 | Mostrar estados y errores accionables. | AC10: tablas vacías/cargando/error/forbidden, invitación pendiente/fallida/expirada y conflicto de revisión tienen salida clara; revocar exige confirmar objetivo y razón. |

## Estados y datos

Invitación: pending→accepted/revoked/expired. deliveryState es independiente: queued/sent/failed; sent indica aceptación del proveedor, no lectura ni aceptación del usuario.

Membership: active/suspended/revoked. Roles y conjunto de issuers autorizados tienen revisión; revoked es terminal por lifecycle. Una invitación posterior a la revocación puede abrir un lifecycle nuevo en la misma membership lógica, conservando membershipId, identidad y revisiones monotónicas, con sólo los grants nuevos e historial previo inmutable. No elude suspended. Semántica y condiciones en el [contrato USR-T01](../../03-design/console-members-contract.md) y [ADR-0011](../../decisions/ADR-0011.md).

Datos mínimos: tenantId, membershipId, operatorIdentityId, roles, issuerIds, state, revision y fechas; invitación añade destinatario, token hasheado, expiración, roles/alcance propuestos y deliveryState. Email se protege con cifrado/retención y no funciona como primary key de identidad.

El token de aceptación viaja sólo por canal seguro al destinatario. Si hace falta material recuperable para la entrega, el worker usa envelope cifrado de vida limitada, separado del registro de hash y purgado tras entrega/expiración. La lista/API no devuelve enlaces ni tokens crudos. El cliente elimina el token de la URL antes de analytics; el borde redacta la ruta/query y el formulario usa Referrer-Policy restrictiva.

## Restricciones de calidad

| ID | Restricción | Verificación |
| --- | --- | --- |
| USR-QR01 | Aislamiento en API/repositorio/RLS y reautorización antes de replay idempotente. | Dos tenants, actor degradado y IDs/cursor adivinados no filtran datos. |
| USR-QR02 | Mutaciones bajo transacción/revisión, con rol runtime no propietario. | Carreras de invitación/último admin y pool reuse. |
| USR-QR03 | Formulario/tabla/confirmación accesibles y sin falsos éxitos. | Teclado, foco, errores asociados y 412 recuperable sin perder edición. |
| USR-QR04 | Retención y expiración configuradas; sin duplicar secretos/PII en auditoría. | Reloj falso, inspección de DB/logs/entregas y prueba de purga. |

## Procedencia y decisiones

Fundamentos: [arquitectura tenant/membership](../../03-design/hukid-architecture.md), [roles y seguridad](../../04-engineering/hukid-security-and-operations.md), [modelo](../../03-design/hukid-data-model.md), [HK-001/005](../../02-requirements/backlogs/team-5-hukid.md).

El detalle de invitaciones/matriz/último admin es propio de consola; no se importa de Events. USR-T01 concreta unicidad/reinvitación, políticas email, TTL, permisos y OpenAPI en la referencia enlazada. USR-T04 implementará el canal sintético y USR-T05 la evidencia email verificada del IdP. Estas decisiones técnicas no justifican ampliar permisos globales ni afirman que esas integraciones existan.
