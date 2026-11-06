# Revalidación de autorización y contexto — USR-T07

Estado: implementación de laboratorio de USR-FR08/AC08 y AUTH-FR07/09 según [ADR-0017](../decisions/ADR-0017.md). Complementa [cambios de membresías](console-members-lifecycle.md), [contexto operator](console-operator-context.md) y [sesiones](console-session-lifecycle.md).

## Autoridad efectiva

La membresía activa y sus roles, alcances issuer y authorization_revision son la autoridad local. Cada petición de contexto consulta esos datos en un único snapshot SQL, con tenant activo y RLS. Management conserva verificación Bearer y consulta local por petición; las operaciones members conservan sus comprobaciones dentro de la transacción, incluida la reautorización de replay. La revisión de sesión sólo registra lo observado, sin conceder permisos ni exigir un nuevo login por un cambio de roles.

La migración forward-only 0010 permite al runtime tenant leer scopes únicamente de la membresía activa del actor en el tenant transaccional. No permite escribir scopes, consultar invitaciones ni leer memberships ajenas. Los issuerIds de contexto dejan de ser un array siempre vacío y reflejan las asignaciones almacenadas, en el mismo snapshot que roles/revisión. No valida ownership ni permite asignar issuers: los reemplazos explícitos no vacíos siguen bloqueados como en USR-T06.

## Sesión y selector

Cada lectura protegida de sesión BFF revalida el tenant seleccionado mediante el puerto de contexto existente. Si sigue activo y cambió la revisión, persiste la revisión actual. Si la membresía está suspendida/revocada o el tenant inactivo, elimina active_tenant_id y authorization_revision. No cambia cookie, CSRF, tokens, generación, familia ni deadlines. El resto de las familias y contextos de la identidad conserva su independencia.

`GET /console/api/me` devuelve 200 con activeTenantId/context null y los tenants accesibles actuales. La pantalla AUTH existente muestra acceso pendiente cuando no quedan tenants, o el selector cuando quedan otros. No selecciona otro tenant ni vuelve a seleccionar el suspendido al reactivarlo. La selección explícita conserva Origin/CSRF, reautorización y rotación de AUTH-T07. Las API tenant-scoped siguen denegando el acceso retirado con 404; una degradación de capacidades produce 403 en las operaciones que ya no están permitidas. `/v1/operator/me` mantiene su forma de identidad/tenants; el contexto Management separado devuelve capacidades/revisión actuales.

Una invitación aceptada aparece al redescubrir tenants en /me; no cambia automáticamente la selección. La revocación no elimina identidad global ni revoca un Bearer del IdP. Una credencial vigente sigue sujeta a la membresía local en cada API.

## Persistencia y concurrencia

La reconciliación usa la credencial de sesión y el orden family→generation compartido con refresh/logout/step-up/selector. Compara generación, selección y revisión observadas antes de escribir. Lecturas concurrentes que resuelven el mismo resultado son idempotentes. Un resultado distinto más reciente requiere otra petición (503/Retry-After), sin sobrescribirlo ni revocar la familia. Cookie rotada/revocada/expirada o lease de refresh impiden la escritura. Un fallo SQL revierte la reconciliación y la lectura falla cerrada; una dependencia tenancy fallida tampoco borra el contexto.

No hay locks de sesión bajo el lock tenant de mutaciones ni llamadas al IdP bajo los locks de reconciliación. Roles/membresías y sesiones usan credenciales y transacciones separadas: la reconciliación ocurre al usar la sesión, sin fan-out ni worker de invalidación. Una rotación puede conservar una selección obsoleta, pero su siguiente lectura vuelve a validarla antes de devolver contexto o servir una operación. No se promete cancelar peticiones ya autorizadas antes del commit. El cambio original, revisión, audit y outbox siguen siendo atómicos en USR; actualizar una selección derivada no duplica ese evento de negocio.

## Validación y límites

Unitarias verifican revisión, retirada, dependencias ausentes/fallidas y fallo de persistencia. PostgreSQL real verifica cambios por el servicio USR-T06, rollback de outbox, varias sesiones y tenants, reactivación sin selección automática, revocación, CAS/lease/familia inválida, rotaciones refresh/step-up y upgrade 0009→0010 con sesión preservada, RLS y pool reuse. HTTP y Chromium verifican el retorno al selector sin exponer credenciales. La evidencia ejecutada se registra en [tareas FEAT-002](../features/FEAT-002-user-management/tasks.md).

No añade pantallas de miembros, variables ni proveedor real. USR-T08 conserva la UI administrativa y USR-T09 el gate completo. Persisten los límites de laboratorio: MFA/IdP sintéticos, ausencia de ownership issuer, correo real, carga/restore, retención institucional y producción. Reversión: detener escrituras o usar un binario compatible con el esquema expand; conservar revisiones/historia. El rollback binario no se ha ensayado y no se restablecen accesos retirados mediante SQL manual.
