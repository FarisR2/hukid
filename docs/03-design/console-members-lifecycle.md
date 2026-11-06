# Cambios de membresías — USR-T06

Estado: implementación de laboratorio de los dos PATCH definidos en el [contrato de miembros](console-members-contract.md), según [ADR-0016](../decisions/ADR-0016.md). No cambia el schema público ni añade migraciones, credenciales o variables. Continúa usando la persistencia y RLS de 0007 y la configuración USR-T04/T05.

## Superficies y entrada

Management: `PATCH /v1/operator/tenants/{tenantId}/memberships/{membershipId}`. BFF: ruta equivalente bajo `/console/api`, con cookie, Origin/CSRF y tenant seleccionado. Management verifica Bearer operator y evidencia MFA firmada; ambos transportes resuelven identidad server-side y comparten servicio/transacción. El token nunca se entrega al navegador.

La entrada reemplaza roles/issuerIds juntos y/o cambia state, siempre con reasonCode cerrado. Rechaza campos desconocidos, duplicados, null, JSON posterior, parámetros query, tipo alternativo, grants parciales y patches vacíos. If-Match exige una revisión fuerte; ausencia 428, forma inválida 400, revisión obsoleta 412. Idempotency-Key conserva los límites del contrato. La respuesta mínima incluye ETag vigente, no-store, no-referrer y correlación opaca.

## Transacción y concurrencia

Con credencial members separada, RLS aísla el tenant. Antes de consultar contención se comprueban tenant/membership activos, members:update y MFA; revocar exige también members:revoke. Después de adquirir el try-lock transaccional común del UUID tenant, se repite autorización/MFA. Contención devuelve 409 operation_in_progress y Retry-After. No se hace I/O externo bajo lock.

La huella liga operación membership.change, actor/tenant, target, JSON canónico y revisión. Ordenar conjuntos no cambia el replay. Una key con otro target/body/revisión produce 409 idempotency_conflict. Replay reautorizado se resuelve antes de comparar la revisión actual y devuelve la proyección vigente y su ETag, sin repetir eventos ni incrementar revision. Auto-reducción puede impedir el replay posterior si el actor perdió autoridad.

Para un cambio nuevo se resuelve el target dentro del tenant, se compara revisión, se comprueba terminalidad y se cuentan tenant_admin activos bajo el mismo lock que aceptación e invitaciones. Auto-reducción sólo procede si queda otro administrador activo. Degradar roles, suspender o revocar al último produce 409 last_admin_required. Revoked es terminal para PATCH; reingreso requiere invitación posterior a revoked_at y el archivo de lifecycle de [USR-T05](console-invitation-acceptance.md).

active y suspended pueden alternarse preservando grants si no se pide reemplazo. Una escritura válida que repite valores también incrementa authorization_revision. El lifecycle sólo cambia por reingreso. Revocación fija revoked_at y archiva los grants finales de ese lifecycle en la misma transacción; ningún runtime puede reescribir ese historial. Mutación, idempotencia, auditoría y outbox confirman juntos. Una falla revierte también roles, revision e historial. MFA se comprueba nuevamente antes de escribir evidencia. reasonCode se valida y participa en la huella; el envelope de auditoría existente conserva actor, target, acción, resultado y correlación, sin texto libre.

## Alcance issuer y límites

No existe fuente confiable de ownership issuer. Un reemplazo explícito con issuerIds no vacío devuelve 503 dependency_unavailable sin conceder ningún issuer, incluido uno ajeno. No se inventan emisores ni se confía en ownership enviado por cliente. Cambios sólo de estado preservan los grants almacenados; retirar issuer_operator junto con todos sus issuerIds sí es posible. Esto no habilita emisión ni grants de integración.

USR-T07 conserva la invalidación/reconciliación completa del contexto y sus pruebas entre tenants. USR-T06 incrementa la revisión y usa autorización viva, sin borrar identidad global, familias ni accesos de otros tenants. USR-T08 conserva UI, confirmaciones y recuperación visual de 412; no hay pantalla nueva. USR-T09 conserva el gate completo. Factores/IdP/entrega son sintéticos; sin producción, proveedor issuer, correo real, carga/restore ni retención institucional.

## Verificación y reversión

Las pruebas Go cubren validación/fingerprints y el guard puro. PostgreSQL real cubre lifecycle, replay, grants, archivo, RLS, roles/MFA, fallos de audit/outbox, cancelación y carreras de dos administradores con conexiones independientes. HTTP real cubre ambas superficies y sus precondiciones/errores. La evidencia ejecutada se registra en [tareas FEAT-002](../features/FEAT-002-user-management/tasks.md).

Reversión operativa: detener escrituras o volver al binario previo compatible con el mismo esquema; conservar memberships, revisiones, archivo y evidencia. Una revocación confirmada no se revierte con UPDATE manual; seguir el flujo de invitación/reingreso. No se ha ensayado rollback binario ni restore.
