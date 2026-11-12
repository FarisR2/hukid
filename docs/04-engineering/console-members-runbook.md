# Operación de miembros e invitaciones en laboratorio

Owner: Team 5. Alcance: entorno test aislado. Preparación base en [desarrollo local](local-development.md), autenticación en su [runbook](console-auth-runbook.md) y criterios en el [gate U4](../05-delivery/members-gate.md).

## Preparar y validar

1. Usar exclusivamente DB descartable loopback con `HUKID_ENV=test`; migrar hasta 0010 y provisionar con el CLI test existente. Mantener separados los runtimes AUTH, tenant y members; ninguno es owner ni BYPASSRLS.
2. Configurar AUTH y members completos según [entrega](../03-design/console-invitation-delivery.md). Mantener DSN, claves y versiones externos; nunca pegarlos en logs, issues ni comandos de diagnóstico compartidos. No sustituir claves si hay envelopes pendientes que deban procesarse.
3. Ejecutar `npm run test:members:gate`. Sólo passed con digest estable acredita ese árbol. El harness crea/detiene su propio clúster; no opera sobre una DB ya existente.
4. En un laboratorio manual, verificar login/step-up, tenant seleccionado, creación, entrega sintética, aceptación con otra identidad y actualización del contexto. Un cambio de identidad requiere evidencia nueva; canjear no selecciona tenant automáticamente.

## Entrega y purga explícitas

Con la configuración members externa del laboratorio y actor/tenant sintéticos conocidos:

```powershell
node scripts/platform.mjs worker:test <actorId> <tenantId>
```

El worker valida configuración test, credencial members y cifrado; ejecuta un lote acotado por tenant con timeout de 30 segundos. Purga antes y después del lote, entrega hasta 100 envelopes elegibles y registra resultados seguros. Repetir procesa el resto sin duplicar recibos del proveedor falso. No envía correo real ni recorre globalmente los tenants. Actor y tenant se suministran explícitamente por el mantenedor de confianza; la credencial del worker es una capacidad de servicio, no un permiso concedido a operadores del panel.

La [política test](../../src/platform/config/user-management.test.json) fija TTL invitación/key en 24 h, envelope de entrega en 1 h y destinatario cifrado en 7 días. Al alcanzar cada deadline, la siguiente ejecución elimina el material vencido. Entrega exitosa elimina inmediatamente su envelope; aceptación/revocación/reemplazo también retiran el secreto correspondiente. Una purga fallida revierte su transacción y debe reintentarse después de corregir la causa. Sin ejecución no se promete eliminación física puntual. Hashes, metadata, historial, audit/outbox y recibos no se borran con esa purga; backups/WAL tienen ciclo independiente sin validar aquí.

## Diagnóstico sin material sensible

Ejecutar estas consultas sólo como mantenedor autorizado de la DB test. Los runtimes no reciben permiso de lectura de auditoría por este runbook. Sustituir `$1` por un parámetro tenant UUID enlazado en la herramienta SQL; nunca concatenar entrada del navegador.

```sql
SELECT state, delivery_state, count(*)
FROM tenancy.invitations WHERE tenant_id=$1
GROUP BY state, delivery_state;

SELECT count(*) AS envelopes_vencidos
FROM tenancy.invitation_delivery_secrets
WHERE tenant_id=$1 AND delete_after<=now();

SELECT count(*) AS destinatarios_vencidos
FROM tenancy.invitations
WHERE tenant_id=$1 AND recipient_hmac IS NOT NULL
  AND recipient_delete_after<=now();

SELECT a.action, a.outcome, count(*)
FROM platform.audit_events a
WHERE a.tenant_id=$1 AND a.action LIKE 'members.%'
GROUP BY a.action, a.outcome;

SELECT count(*) AS eventos_sin_outbox
FROM platform.audit_events a
LEFT JOIN platform.outbox_events o USING(event_id)
WHERE a.tenant_id=$1 AND a.action LIKE 'members.%' AND o.event_id IS NULL;
```

| Señal | Acción |
| --- | --- |
| 403 por rol/MFA | Releer contexto y obtener step-up válido; no cambiar permisos para forzar replay. |
| 412 | Cargar revisión actual, comparar propuesta y confirmar de nuevo. |
| 409 último administrador | Conservar otro administrador activo antes de reducir acceso. |
| deliveryState=failed | Repetir worker mientras el envelope siga vigente; errores internos del proveedor no se muestran. |
| Envelope vencido o invitación expirada | Crear invitación nueva autorizada; no reconstruir tokens desde hashes. |
| 503, fallo worker o evidencia incoherente | Detener escrituras/worker del laboratorio y revisar configuración/DB/locks; reintentar sólo tras corregir la causa. |
| Destinatarios/envelopes vencidos presentes | Ejecutar lote explícito por tenant y revisar su resultado; no borrar evidencia manualmente. |

## Retirada y recuperación

Detener API y worker propios antes de modificar su configuración. Para retirar sólo USR, quitar `HUKID_MEMBERS_DATABASE_URL`, `HUKID_MEMBERS_POLICY`, `HUKID_MEMBERS_CURSOR_KEY` y las tres variables `HUKID_INVITATION_KEY`, `HUKID_INVITATION_HMAC_KEY`, `HUKID_INVITATION_KEY_VERSION`; arrancar con AUTH completo. Comprobar que health/AUTH funcionan y que ambos transportes USR quedan deshabilitados. Las unitarias de configuración validan rechazo de configuración members parcial; smoke cubre arranque AUTH cerrado. Este procedimiento USR no acredita un rollout productivo. Para retirar también AUTH, seguir su runbook e invalidación offline test.

Conservar esquema, historial, recibos y hashes; no restaurar tokens anteriores ni reactivar memberships revocadas mediante SQL. Reactivar con el mismo esquema/binario compatible y configuración completa; releer contexto y obtener login/step-up cuando proceda. Una revocación durante entrega prevalece localmente, pero no retira un mensaje ya aceptado por el proveedor. Este procedimiento no acredita rollback a binario anterior, restore, rotación multiversión, drenado por señales ni revocación de grants del IdP.
