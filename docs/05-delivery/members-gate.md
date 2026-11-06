# Gate U4 de miembros — USR-T09

Fecha: 2026-11-06. Owner: Team 5. Alcance: AUTH y USR-T01–T09 en laboratorio Windows aislado, con PostgreSQL real, API/BFF y dos identidades OIDC sintéticas. El [runbook](../04-engineering/console-members-runbook.md) mantiene la operación. El perfil HukID permanece v0.1-draft.

## Criterio de cierre y reproducción

Ejecutar `npm run test:members:gate` con los requisitos de [desarrollo local](../04-engineering/local-development.md). Reutiliza el runner AUTH: check, build, test:postgres, smoke y test:browser, secuenciales y sin reutilizar resultados previos. Incluye la regresión de autenticación y las doce operaciones USR implemented-test. El primer fallo detiene el gate. Un cambio de fuentes durante la ejecución invalida el resultado.

El informe ignorado `.cache/members-gate/latest.json` contiene HEAD, dirty, digest SHA-256 de fuentes versionadas/no ignoradas, versión Node, tiempos y códigos de salida. No contiene logs, entorno ni secretos. HEAD identifica la base si dirty=true; el digest identifica las fuentes evaluadas. El [workflow](../../.github/workflows/authentication.yml) ejecuta el mismo comando. Una ejecución local no prueba GitHub Actions remoto. El comando AUTH anterior conserva su informe independiente.

## Matriz de aceptación

Los tests Go citados están en [PostgreSQL/HTTP](../../src/platform/internal/adapters/postgres); contratos en [tests/auth](../../tests/auth); la suite [Chromium](../../tests/browser/authentication.py) ejecuta también el journey de miembros. La [especificación](../features/FEAT-002-user-management/spec.md) mantiene el texto normativo de AC/QR.

| Criterio | Evidencia ejecutada por el gate | Límite |
| --- | --- | --- |
| AC01 / QR01 | TestDirectoryReadIsolationFiltersAndLivePermissions; TestDirectoryInvitationEffectiveExpiryAndMinimalProjection; negativos HTTP. | Máscara fija de destinatario; cursor no promete snapshot entre páginas. |
| AC02 | TestInvitationCommandsReplayReplacementRevocationAndReauthorization; HTTP/Chromium. | MFA sintética; asignación issuer no vacía falla cerrada con 503 sin ownership confiable. |
| AC03 | TestAcceptanceIdentityOneUseAndLiveReplay; TestAcceptanceConcurrentAndAtomicRollback; TestAcceptanceExpiredRevokedExistingAndInactive. | Email verificado de ID token sintético validado; refresh descarta evidencia. |
| AC04 | TestInvitationAtomicEvidenceAndConcurrentCommands; TestInvitationDeliveryFailureRetryCrashDedupAndRetention; TestInvitationDeliveryRevocationDuringProviderAndCorruptEnvelope. | Proveedor falso con recibos duraderos; sent no significa aceptación. |
| AC05 | TestMembershipAuthorizationScopeAndAtomicRollback; TestMembershipLifecycleETagReplayAndHistory; HTTP y recuperación 412 en Chromium. | No acredita ownership/operación de issuers. |
| AC06 | TestMembershipPatchRevocationThenInvitationReentry; TestAcceptanceReentryAndOldInvitationCutoff. | Conserva identidad/membership e historial; reingreso sólo con grants nuevos. |
| AC07 / QR02 | TestMembershipConcurrentLastAdministrators; TestMembershipLockAndCancelledCommand; tests RLS/upgrade/pool reuse. | Carreras reales con conexiones independientes en laboratorio; sin benchmark/SLO. |
| AC08 | TestMembershipChangesReconcileSessionsAcrossTenants; TestContextReconciliationCASLeaseRotationAndFailure; TestRefreshAndStepUpRotationCannotRestoreLostContext. | Reconciliación al leer; no cancela peticiones ya autorizadas antes del commit. |
| AC09 | Rollbacks de creación, aceptación y PATCH; TestMembersGateRetentionAtomicityIsolationAndEvidence. | Audit/outbox atómicos; no hay publisher, visor ni SIEM desplegados. |
| AC10 / QR03 | Journey Chromium: entrega por worker, aceptación, roles, lifecycle, confirmación, teclado/foco y recuperación 412. | Negativos MFA/503 de UI inyectados; no certificación WCAG/lector físico. |
| QR04 | TestMembersGateRetentionAtomicityIsolationAndEvidence; tests de entrega/retención, redacción HTTP y navegador. | Purga explícita por tenant, sin scheduler/SLA ni retención institucional aprobada. |

## Ensayo de retención y evidencia

La prueba de USR-T09 usa reloj controlado y dos tenants. Inyecta rechazo de INSERT en auditoría y outbox separadamente: tanto la expiración con eliminación de envelopes/keys como la redacción posterior del destinatario deben revertir sin cambios parciales. Tras retirar el fallo, comprueba el microsegundo anterior al deadline y la igualdad exacta, las cuatro columnas de destinatario vacías, secretos/keys eliminados, hash conservado y tenant B intacto. Repetir no duplica eventos. Verifica correspondencia audit/outbox, actor, target, resultado, correlación y ausencia de email/código en la evidencia.

Los escenarios previos completan las carreras, replay reautorizado y fallo/reintento del proveedor. HTTP/Chromium inspeccionan los canales de logs/URL/HTML/storage observados; no se promete redacción de proxies, backups ni infraestructura externa.

## DoD aplicable y límites

| Requisito | Resultado |
| --- | --- |
| Actor, alcance, contrato y estados | Spec/plan/tasks y contratos propios existentes; no cambia API, permisos ni dominio. |
| Aislamiento, atomicidad y concurrencia | Suites negativas con RLS/runtime no propietario, locks, ETag, rollback y replay vivo. |
| Migraciones | Sin DDL nuevo; suite repite vacío y upgrades hasta 0010. No se migró una base existente. |
| Journey y diagnóstico | Regresión Chromium, evidencia mínima de audit/outbox y runbook con consultas agregadas. Dashboard/alertas productivos pendientes. |
| Operación y entrega | Gate reproducible local/CI y retirada documentada. CI remoto y ensayo de rollback binario/restore pendientes. |

El resultado ejecutado se registra en [tareas USR-T09](../features/FEAT-002-user-management/tasks.md#evidencia-usr-t09--2026-11-06). U4 cierra el incremento de laboratorio y permite continuar con DASH-T01; no declara completa la [DoD de producción](definition-of-done.md). Producción conserva NO-GO: ownership issuer, IdP/MFA/correo reales, HTTPS, secretos/rotación, rate limiting específico de invitaciones, scheduler/retención institucional, observabilidad/on-call, carga/SLO, backup/restore y DR. La prioridad AUTH→USR→DASH y el roadmap HK permanecen separados.
