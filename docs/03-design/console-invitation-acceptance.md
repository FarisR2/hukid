# Aceptación y reingreso de laboratorio — USR-T05

Referencia para backend y operación local de [FEAT-002](../features/FEAT-002-user-management/spec.md), según [ADR-0015](../decisions/ADR-0015.md). Extiende el [contrato de miembros](console-members-contract.md) y las [invitaciones/entrega USR-T04](console-invitation-delivery.md).

## Rutas y evidencia

POST /v1/operator/invitation-acceptances recibe exclusivamente token en JSON y una Idempotency-Key contractual. Exige Bearer operator verificado y evidencia email obtenida por este servidor. POST /console/api/invitation-acceptances usa cookie y Origin/CSRF vigentes, además del access token cifrado del BFF. Ninguna exige membership previa, capacidad de directorio ni tenant seleccionado. Devuelven 200 con tenantId, membership y ETag; no cambian el contexto seleccionado ni emiten una nueva cookie.

El perfil test solicita email. El ID token de login/step-up debe superar Code/PKCE, nonce, firma, issuer, audience, tiempos y binding al mismo issuer/subject del access token. Sólo email_verified=true booleano produce evidencia. El destinatario se conserva dentro de SessionSecrets cifrado, sin nuevo directorio de email. Un índice access_hash permite recuperar una sesión/generación activa para esa credencial, comprobar actor/identidad y descifrar la evidencia. Nunca se obtiene autoridad de un ID token/email en body o de un claim email del access token.

La emisión y auth_time del ID token deben estar en el pasado y tener edad menor que emailEvidenceSeconds; también debe seguir vigente exp. No añadir skew al deadline local. Cambiar tenant conserva la evidencia original sin renovarla. Refresh la descarta; para aceptar después hace falta login o step-up Code/PKCE nuevo. Una sesión antigua sin evidencia devuelve 403 recipient_unverified. La falta de evidencia se rechaza antes de localizar el token.

## Canje transaccional

La migración [0009](../../src/platform/internal/adapters/postgres/migrations/0009_invitation_acceptance.sql) añade access_hash y un localizador restringido de tenant por hash completo del token. No da acceso global a filas de invitaciones al runtime. Su rol separado no propietario no se puede heredar desde una credencial runtime. La función tiene search_path fijo y no es ejecutable por PUBLIC; sólo devuelve un UUID de tenant o NULL.

El servicio acepta tokens base64url canónicos de 32 bytes; persiste sólo digest y huellas. Después de localizar tenant, usa la credencial members con RLS y try-lock advisory común de USR-T02/T04. La contención devuelve 409 operation_in_progress y Retry-After: 1. Bajo lock vuelve a comprobar tenant activo, deadlines, invitación pending y HMAC tenant/email normalizado. Revalida roles; issuerIds no vacíos fallan cerrados sin ownership confiable.

Sin membership crea active/lifecycle=1/revision=1. Active o suspended devuelve 409 membership_exists sin modificar grants ni consumir el token. Para revoked exige createdAt de invitación posterior al revoked_at vigente y bindings opcionales coincidentes. Exige archivo del lifecycle revocado, conserva membershipId, incrementa lifecycle/revision, elimina grants actuales e instala sólo los nuevos. No modifica identidad ni acceso a otros tenants.

Aceptación, referencia idempotente, revisión de invitación, eliminación del envelope de entrega, evento members.invitation.accepted y outbox se confirman juntos. Reingreso añade members.membership.reentered en esa misma transacción. Un fallo de auditoría/outbox revierte el conjunto. La lectura /me descubre la membership nueva; seleccionar contexto sigue siendo un comando AUTH independiente.

## Replay y errores

La key se acota por actor, operación y digest del token. Replay exacto vuelve a validar evidencia/email y consulta la membership vigente, sin requerir que el token consumido siga pending. Devuelve los mismos IDs y la representación actual; no duplica eventos. Suspensión devuelve membership_exists; revocación o cambio de lifecycle devuelve membership_revoked. Otra key para token consumido devuelve invitation_invalid. Tras vencer/purgar la huella no se restablece el token.

Token desconocido, expirado, revocado, reemplazado o de destinatario distinto comparte 409 invitation_invalid sin revelar email/tenant del invitado. Forma de token inválida devuelve 422 invalid_input. JSON/headers y ambos transportes conservan los controles USR-T04: límites, campos estrictos, correlación, no-store y no-referrer. El token sólo viaja en body y no se copia a errores, auditoría, outbox ni logs propios.

## Operación y verificación

Aplicar migraciones con el CLI test antes de arrancar el binario nuevo, usando [desarrollo local](../04-engineering/local-development.md). Mantener configuración AUTH/members y las claves de invitaciones de USR-T04; no hay variables nuevas. Usar la política AUTH actualizada con scope email y un intercambio nuevo. No reutilizar evidencia de una sesión anterior ni enviar un ID token manualmente al endpoint.

Para retirar las escrituras, quitar la configuración de secretos de invitación y detener su worker según USR-T04. Mantener 0009, memberships, archivo, hashes y recibos. No revertir datos ni restaurar tokens consumidos. La nueva columna es nullable y conserva las sesiones preexistentes; éstas siguen autenticando según AUTH, pero necesitan intercambio nuevo para aceptar.

Ejecutar npm run check, npm run test:postgres, npm run build y npm run smoke. Las [unitarias OIDC](../../src/platform/internal/adapters/oidc/recipient_test.go) y [de sesión](../../src/platform/internal/authentication/recipient_test.go) prueban origen/tipo/binding/deadlines de evidencia. Las [pruebas PostgreSQL](../../src/platform/internal/adapters/postgres/acceptance_integration_test.go) cubren un uso, carreras, replay vivo, reingreso/corte histórico, rollback, upgrade y separación de roles. La [integración HTTP](../../src/platform/internal/adapters/postgres/login_integration_test.go) recorre Management/BFF con API, IdP y DB propios, sin UI nueva. Resultados efectivos en [tareas](../features/FEAT-002-user-management/tasks.md).

Siguiente: USR-T06, edición de roles/estado con ETag y lock tenant. USR-T07 conserva integración completa de invalidación; USR-T08 aporta UI; USR-T09 su gate/operación. Sin factores/proveedor ni email real, rate limiting específico de aceptación, carga/restore, fuente ownership issuer o producción. La futura UI debe retirar el fragmento del historial antes de analytics y no persistir tokens en storage JS, conforme al contrato.
