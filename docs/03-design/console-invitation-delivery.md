# Invitaciones y entrega de laboratorio — USR-T04

Referencia para backend y operación local de [FEAT-002](../features/FEAT-002-user-management/spec.md). Implementa creación/revocación y entrega sintética sobre el [contrato](console-members-contract.md), la persistencia 0007 y [ADR-0014](../decisions/ADR-0014.md). No implementa aceptación, evidencia email del IdP, edición de miembros ni UI.

## Rutas y autorización

| Operación | Resultado |
| --- | --- |
| POST /v1/operator/tenants/{tenantId}/invitations | 201 con representación segura y ETag; members:invite y MFA reciente. |
| POST /v1/operator/tenants/{tenantId}/invitations/{invitationId}/revocations | 200 con representación segura y ETag; invitations:revoke, MFA reciente e If-Match. |
| Las dos rutas equivalentes bajo /console/api | Misma operación, con cookie, Origin exacto, X-CSRF-Token vigente y tenant seleccionado. |

Management verifica el token operator y obtiene de evidencia firmada un deadline igual al mínimo de expiración del token y auth_time+stepUpSeconds. Después de tomar el lock transaccional del tenant, vuelve a consultar membership/tenant/capacidad y compara ese deadline con el reloj local. Así no mantiene locks durante OIDC/JWKS. El BFF además liga el actor verificado al de la sesión. RLS y la credencial members separada no sustituyen estas comprobaciones.

JSON estricto de 16 KiB: propiedades requeridas, sin duplicados, null, extras, query ni contenido posterior. Content-Type debe ser application/json sin parámetros. Idempotency-Key respeta el contrato. La revocación exige una revisión fuerte; sin header devuelve 428, forma inválida 400, revisión obsoleta 412 y transición no pendiente 409. Los errores son Problem Details seguros; todas las respuestas añaden no-store, no-referrer y correlación.

El lock es el mismo advisory lock por UUID normalizado de USR-T02. Un control inicial de pertenencia/capacidad/MFA evita revelar contención de un tenant ajeno; no autoriza el commit y se repite bajo lock. Los comandos usan try-lock: si otro escritor posee el tenant devuelven 409 operation_in_progress y Retry-After: 1. Esta respuesta puede ocurrir también entre comandos de distinta key del mismo tenant. No hay segundo efecto concurrente.

## Creación, replay y reemplazo

La huella canónica normaliza únicamente el dominio email y ordena roles/issuerIds. Para revocar incluye ID, reasonCode e If-Match. Se guardan hashes de key/request y referencia a la invitación, nunca body o respuesta JSON. Reautorizar precede al replay; el replay confirmado precede a comparar la revisión actual. Devuelve los mismos IDs con estado efectivo y ETag vigente, sin generar token ni duplicar eventos.

La creación genera UUID aleatorio y token CSPRNG de 32 bytes base64url, conservando sólo SHA-256 del token. Cifra email y payload de entrega mediante AES-256-GCM con nonce independiente, key version y AAD hukid:invitation:v1:tenant:invitation:propósito. Un HMAC con clave distinta y tenant ligado deduplica destinatarios. El API nunca devuelve email, token, enlace, hashes o envelopes; recipientHint mantiene la máscara fija de USR-T03.

Una key nueva para el mismo destinatario revoca o materializa la expiración de la pending anterior, elimina su envelope y crea otro token, bajo una sola transacción. Cada transición añade su evento/outbox. La revocación explícita elimina también el secreto. Fallo de audit/outbox revierte invitación, reemplazo, fingerprints y secretos juntos. No se infiere identidad por email. Los grants issuer no vacíos devuelven 503 hasta disponer de ownership confiable.

## Worker y proveedor sintético

[InvitationWorker](../../src/platform/internal/tenancy/invitations.go) ejecuta un lote explícito actor/tenant: purga, recupera hasta cien envelopes elegibles, descifra y comprueba el hash del token, llama al puerto NotificationProvider fuera del lock y confirma el resultado bajo el lock del tenant. Vuelve a purgar al finalizar. Un envelope vencido/corrupto no se entrega. Error del proveedor registra deliveryState=failed y un evento cerrado sin copiar su mensaje; la invitación sigue pending. Un reintento usa la misma generación, token y deadline.

[SyntheticNotifications](../../src/platform/internal/adapters/postgres/invitation_delivery.go) simula aceptación del proveedor; no envía correo ni almacena una bandeja de mensajes. La migración [0008](../../src/platform/internal/adapters/postgres/migrations/0008_invitation_delivery.sql) añade recibos duraderos tenant/invitación/generación con digest del payload y fecha. No guarda PII ni material recuperable. Su RLS fuerza tenant, usa el runtime members y conserva el esquema AUTH. El digest incluye el token aleatorio; no es un hash de email aislado.

El proveedor vuelve a comprobar tenant/invitación/deadline al registrar el recibo. Una caída después de su aceptación y antes del commit local reintenta contra el mismo recibo sin duplicar entrega, incluso con una nueva instancia del adaptador. sent sólo confirma aceptación sintética: nunca aceptación por el usuario.

Una revocación concurrente no puede retirar un mensaje que un proveedor ya aceptó. Al regresar del proveedor, el store no cambia a sent una invitación que dejó de ser elegible ni revive su token. Si el secreto vence con resultado incierto, no se reconstruye desde hash: se necesita una invitación nueva. Un adaptador externo futuro debe proporcionar deduplicación duradera equivalente; no basta un mapa en memoria.

## Purga y operación

Los TTL siguen la política test, sin defaults nuevos. El secreto desaparece tras sent, revocación/reemplazo, aceptación almacenada o su deadline. La purga materializa pending vencidas y elimina envelopes, fingerprints vencidos y las cuatro columnas de destinatario al deadline de retención. Conserva token hash, metadata, historial, audit/outbox y recibos del proveedor. Expirar el secreto de entrega por sí solo no cambia el estado de aceptación ni deliveryState. No hay scheduler, SLA de retención, rotación/múltiples versiones de claves ni transporte productivo.

La ejecución y variables están en [desarrollo local](../04-engineering/local-development.md#worker-de-invitaciones-usr-t04). El operador CLI aporta IDs confiables de laboratorio; la credencial de mantenimiento no se entrega al navegador. El lote no enumera tenants globalmente. El mantenimiento usa el mismo lock y evidencia, incluso para purgar un tenant inactivo. El alcance por tenant aún requiere medición y límites de carga antes de producción.

Rollback: retirar las tres variables de secretos de invitación deshabilita las cuatro rutas nuevas, conservando las lecturas existentes. Detener el worker, mantener 0008 y los datos; no reactivar tokens previos ni borrar recibos para reintentar. Al volver a habilitar hay que conservar las mismas claves: sustituir HMAC sin protocolo de rotación impediría deduplicar destinatarios anteriores.

## Evidencia y continuación

[Pruebas PostgreSQL](../../src/platform/internal/adapters/postgres/invitations_integration_test.go) cubren replay/reautorización, reemplazo/revocación, revisión, locks/concurrencia, rollback de evidencia, cifrado, entrega fallida/reintento/caída, deduplicación persistente, purga temporal y revocación durante entrega. La [integración HTTP](../../src/platform/internal/adapters/postgres/login_integration_test.go) usa API, IdP y DB propios para ambas superficies y sus controles. Las pruebas OIDC comprueban freshness/deadline firmados; configuración rechaza claves parciales, productivas o compartidas. Comandos y resultados efectivos en [tareas](../features/FEAT-002-user-management/tasks.md).

USR-T05 debe integrar email verificado, lookup seguro del token y canje/reingreso. USR-T06/T07 gestionan miembros y revalidación; USR-T08 la interfaz; USR-T09 el gate, rate limiting específico y operación. El roadmap HK y el perfil draft conservan sus pendientes.
