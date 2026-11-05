# Contrato de miembros e invitaciones — USR-T01

Estado: baseline de contrato y reglas puras validables para laboratorio; USR-T02 añade [persistencia/RLS/transacciones](console-members-persistence.md). No hay handlers ni pantallas de miembros. [ADR-0011](../decisions/ADR-0011.md) adopta este corte de [FEAT-002](../features/FEAT-002-user-management/spec.md). AUTH-T01–T10 mantienen su comportamiento y sus límites productivos.

## Artefactos y autoridad

| Artefacto | Responsabilidad |
| --- | --- |
| [OpenAPI propio](../../src/platform/contracts/console-members.openapi.json) | Doce operaciones, seis Management y seis BFF, todas `contract-only`. No sustituye el OpenAPI histórico ausente. |
| [Schemas compartidos](../../src/platform/contracts/user-management.schema.json) | Requests, membership, invitación, páginas y Problem Details estrictos; OpenAPI referencia esta fuente. |
| [Matriz única](../../src/platform/contracts/capabilities.json) | Conserva los cuatro roles y capacidades de AUTH, sin ampliar sus grants. |
| [Política test](../../src/platform/config/user-management.test.json) y [schema](../../src/platform/contracts/user-management-policy.schema.json) | Valores explícitos de expiración/retención y perfil email; no son política institucional. |
| [Reglas Go](../../src/platform/internal/tenancy/membership_rules.go) | Carga/relaciones de política, email, deadline, grants y guard de último administrador/revisión/terminalidad. Sin acceso DB, verificación JWT ni autorización HTTP. |
| [Tests de contrato](../../tests/auth/members-contracts.test.mjs) y [unitarias Go](../../src/platform/internal/tenancy/membership_rules_test.go) | Schemas/ejemplos, seguridad declarada, permisos, negativos y límites puros. No demuestran concurrencia ni aceptación real. |

## Superficies y permisos

El navegador usa las rutas equivalentes bajo `/console/api`; no transporta Bearer. Management usa `/v1/operator`, exige firma/clase/audience/grant humano y scope `operator:read` según [AUTH](console-auth-contract.md). Ese scope sólo hace elegible la credencial: las capacidades locales, pertenencia y MFA deciden la operación. No se introduce `operator:write` ni se altera la emisión de scopes del IdP test.

| Operación Management | Capacidad local | Evidencia adicional |
| --- | --- | --- |
| GET /tenants/{tenantId}/memberships | members:read | Tenant y membership activos; security_admin puede leer. |
| GET /tenants/{tenantId}/invitations | invitations:read | Sólo tenant_admin con la matriz actual; security_admin no obtiene destinatarios. |
| POST /tenants/{tenantId}/invitations | members:invite | MFA reciente, Idempotency-Key. |
| POST /tenants/{tenantId}/invitations/{invitationId}/revocations | invitations:revoke | MFA reciente, Idempotency-Key, If-Match. |
| PATCH /tenants/{tenantId}/memberships/{membershipId} | members:update; además members:revoke si state=revoked | MFA reciente, Idempotency-Key, If-Match y guard de último admin. |
| POST /invitation-acceptances | Ninguna capacidad/directorio previo | Operador válido, prueba de destinatario y token de invitación. |

MFA reciente significa `VerifyPrivilegedOperator` y freshness de [AUTH-T07](console-reauthentication.md); refresh no renueva auth_time. BFF aplica las mismas reglas desde la sesión y el access token custodiado. POST/PATCH BFF exigen cookie, Origin exactamente configurado y X-CSRF-Token de la generación vigente, incluso para aceptación sin tenant seleccionado. No se confía en tenant/roles/issuerIds del navegador como autoridad.

Todo tenant de ruta es selector de recurso. Validar membership viva y tenant activo antes de consultar el directorio o devolver replay; recurso ajeno/inactivo se oculta con 404. Actor sin capacidad en su tenant recibe 403. issuer_operator y support_readonly no leen directorios. Las nueve rutas AUTH existentes no se modifican al materializar este contrato.

## Datos y edición

Membership expone sólo tenantId, membershipId, operatorIdentityId, roles, issuerIds, state, revision, lifecycle, createdAt y updatedAt. No expone email global, subject, tokens ni claims. La identidad canónica continúa siendo `(oidc_issuer, subject)`; no hay segundo registro users ni fusión por correo.

Roles contienen de uno a cuatro elementos distintos de la matriz. issuerIds es un conjunto de hasta cien UUID canónicos minúsculos. Si hay issuer_operator se exige al menos uno, verificado como perteneciente al tenant por una fuente confiable; sin ese rol se exige `[]`. En combinaciones de roles, el alcance limita sólo las acciones issuer concedidas por ese rol: nunca concede emisión ni autoridad global. Si no existe fuente de propiedad/asignación issuer, rechazar sin conceder; no inventar emisores para satisfacer el schema. USR-T02 debe coordinar esa fuente antes de habilitar grants no vacíos; su indisponibilidad devuelve 503.

PATCH permite state y/o reemplazo completo de roles más issuerIds; estos dos últimos deben viajar juntos. reasonCode es obligatorio, cerrado y sin texto libre/PII. Ausencia de cambio solicitado es 422. Una escritura válida, incluso si repite valores, incrementa revision y escribe evidencia; un replay de la misma key no vuelve a incrementar. Los límites enteros son seguros para JavaScript.

Respuesta individual de invitación/membership incluye ETag fuerte `"<revision>"`; los items de lista incluyen revision. If-Match sólo acepta una revisión fuerte, sin wildcard, lista ni prefijo débil. Falta devuelve 428, forma inválida 400 y revisión desactualizada 412 sin efecto parcial. Se compara dentro de la transacción, después de autorizar. No se anuncia un cambio hasta confirmar commit/audit/outbox.

Invitación expone tenantId, invitationId, recipientHint enmascarado, roles, issuerIds, state, deliveryState, revision y fechas. Nunca email completo, token, enlace, hash o envelope. recipientHint puede convertirse en `redacted` tras purga. pending→accepted/revoked/expired; acceptedAt y revokedAt son coherentes con state. Expiración es efectiva aunque el worker aún no haya materializado expired; una lectura devuelve el estado efectivo. deliveryState queued/sent/failed es independiente: sent sólo confirma aceptación del proveedor, incluso si luego se revocó la invitación.

## Email e identidad del destinatario

Perfil de laboratorio `ascii-case-sensitive-local-v1`: email ASCII dot-atom, local de 1–64 bytes, total máximo 254, dominio con etiquetas de hasta 63 caracteres y al menos un punto. Rechazar espacios, controles, nombres de presentación, literales IP, Unicode y local entre comillas. No recortar silenciosamente ni eliminar puntos/sufijos `+`. Convertir sólo el dominio a minúsculas; preservar el local exactamente. Dos variantes de mayúsculas del local son distintos destinatarios en este perfil conservador.

El schema verifica forma; Go verifica además límites y normalización. Una coincidencia de texto no prueba propiedad del correo. Para aceptar, el adaptador OIDC de USR-T05 debe producir evidencia server-side de un ID token validado en un intercambio Code/PKCE nuevo, ligado por nonce al mismo issuer/subject de la sesión, con audience del cliente, firma/tiempos válidos, email y `email_verified=true` booleano. Exigir auth_time y emisión de evidencia recientes dentro de emailEvidenceSeconds; ni body ni ID token arbitrario enviado por navegador son evidencia. No usar access tokens de otro propósito, un claim no verificado, un dominio supuesto ni cache global de email.

La política permite sólo el issuer configurado de AUTH. El fixture actual no emite email verificado ni solicita scope email: USR-T05 debe extender su perfil y probar mapping/negativos sin cambiar la identidad issuer/subject ni introducir bypass. T01 define ese contrato de puerto; no acredita su integración ni un proveedor productivo. Si falta evidencia, 403 recipient_unverified antes de resolver el token. Si la evidencia existe pero no coincide con el destinatario normalizado, usar la misma respuesta genérica 409 invitation_invalid que para un token desconocido/expirado/revocado/usado.

El operador sin membership puede aceptar con sesión válida; no requiere tenant seleccionado, roles previos ni acceso al directorio. El token determina el tenant en servidor, nunca el body. La respuesta contiene sólo tenantId y su propia membership. No selecciona automáticamente tenant ni rota la sesión: después se relee /me y se usa el selector de AUTH.

## Expiración, entrega y retención test

Los números se mantienen en la política JSON. Su baseline es: invitación 24 horas, idempotencia 24 horas, secreto recuperable de entrega una hora, destinatario siete días desde creación, cursor quince minutos y evidencia email cinco minutos. Límites/relaciones se validan en Go: idempotencia y retención de destinatario no menores que invitación; secreto no mayor que invitación; cursor ≤15 minutos, evidencia ≤5 minutos e invitación ≤24 horas. No se añaden defaults ante campos ausentes ni se permite cargar esta política como producción.

Al crear, fijar createdAt/expiresAt desde reloj servidor; el cliente no elige TTL. En now=expiresAt ya no se puede canjear, sin sumar skew. Token CSPRNG de 32 bytes en base64url canónico sin padding; guardar SHA-256 para verificar. El enlace para la futura UI usa fragmento, no query/path; eliminarlo del historial inmediatamente, aplicar no-referrer/no-store y excluir analytics/logs. Si se necesita navegar para autenticar y no hay custodia segura del intento, descartar el token y pedir reabrir la invitación tras login; no persistirlo en JS storage.

Guardar email normalizado cifrado y un HMAC tenant-scoped para deduplicar pendientes; la clave es externa. Material de entrega (email y token) usa envelope AES-256-GCM, nonce único, key version, AAD por tenant/invitation/propósito y deleteAfter=min(expiresAt, createdAt+deliverySecretSeconds). Outbox sólo referencia invitationId/versión; no contiene email/token/enlace en claro. Token hash no permite reconstruir el enlace.

USR-T04 implementará puerto/worker sintético con deduplicación por invitationId/generación. Reintentos internos usan el mismo envelope vigente; sent no reinicia TTL. Tras sent, aceptación, revocación o vencimiento del envelope se elimina material recuperable. Un fallo conserva deliveryState=failed, sin revocar automáticamente la invitación; agotado el secreto requiere invitación nueva, no recuperar el token desde hash. No existe endpoint adicional de reenvío: POST con key nueva genera token nuevo y revoca atómicamente cualquier pending del mismo tenant/destinatario antes de habilitarlo. Nunca revive el token anterior.

El email y su HMAC de destinatario se purgan a más tardar createdAt+recipientRetentionSeconds; se conserva sólo metadata/IDs/fechas/estados y evidencia sin PII. Idempotencia guarda huellas y referencias seguras, nunca body/token en claro. Su purga no restablece tokens usados. Retención institucional de membership/historial/auditoría se mantiene pendiente; no borrar evidencia por aplicar TTL de invitación.

## Reingreso y último administrador

Una sola membership lógica por `(tenant_id, operator_identity_id)`. PATCH sólo permite active↔suspended y active/suspended→revoked; revoked es terminal para ese lifecycle. Reactivar suspended conserva grants actuales; modificar roles sigue las reglas explícitas de PATCH.

Aceptar para identidad sin membership crea lifecycle=1, revision=1. Para membership activa o suspendida devuelve 409 membership_exists: la invitación no altera sus permisos ni elude suspensión. La creación de una invitación no puede inferir identidad por email y no promete detectar ese caso antes del canje.

Para revoked, una invitación nueva aceptada conserva membershipId, incrementa lifecycle y revision monotónicamente, y deja el lifecycle anterior inmutable en historial. Instala sólo roles/issuerIds de esa invitación, revalidados al aceptar, nunca los revocados. No sustituye operatorIdentityId ni reasocia otra identidad aunque use el mismo correo. Invitaciones antiguas vinculadas al lifecycle revocado se invalidan y no pueden reabrirlo; USR-T02/T05 deben registrar y comprobar la generación de acceso objetivo. El reingreso exige invitación creada después de la revocación vigente, validada bajo lock. Esto precisa el requisito revoked terminal: el historial sigue revocado, cambia sólo la proyección de lifecycle vigente.

Todas las mutaciones toman primero el lock del tenant, luego actor/target/invitación en orden estable y finalmente idempotencia/historial; vuelven a validar tenant, capacidad, revisión del actor y grants antes de persistir. Lecturas previas no autorizan commit. No mantener locks durante OIDC ni entrega externa. Aceptación/promoción/reactivación/revocación usan el mismo orden, aunque la aceptación no exija membership al actor.

Contar tenant_admin activos bajo ese mismo lock. Reducir roles, suspender o revocar a un admin activo exige que quede otro: 409 last_admin_required sin cambio. Auto-reducción se permite con otro admin activo. El guard Go recibe snapshot y conteo de confianza; no demuestra serialización. USR-T02/T06 deben probar las carreras reales. Tras commit, revalidar /me/contexto por revisión sin revocar los accesos de otros tenants.

## Idempotencia, paginación y fallos

Todo POST/PATCH exige Idempotency-Key de 16–128 caracteres base64url. Scope: identidad issuer/subject, operación y tenant; aceptación usa digest de token en lugar de tenant conocido por cliente. Huella SHA-256 del JSON validado/canónico y If-Match: ordenar conjuntos roles/issuerIds y normalizar dominio email; no guardar body en claro. Otra huella con la misma key devuelve 409 idempotency_conflict. La concurrencia de una misma key devuelve 409 operation_in_progress con Retry-After, sin ejecutar dos efectos.

Reautorizar credencial/capacidad/MFA y pertenencia antes de replay; aceptación revalida identidad/email y liga el resultado a ese actor/digest, sin exigir que siga pending el token ya consumido por esa misma key. Resolver un replay confirmado antes de comparar If-Match contra la revisión actual, para que un reintento exacto funcione después del primer commit. Devolver los mismos IDs con representación vigente/estado efectivo y ETag actual, sin regenerar secretos ni duplicar auditoría. Si la misma identidad fue revocada/suspendida después de aceptar, no devolver éxito de aceptación obsoleto: 409 membership_revoked/membership_exists según estado. Con otra key, el token ya consumido devuelve invitation_invalid.

Listados usan limit 1–100 (25 por defecto), cursor opaco autenticado por actor/tenant/operación/filtros/limit/versión/deadline y orden `(createdAt,id)` ascendente. Rechazar cursor alterado, expirado, de otro actor/tenant/filtro con 400 invalid_cursor. No prometer snapshot: cambios concurrentes pueden requerir recargar; nunca exponen otro tenant. query de memberships es prefijo canónico de UUID (8–36 caracteres) sobre membershipId/operatorIdentityId; no es búsqueda global por email o nombre. Estados/roles desconocidos y límites inválidos son 422; parámetros repetidos/desconocidos son 400. JSON estricto de hasta 16 KiB, sin campos extra, duplicados, contenido posterior ni content-type alternativo.

| HTTP / code | Semántica segura |
| --- | --- |
| 400 invalid_request / invalid_cursor | Forma, parámetros, header o cursor inválidos. |
| 401 invalid_credential | Credencial/sesión inválida; WWW-Authenticate sólo en Management. |
| 403 forbidden / mfa_required / csrf_invalid / origin_invalid / recipient_unverified | Falta autoridad o evidencia; no resolver destinatario desde el error. |
| 404 resource_not_found | Tenant/recurso ajeno o no disponible; aceptación no usa este error. |
| 409 last_admin_required / membership_exists / membership_revoked / invitation_not_pending / invitation_invalid / idempotency_conflict / operation_in_progress | Invariante, lifecycle, invitación o key incompatible; sin datos del invitado. |
| 412 revision_mismatch / 428 precondition_required | Recargar/preservar edición o suministrar If-Match. |
| 415 unsupported_media_type / 422 invalid_input | Tipo o campos inválidos; sin reflejar PII. |
| 429 rate_limited / 503 dependency_unavailable | Reintentar según Retry-After, revalidando resultado. |

Todas las respuestas: Problem Details seguro en errores, X-Correlation-Id opaco, no-store y no-referrer. 429/503 y operation_in_progress incluyen Retry-After. Los éxitos escriben mutación, revisión, evento y outbox en una transacción; el vocabulario de auditoría USR se materializa en la [persistencia USR-T02](console-members-persistence.md), conservando el envelope de AUTH-T09. No guardar correo, token, enlaces, claims ni reason libre en eventos. Denegaciones conservan el límite best effort de AUTH.

## Gate y continuación

`npm run test:auth` incluye automáticamente los tests nuevos de contrato. `npm run check:platform` ejecuta las unitarias Go; `npm run check` incluye ambos más TypeScript/documentación. Los ejemplos OpenAPI incluyen aceptación sin membership previa y 409 last_admin_required. Las pruebas negativas cubren roles/campos/issuerIds, input de email y deadlines/revisiones; no sustituyen efectos reales.

USR-T02 añade migraciones expand, lifecycle/historial, invitaciones, retención e idempotencia/RLS/locks/audit/outbox. USR-T03–T07 conectan handlers, evidencia email, entrega y autorización viva. USR-T08 añade UI y USR-T09 su gate. No se ejecuta ninguna migración de aplicación con T01 ni se habilitan permisos de escritura DB; el perfil de credenciales y producción siguen pendientes.
