# Modelo de datos

## Ownership por producto

| Dominio | Fuente de verdad | Referencia detallada |
| --- | --- | --- |
| Platform / Content | Organizaciones, identidad/sesiones, CMS, medios y proyecciones públicas. | [Límites Events](contracts/events-database-boundaries.md) |
| Configuration | Eventos, recursos, agenda, formularios/versiones y releases. | [Límites Events](contracts/events-database-boundaries.md) |
| Participation | Identidad del participante, respuestas, consentimiento, cupo, tickets, equipos y postulaciones. | [Límites Events](contracts/events-database-boundaries.md) |
| Onsite / Operations | Asistencia, dispositivos, mensajes, reportes, certificados y entregas HukID locales. | [Límites Events](contracts/events-database-boundaries.md) |
| HukID backend | Tenancy/issuers/keys referenciadas, definitions, requests/offers/signing attempts, credentials/status, auditoría/outbox. | [Modelo HukID](hukid-data-model.md) |
| HukID wallet | Claves holder y credenciales cifradas locales, render metadata y status cacheado. | [Wallet/backend](hukid-wallet-backend.md) |

## Identidades y separación

Events usa organization_id y HukID tenant_id/issuer/client. El adaptador resuelve el vínculo autorizado entre esos contextos. No copiar el tenant recibido por body como autoridad y no introducir una FK entre ambas bases.

Events guarda el certificado y el ID externo de la solicitud; no copia el inventario de la wallet. HukID almacena metadata/evidencia y artefactos cifrados según policy, sin clave privada holder ni PIN. Retención de artefactos necesaria para reentrega debe ser compatible con la política de evidencia/purga; un hash no reconstruye la credencial.

## Invariantes HukID

La cadena tenant→issuer→definition version→key→request→status se protege con constraints compuestas. El origen externo es issuer + source_system + external_reference. El canje de oferta y los cambios de status usan controles transaccionales/CAS. Payload final, key version y slots se reservan antes de KMS; desired y published status se reconcilian.

Claims/payload están cifrados; el modelo especifica AES-256-GCM, nonce de 96 bits, AAD y key version. RLS usa roles no propietarios sin BYPASSRLS y SET LOCAL por transacción. Estas son reglas del modelo; los DDL referenciados no están incluidos.

## Migraciones y evidencia

Aplicar forward-only y expand/backfill/validate/switch/contract. Probar base vacía, versión previa, dos tenants, pooling y restauración. Conservar hashes/versiones y no reactivar ofertas expiradas tras restore.

Fuentes: [modelo HukID](hukid-data-model.md), [arquitectura HukID §7–8](hukid-architecture.md), [migraciones Events](contracts/events-database-boundaries.md), [ownership/retención](../04-engineering/data-ownership-and-retention.md). Estado de SQL: [pendientes](../05-delivery/documentation-gaps.md).
