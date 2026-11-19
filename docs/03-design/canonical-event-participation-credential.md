# Credencial canónica de participación en eventos e integración Wallet (`ISS-T07` / `ISS-T08`)

- Estado: **Especificación propuesta (implementada localmente en `canonical.go` y suite E2E OID4VCI; pendiente de aprobación del owner según [ADR-0036](../decisions/ADR-0036.md))**.
- Relacionado con: [Contratos de API](api-contracts.md#frontera-eventshukid), [Perfil HukID](hukid-profile.md), [Consola de emisión](console-issuance-management.md), [ADR-0035](../decisions/ADR-0035.md), [FEAT-005 tasks](../features/FEAT-005-issuer-operations/tasks.md) y el flujo de referencia `upstream/develop:docs/03-design/events-hukid-credential-flow.md`.

---

## 1. Definición canónica del producto (`ISS-T07`)

La credencial canónica v0 emitida por HukID para la plataforma de eventos es el **Certificado de Participación en Evento**, materializado en código en [`canonical.go`](../../src/platform/internal/issuance/canonical.go).

| Propiedad | Valor canónico | Notas normativas |
| :--- | :--- | :--- |
| `id` | `event-participation-certificate` | Regexp `^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$` |
| `version` | `1.0.0` | Inmutable tras publicar ([definition.go](../../src/platform/internal/issuance/definition.go)) |
| `configurationId` | `pe.hukid.events.participation-certificate.v1` | Identificador en `credential_configurations_supported` y Offers OID4VCI |
| `displayName` | `Certificado de Participación en Evento` | Título mostrado en Consola y metadatos |
| `locale` | `es-PE` | Configuración regional por defecto |
| `types` | `["EventParticipationCertificate"]` | Se antepone automáticamente `"VerifiableCredential"` |
| `contexts` | `["https://issuer.hukid.pe/{slug}/contexts/event-participation-certificate/1.0.0.jsonld"]` | Se antepone automáticamente `https://www.w3.org/ns/credentials/v2` |
| `defaultValiditySeconds` | `31536000` (365 días) | Alinea `DefaultCredentialValidity` y `DefaultStatusPolicy().RequireValidUntil = true` (`VER-T09`) |
| `statusPurposes` | `["revocation", "suspension"]` | Bitstring Status List para anulación o suspensión operativa |
| `publishSchema` | `true` | Expone `https://issuer.hukid.pe/{slug}/schemas/event-participation-certificate/1.0.0.json` (`VER-T13`) |

### Esquema de claims (`fields`) y minimización de PII

Siguiendo la regla de minimización de datos de [seguridad](../04-engineering/security.md) y `FieldSpec` (`string | number | boolean | object`), la credencial **prohíbe** incluir DNI, correo electrónico, teléfono o direcciones postales en los claims:

```json
{
  "id": "event-participation-certificate",
  "version": "1.0.0",
  "configurationId": "pe.hukid.events.participation-certificate.v1",
  "displayName": "Certificado de Participación en Evento",
  "locale": "es-PE",
  "contexts": [
    "https://issuer.hukid.pe/{slug}/contexts/event-participation-certificate/1.0.0.jsonld"
  ],
  "types": ["EventParticipationCertificate"],
  "defaultValiditySeconds": 31536000,
  "statusPurposes": ["revocation", "suspension"],
  "publishSchema": true,
  "fields": {
    "participantName": { "type": "string", "required": true, "maxLength": 160 },
    "eventTitle": { "type": "string", "required": true, "maxLength": 200 },
    "organizerName": { "type": "string", "required": true, "maxLength": 160 },
    "eventDate": { "type": "string", "required": true, "maxLength": 32 },
    "participationRole": { "type": "string", "required": true, "maxLength": 64 },
    "certificateNumber": { "type": "string", "required": true, "maxLength": 64 }
  }
}
```

| Campo | Tipo | Obligatorio | Longitud máx. | Significado |
| :--- | :--- | :--- | :--- | :--- |
| `participantName` | `string` | Sí | 160 | Nombre visible de la persona participante |
| `eventTitle` | `string` | Sí | 200 | Título oficial del evento |
| `organizerName` | `string` | Sí | 160 | Organización emisora / entidad organizadora |
| `eventDate` | `string` | Sí | 32 | Fecha ISO-8601 o intervalo del evento (ej. `2026-11-18`) |
| `participationRole` | `string` | Sí | 64 | Rol desempeñado (valores recomendados: `attendee`, `speaker`, `organizer`) |
| `certificateNumber` | `string` | Sí | 64 | Referencia opaca del certificado emitido en Events (`certificate_id`) |

---

## 2. Flujo de integración Events -> HukID -> Wallet (`ISS-T08`)

El diseño respeta el aislamiento de fronteras documentado en [api-contracts.md](api-contracts.md#frontera-eventshukid): HukID no comparte base de datos ni bus de eventos con Events.

```mermaid
sequenceDiagram
  autonumber
  participant C as Consola Operadores
  participant E as Events / Adaptador Team 4
  participant H as HukID Runtime (OID4VCI + KMS)
  participant W as Wallet / Participante

  C->>H: Alta de Emisor (slug), Definición 1.0.0 publicada y Cliente M2M
  E->>H: POST /oauth2/token (client_credentials; scopes issuance:create issuance:read status:write)
  E->>H: POST /v1/issuance-requests + Idempotency-Key (claims mínimos + source)
  H-->>E: 201 {id, offerState:"ready", credentialOfferUri, expiresAt}
  Note over E,W: Events muestra QR/enlace solo en sesión autenticada (+ fallback descarga Wallet)
  W->>H: Discovery (.well-known/openid-credential-issuer, AS, jwks.json)
  W->>H: GET /{slug}/offers/{ref}
  W->>H: POST /oauth2/token (grant pre-authorized_code)
  W->>H: POST /{slug}/nonce -> c_nonce
  W->>H: POST /{slug}/credential (Bearer wallet + JWT PoP P-256)
  alt Emisión inmediata
    H-->>W: 200 {credentials:[{credential: vc+jwt}]}
  else Emisión diferida (HK-025)
    H-->>W: 202 {transaction_id, interval}
    H->>H: Worker cumple solicitud diferida y firma con KMS
    W->>H: POST /{slug}/deferred_credential -> 200 vc+jwt
  end
  W->>H: Verifica firma (jwks.json), JSON Schema y Bitstring Status List
  loop Reconciliación v0 (polling)
    E->>H: GET /v1/issuance-requests/{id} -> issuanceState:"issued"
  end
  C->>H: Consulta metadata-only en Solicitudes / Credenciales (ADR-0035)
```

---

## 3. Reglas de entrega y huecos cerrados frente al piloto

Para resolver sin ambigüedad ni sobrepromesas los puntos abiertos del flujo Events -> HukID -> Wallet:

### Entrega v0 (implementada hoy en runtime) vs. endurecimiento v0.1 (`tx_code`)

* **Modo v0 vigente:** [`Service.CreateIssuanceRequest`](../../src/platform/internal/issuance/service.go#L321-L329) opera exclusivamente con `delivery.flow = "pre-authorized_code"`, `delivery.txCodeRequired = false` y `expiresInSeconds <= 300` (`MaxOfferTTL = 5 * time.Minute`).
  * **Control compensatorio obligatorio en v0:** El adaptador de Events **solo** debe desplegar la `credentialOfferUri` (QR o deep link `openid-credential-offer://...`) dentro de la sesión autenticada del participante titular del certificado, nunca en enlaces públicos indexables ni por correo sin expiración corta. El código pre-autorizado es de **un solo uso**.
  * **App no instalada:** Si el dispositivo del participante no abre el esquema `openid-credential-offer://`, la vista de Events ofrece el enlace oficial de descarga de la Wallet y un botón para generar una nueva solicitud idempotente si el TTL de 300 s expiró.
* **Endurecimiento v0.1 (planificado para credenciales nominativas fuera de sesión directa):**
  * Habilitar `delivery.txCodeRequired = true` con PIN numérico de 6 dígitos generado en servidor, persistido únicamente como hash criptográfico y entregado en la UI autenticada o canal verificado del participante para canje en `POST /oauth2/token`.
  * Nota técnica: en v0 actual, enviar `txCodeRequired: true` devuelve `422 delivery_not_supported` (`ErrUnsupportedDelivery`) hasta ejecutar su migración e implementación dedicadas.

### Contrato exacto de solicitud y respuesta (`Events -> HukID`)

**Request (`POST /v1/issuance-requests`):**
```json
{
  "issuerId": "iss_unas",
  "credentialDefinition": "event-participation-certificate@1.0.0",
  "claims": {
    "participantName": "Ana María Quispe",
    "eventTitle": "Congreso de Aplicaciones en la Nube UNAS 2026",
    "organizerName": "IncubaUNAS",
    "eventDate": "2026-11-18",
    "participationRole": "attendee",
    "certificateNumber": "CERT-2026-0001"
  },
  "delivery": {
    "flow": "pre-authorized_code",
    "expiresInSeconds": 300,
    "txCodeRequired": false,
    "deferred": false
  },
  "source": {
    "system": "events",
    "reference": "cert-2026-0001"
  }
}
```

### Matriz mínima de validación y rechazo

| Caso | Entrada / Condición | Respuesta esperada |
| :--- | :--- | :--- |
| Falta campo requerido o claim PII no declarado (`email`) | Claim extra o string vacío | `422 claim_validation_failed` sin hacer eco del valor enviado |
| Solicitud de `txCodeRequired: true` en v0 | `delivery.txCodeRequired = true` | `422 delivery_not_supported` |
| Expiración superior al techo de perfil | `delivery.expiresInSeconds > 300` | `400 malformed_request` |
| Reintento idempotente | Mismo `Idempotency-Key` y mismo body | `200 OK` con el mismo `id` y estado vigente |
| Colisión de idempotencia | Mismo `Idempotency-Key` y body distinto | `409 idempotency_key_reused` |
| Canje de oferta vencida o código ya usado | TTL > 300 s o segundo `POST /oauth2/token` | `404 not_found` / `400 invalid_grant` |
| Consulta administrativa de consola ([ADR-0035](../decisions/ADR-0035.md)) | `Solicitudes` y `Credenciales` | Solo IDs, estado y fechas; cero claims, cero `source.reference` y cero JWS |
| Revocación M2M posterior | `POST /v1/credentials/{id}/revocations` | Verificador (`VER-T09`) marca `status.revoked` como `invalid` |
