# 04 — APIs y contratos

## 1. Catálogo de superficies

| Superficie | Consumidor | Autenticación | Compatibilidad |
| --- | --- | --- | --- |
| Management API `/v1/tenants`, `/issuers`, `/credential-definitions` | Console/operadores | OIDC user token + MFA/RBAC | HukID |
| Integration API `/v1/issuance-requests` | POS/SIS/ERP | OAuth client credentials | HukID |
| Operations API `/v1/credentials/{id}/...` | issuer operators/systems | OAuth scopes | HukID |
| Issuer metadata / offer / token / credential | Wallet | OpenID4VCI | Estándar |
| Presentation request/response | Wallet/verifier | OpenID4VP | Estándar |
| Public resources | Wallet/verifier | público + integrity/caching | W3C/perfil |

No colocar rutas estándar debajo de `/v1` ni devolver Problem Details donde OpenID prescribe un error OAuth/OpenID.

## 2. Convenciones privadas

- Base: `https://api.hukid.pe/v1`.
- JSON UTF-8.
- `Authorization: Bearer` obligatorio.
- `Idempotency-Key` obligatorio en creación de emisiones y mutaciones reintentables.
- `X-Correlation-Id` aceptado si es válido; de lo contrario HukID genera uno.
- Timestamps RFC 3339 UTC.
- Dinero como decimal string.
- Paginación cursor-based.
- ETag/`If-Match` para editar drafts y recursos administrativos.
- Errores RFC 9457 `application/problem+json`.

## 3. Autenticación de integración

```http
POST /oauth2/token HTTP/1.1
Host: auth.hukid.pe
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&scope=issuance:create%20issuance:read
```

Producción debe preferir `private_key_jwt` o mTLS para integraciones de mayor riesgo. El access token incluye `typ=at+jwt`, `aud=https://api.hukid.pe/integration`, `hukid_token_class=integration`, `client_id`, scopes y grants resueltos; `tenant_id` interno no se acepta como autoridad si viene en el request body. Management exige clase `operator` y audience `/operator`; los Credential Endpoints sólo aceptan clase `oid4vci` con audience igual al issuer exacto. Ningún adapter acepta otra clase aunque firma y scopes sean válidos.

## 4. Crear solicitud de emisión

```http
POST /v1/issuance-requests HTTP/1.1
Host: api.hukid.pe
Authorization: Bearer eyJ...
Idempotency-Key: pos01-B001-00001234
Content-Type: application/json

{
  "issuerId": "iss_01K6YH8S7N4F",
  "credentialDefinition": "cpe-receipt@1.0.0",
  "claims": {
    "document": {
      "type": "03",
      "series": "B001",
      "number": "00001234",
      "issuedAt": "2026-10-09T20:31:42-05:00",
      "currency": "PEN",
      "total": "118.00",
      "xmlDigest": "sha256-uU0..."
    },
    "seller": {
      "taxId": "20123456789",
      "legalName": "Comercial Ejemplo SAC"
    },
    "taxAuthority": {
      "status": "accepted",
      "observedAt": "2026-10-09T20:31:50-05:00"
    }
  },
  "delivery": {
    "flow": "pre-authorized_code",
    "expiresInSeconds": 300,
    "txCodeRequired": false
  },
  "source": {
    "system": "pos",
    "reference": "sale_8f37ab"
  }
}
```

Respuesta:

```http
HTTP/1.1 201 Created
Location: /v1/issuance-requests/ir_01K6YK1G2TBP
Content-Type: application/json
Cache-Control: no-store

{
  "id": "ir_01K6YK1G2TBP",
  "offerState": "ready",
  "issuanceState": "prepared",
  "issuerId": "iss_01K6YH8S7N4F",
  "credentialConfigurationId": "pe.cpe.receipt.vc-jwt.v1",
  "credentialOfferUri": "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.hukid.pe%2Facme%2Foffers%2Fofr_x7Kp...",
  "expiresAt": "2026-10-10T01:36:42Z",
  "createdAt": "2026-10-10T01:31:42Z"
}
```

El POS genera el QR a partir del URI exacto. No interpreta ni construye el Credential Offer.

## 5. Idempotencia

Clave lógica: `(integration_client_id, idempotency_key, operation)`.

HukID persiste:

- hash canónico del request;
- status de procesamiento;
- response status/body o resource id;
- expiración de la key, más larga que la ventana de retry del POS.

Resultados:

- misma key + mismo hash: misma respuesta semántica;
- misma key + hash distinto: `409 idempotency_key_reused`;
- request concurrente: uno procesa, los demás esperan/acceden al resultado;
- error no comprometido: puede reintentarse;
- commit completado y respuesta perdida: devuelve recurso creado.

## 6. Errores privados

```http
HTTP/1.1 422 Unprocessable Content
Content-Type: application/problem+json

{
  "type": "https://docs.hukid.pe/problems/claim-validation",
  "title": "Los claims no cumplen la definición",
  "status": 422,
  "detail": "Dos campos no son válidos para cpe-receipt@1.0.0.",
  "instance": "/v1/issuance-requests/attempts/att_01K...",
  "code": "claim_validation_failed",
  "correlationId": "cor_01K...",
  "errors": [
    {"path": "/claims/document/total", "code": "invalid_decimal"},
    {"path": "/claims/document/xmlDigest", "code": "required"}
  ]
}
```

| HTTP | Code | Semántica |
| ---: | --- | --- |
| 400 | malformed_request | JSON/sintaxis inválida |
| 401 | invalid_token | autenticación ausente/inválida |
| 403 | grant_denied | client no autorizado para issuer/definition |
| 404 | resource_not_found | recurso no visible en el tenant |
| 409 | idempotency_key_reused | key con payload distinto |
| 409 | invalid_state_transition | estado ya no permite acción |
| 412 | etag_mismatch | draft cambió |
| 422 | claim_validation_failed | input no cumple definición |
| 429 | rate_limit_exceeded | incluye `Retry-After` |
| 503 | signing_unavailable | KMS/firmador no disponible |

## 7. Credential Offer OpenID4VCI

El QR referencia un endpoint. Al resolverlo:

```json
{
  "credential_issuer": "https://issuer.hukid.pe/acme",
  "credential_configuration_ids": ["pe.cpe.receipt.vc-jwt.v1"],
  "grants": {
    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
      "pre-authorized_code": "SplxlOBeZQQYbYS6WxSbIA"
    }
  }
}
```

Este ejemplo es la variante de bajo riesgo sin `tx_code`: quien primero canjea recibe la credencial. Para factura nominativa, certificados o licencias, el QR público no basta; se usa otra configuración/policy y un `tx_code` entregado por un canal independiente del QR o autenticación del usuario.

## 8. Issuer metadata

Ejemplo recortado:

```json
{
  "credential_issuer": "https://issuer.hukid.pe/acme",
  "authorization_servers": ["https://auth.hukid.pe"],
  "credential_endpoint": "https://issuer.hukid.pe/acme/credential",
  "nonce_endpoint": "https://issuer.hukid.pe/acme/nonce",
  "credential_configurations_supported": {
    "pe.cpe.receipt.vc-jwt.v1": {
      "format": "application/vc+jwt",
      "scope": "pe.cpe.receipt",
      "cryptographic_binding_methods_supported": ["jwk"],
      "credential_signing_alg_values_supported": ["ES256"],
      "credential_definition": {
        "type": ["VerifiableCredential", "ElectronicReceiptCredential"]
      },
      "proof_types_supported": {
        "jwt": {"proof_signing_alg_values_supported": ["ES256"]}
      },
      "credential_metadata": {
        "display": [{
          "name": "Comprobante electrónico",
          "locale": "es-PE",
          "background_color": "#12263A",
          "text_color": "#FFFFFF"
        }]
      }
    }
  }
}
```

El perfil MVP fija `issuer = https://issuer.hukid.pe/{slug}`. La credencial JWS usa `typ=vc+jwt`, `cty=vc` y un `kid` que debe resolver exclusivamente contra `https://issuer.hukid.pe/{slug}/.well-known/jwks.json`; HukID registra la relación issuer→key version y nunca acepta un JWKS indicado por la credencial. Rotaciones conservan claves públicas retiradas mientras existan credenciales verificables. El identificador de formato `application/vc+jwt` es una extensión HukID sobre los puntos de extensión OpenID4VC: sólo debe anunciarse a clientes que implementen [07 — Perfil HukID v0](hukid-profile.md).

## 9. Token y proof

Token request en pre-authorized flow:

```http
POST /oauth2/token HTTP/1.1
Host: auth.hukid.pe
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA
```

El Authorization Server Metadata del piloto declara `pre-authorized_grant_anonymous_access_supported: true`. Sin esa declaración, una wallet debe enviar un `client_id` válido. El modo anónimo se compensa con offer de un uso, TTL, rate limits y restricción a tipos de bajo riesgo.

Token response que habilita el uso posterior de `credential_identifier`:

```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 300,
  "authorization_details": [{
    "type": "openid_credential",
    "credential_configuration_id": "pe.cpe.receipt.vc-jwt.v1",
    "credential_identifiers": ["cred_ident_01K6..."]
  }]
}
```

La wallet obtiene un nonce fresco antes de crear el proof:

```http
POST /acme/nonce HTTP/1.1
Host: issuer.hukid.pe
Content-Length: 0
```

```json
{"c_nonce":"n_01K6..."}
```

Credential request conceptual:

```json
{
  "credential_identifier": "cred_ident_01K6...",
  "proofs": {
    "jwt": ["eyJhbGciOiJFUzI1NiIsInR5cCI6Im9wZW5pZDR2Y2ktcHJvb2Yrand0IiwiandrIjp7Li4ufX0.eyJhdWQiOiJodHRwczovL2lzc3Vlci5odWtpZC5wZS9hY21lIiwiaWF0IjoxNzgxMjI4MDAwLCJub25jZSI6Im5fLi4uIn0.signature"]
  }
}
```

El issuer valida esa JWK, calcula su thumbprint RFC 7638 y lo fija como `cnf.jkt` en el payload. Los campos exactos deben seguir OpenID4VCI 1.0 y el perfil seleccionado. No copiar ejemplos de drafts antiguos.

## 10. Credencial conceptual

El archivo `cpe-credential.json` (artefacto no incluido; ver [registro de pendientes](../05-delivery/documentation-gaps.md)) muestra el payload VCDM 2.0 antes de firmarlo. El JWS `application/vc+jwt` usa ese documento directamente como payload, sin claim contenedor `vc`; el valor retornado es el JWS compacto, no ese JSON suelto.

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://schemas.hukid.pe/contexts/cpe/v1"
  ],
  "id": "urn:uuid:0199c5d2-9a47-7a41-b4a5-1c44d5dfceab",
  "type": ["VerifiableCredential", "ElectronicReceiptCredential"],
  "issuer": "https://issuer.hukid.pe/acme",
  "validFrom": "2026-10-10T01:31:42Z",
  "cnf": {"jkt": "bSXx2QnWnzOO_d0aNCKrdg9XyRZoARe-hQrRkkTewdk"},
  "credentialSubject": {
    "document": {
      "type": "03",
      "series": "B001",
      "number": "00001234",
      "currency": "PEN",
      "total": "118.00",
      "xmlDigest": "sha256-uU0..."
    },
    "seller": {"taxId": "20123456789"}
  },
  "credentialStatus": [
    {
      "id": "https://issuer.hukid.pe/acme/status/revocation/1#94567",
      "type": "BitstringStatusListEntry",
      "statusPurpose": "revocation",
      "statusListIndex": "94567",
      "statusListCredential": "https://issuer.hukid.pe/acme/status/revocation/1"
    },
    {
      "id": "https://issuer.hukid.pe/acme/status/suspension/1#94567",
      "type": "BitstringStatusListEntry",
      "statusPurpose": "suspension",
      "statusListIndex": "94567",
      "statusListCredential": "https://issuer.hukid.pe/acme/status/suspension/1"
    }
  ]
}
```

## 11. Presentación OpenID4VP

El payload de request object está en `oid4vp-request-payload.json` (artefacto no incluido; ver [registro de pendientes](../05-delivery/documentation-gaps.md)). Usa DCQL con `format=application/vc+jwt`, `direct_post.jwt` y publica en `client_metadata.jwks` una clave efímera `use=enc` para cifrar la respuesta. La wallet crea una VP VCDM 2.0 firmada como `application/vp+jwt`; las credenciales se incluyen como `EnvelopedVerifiableCredential`. Véase `vp-jwt-structure.json` (artefacto no incluido; ver [registro de pendientes](../05-delivery/documentation-gaps.md)).

El verifier calcula el thumbprint RFC 7638 de la clave que verificó la VP y exige igualdad con `cnf.jkt` de la VC. También valida nonce, audience, state, request/response binding y replay. La JWK de cifrado de la respuesta no sirve para validar la firma del request object ni la firma del holder.

## 12. Status operations privadas

```http
POST /v1/credentials/vc_01K6.../suspensions HTTP/1.1
Authorization: Bearer eyJ...
Idempotency-Key: case-9921-suspend
Content-Type: application/json

{
  "reasonCode": "source_under_review",
  "comment": "Caso interno CASE-9921"
}
```

```http
DELETE /v1/credentials/vc_01K6.../suspension HTTP/1.1
Authorization: Bearer eyJ...
Idempotency-Key: case-9921-reactivate
```

```http
POST /v1/credentials/vc_01K6.../revocations HTTP/1.1
Authorization: Bearer eyJ...
Idempotency-Key: case-10012-revoke
Content-Type: application/json

{"reasonCode": "superseded"}
```

La respuesta indica `accepted`, `effectiveAt`, `statusListVersion` y propagation state. No afirmar revocación pública completa antes de publicar el artefacto de status.

## 13. Webhooks

Eventos candidatos:

- `hukid.issuance.offer_consumed.v1`
- `hukid.credential.issued.v1`
- `hukid.credential.deferred_failed.v1`
- `hukid.credential.status_changed.v1`

Entrega at-least-once, firma sobre timestamp + body, event ID único, retries exponenciales y endpoint de replay. Receptores deduplican por event ID.

```json
{
  "id": "evt_01K6...",
  "type": "hukid.credential.issued.v1",
  "occurredAt": "2026-10-10T01:32:10Z",
  "tenantId": "ten_01K...",
  "data": {
    "issuanceRequestId": "ir_01K6YK1G2TBP",
    "credentialId": "vc_01K6...",
    "sourceReference": "sale_8f37ab"
  }
}
```

No incluir VC, access token ni claims completos.

## 14. Versionado

- API privada: cambios aditivos compatibles dentro de `/v1`; breaking change crea `/v2` o media/profile version.
- Webhooks: versión en event type.
- Definitions: SemVer y snapshot inmutable.
- Credential Configuration: ID nuevo ante cambio incompatible de formato, binding o semántica.
- Schema/context: URL inmutable por versión y digest/integrity cuando el perfil lo permita.
- Protocolos: metadata publica sólo perfiles realmente soportados y probados.
