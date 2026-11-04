# 07 — HukID Interoperability Profile v0.1-draft

Este documento es el contrato implementable inicial entre issuer, wallet y verifier. **No es todavía un perfil publicado ni una certificación de conformidad**: pasa a `v0.1` sólo cuando existan vectores criptográficos y pruebas automatizadas. Los términos MUST, MUST NOT, SHOULD y MAY se interpretan como RFC 2119/8174.

## 1. Scope y decisión de formato

- W3C VC Data Model 2.0.
- W3C Securing Verifiable Credentials using JOSE and COSE.
- OpenID4VCI 1.0 Final y OpenID4VP 1.0 Final como protocolos.
- Credential Format Identifier HukID: `application/vc+jwt`.
- Presentación W3C: `application/vp+jwt`.
- ES256 para credencial, holder proof y presentación.

## Política criptográfica del perfil

El perfil separa los algoritmos de interoperabilidad de los algoritmos internos de protección:

| Uso | Algoritmo v0 | Regla |
| --- | --- | --- |
| Firma VC, VP y proof JWT | **ES256** (ECDSA P-256 + SHA-256) | Obligatorio para el perfil interoperable v0; clave no exportable en KMS/HSM. |
| Hashes, `kid`, digests y Merkle roots | **SHA-256** | No usar MD5, SHA-1 ni hashes truncados sin una decisión explícita. |
| Cifrado de datos en reposo | **AES-256-GCM** gestionado por KMS | Claves separadas por propósito; nonce único por operación. |
| Cifrado autenticado interno | **XChaCha20-Poly1305** | Permitido para servicios/libs que lo soporten; no sustituye la firma VC. |
| Derivación de claves | **HKDF-SHA-256** | Contexto y `salt` distintos por tenant/propósito. |
| Contraseñas o secretos memorizables | **Argon2id** | Nunca almacenar contraseñas con SHA-256 directo. |
| Transporte | **TLS 1.3** | TLS 1.2 sólo como compatibilidad temporal documentada; sin suites débiles. |

Ed25519/EdDSA se mantendrá como capacidad futura o perfil interoperable separado, no mezclado silenciosamente con v0: la compatibilidad real de wallets, verificadores y KMS debe probarse antes de anunciarlo. RSA/RS256 queda sólo para integraciones heredadas y no será la opción nueva por defecto. La implementación debe ser criptográficamente ágil para permitir migración futura, incluida una transición post-cuántica cuando los perfiles VC/OpenID y los HSM tengan soporte interoperable.
- JWK thumbprint como holder binding HukID.
- Bitstring Status List para `revocation` y `suspension` cuando la definition las habilita.

`application/vc+jwt` es el media type registrado por W3C para VCDM 2.0 y, en este perfil, también es el Credential Format Identifier en los puntos de extensión de OID4VCI/OID4VP. **No es el perfil OpenID legado `jwt_vc_json`**: ese perfil referencia VC Data Model 1.1. Por ello, una wallet o verifier externo sólo es compatible si anuncia explícitamente soporte para el perfil HukID `application/vc+jwt`. No se debe publicitar interoperabilidad universal hasta probarla.

Fuera de v0: `jwt_vc_json`, `dc+sd-jwt`, Data Integrity, BBS, mdoc, offline presentation, self-hosted issuers, custom domains y recuperación `account-linked`.

## 2. Representación W3C/JOSE

1. El payload JWS MUST ser directamente el documento VC VCDM 2.0; MUST NOT usarse un claim contenedor `vc` ni duplicarse `issuer`, `validFrom` o subject como `iss`, `nbf` o `sub`.
2. El JOSE header de una credencial MUST contener `alg=ES256`, `typ=vc+jwt` y `kid` del issuer; `cty=vc` SHOULD estar presente.
3. El JOSE header de una presentación MUST contener `alg=ES256`, `typ=vp+jwt` y la JWK pública o un `kid` resoluble del holder; `cty=vp` SHOULD estar presente.
4. Debe soportarse JWS Compact Serialization.
5. Una VC incluida en una VP MUST representarse como `EnvelopedVerifiableCredential`, cuyo `id` sea un data URL `data:application/vc+jwt,<JWS compacto>`.
6. Los contextos JSON-LD versionados forman parte del documento VCDM 2.0. HukID MUST servirlos por HTTPS, inmutables y con tests contra cambios de expansión; ningún consumidor debe obtener contextos no allowlisted durante una verificación crítica.

## 3. Issuer profile

1. HukID MUST operar un issuer lógico separado por organización.
2. El identifier MUST ser `https://issuer.hukid.pe/{issuerSlug}`.
3. Cada issuer MUST tener key ring exclusivo en KMS/HSM HukID.
4. VCDM `issuer` MUST coincidir con el identifier.
5. `kid` MUST resolver únicamente contra `https://issuer.hukid.pe/{issuerSlug}/.well-known/jwks.json` según el perfil HukID. Un verifier MUST rechazar keys de otro host, redirects cross-origin o `jku` suministrado por la credencial.
6. JWKS MUST publicarse por HTTPS, con cache headers y key IDs inmutables. Claves retiradas MUST permanecer públicas durante la vida verificable de las credenciales correspondientes.
7. Tenant e issuer MUST NOT compartir private key.

Este JWKS binding es una regla HukID, no una afirmación de que VCDM por sí solo defina la resolución.

## 4. Credential Definition/Profile

- Una definition publicada MUST ser inmutable y tener SemVer.
- Cada configuration v0 MUST usar `required-holder-key`.
- `credential_configuration_id` para CPE: `pe.cpe.receipt.vc-jwt.v1`.
- `type`: `VerifiableCredential`, `ElectronicReceiptCredential`.
- `format`: `application/vc+jwt`.
- `cryptographic_binding_methods_supported`: `jwk`.
- `proof_types_supported.jwt.proof_signing_alg_values_supported`: `ES256`.
- Contextos: base VCDM 2.0 y `https://schemas.hukid.pe/contexts/cpe/v1`.
- `credentialSchema` v0 usa VC JSON Schema; la versión exacta y los tests forman parte del release.

### 4.1 Holder binding HukID

El proof JWT de OID4VCI MUST contener la JWK pública en el header y demostrar control de su private key. Al construir la VC, el issuer calcula su thumbprint RFC 7638 y añade en la raíz:

```json
{"cnf": {"jkt": "bSXx2QnWnzOO_d0aNCKrdg9XyRZoARe-hQrRkkTewdk"}}
```

El término `cnf` queda definido por el contexto HukID y su semántica normativa en v0 es la de confirmation thumbprint. La JWK completa no se inserta en la VC. En presentación, la wallet MUST firmar la `application/vp+jwt` con esa misma clave. El verifier MUST calcular el RFC 7638 thumbprint de la clave que verificó la VP y compararlo, en tiempo constante, con `cnf.jkt` de cada VC. Una discrepancia invalida `holderBinding`, aunque la firma del issuer sea válida.

Esta regla es una extensión HukID necesaria para binding criptográfico; un verifier W3C genérico puede validar la firma del issuer sin implementarla, pero no puede declarar holder binding conforme a HukID.

## 5. Status

Si una definition declara status:

1. El issuer MUST reservar índices antes de construir el payload final.
2. La VC MUST contener `credentialStatus` con una entrada por purpose.
3. Revocation y suspension MUST usar listas/entradas distinguibles.
4. Un verifier MUST comprobar tipo, purpose, índice, firma, issuer y freshness de la lista.
5. HukID MUST mantener `desired_status` separado de `published_status`.
6. Una API privada MAY responder accepted/pending, pero MUST NOT declarar el cambio públicamente efectivo antes de publicar la versión correspondiente.

## 6. Separación de tokens y audiences

Un único Authorization Server puede emitir las tres clases, pero cada adapter MUST rechazarlas por `aud`, clase y grant antes de evaluar scopes:

| Clase | `aud` exacta | Grant/cliente | Superficie permitida |
| --- | --- | --- | --- |
| `operator` | `https://api.hukid.pe/operator` | sesión humana/OIDC | consola administrativa |
| `integration` | `https://api.hukid.pe/integration` | client credentials | `/v1` del tenant |
| `oid4vci` | identifier exacto del issuer | pre-authorized o authorization code | nonce, credential y deferred endpoints de ese issuer |

Los access tokens JWT MUST usar `typ=at+jwt` y un claim privado `hukid_token_class` con uno de esos valores. Un token con audience múltiple, clase ausente, issuer incorrecto o clase distinta MUST rechazarse. Un access token de integración nunca actúa como holder y un token OID4VCI nunca autoriza `/v1`.

## 7. OpenID4VCI — low-risk receipt

### 7.1 Authorization Server

El piloto permite wallets no preregistradas y MUST publicar `pre-authorized_grant_anonymous_access_supported: true`. Este modo se limita a tipos aprobados de bajo riesgo. Offers MUST ser de alta entropía, un uso, hash-at-rest, TTL ≤ 5 minutos y rate-limited.

### 7.2 Variantes

- **Sin tx code:** acepta “first valid redemption wins”. El Token Request MAY omitir `client_id` porque metadata habilita anonymous access.
- **Con tx code:** el código MUST entregarse por un canal diferente del QR; se usa para credenciales nominativas o de mayor riesgo.

### 7.3 Secuencia común

1. Wallet resuelve `credential_offer_uri` por HTTPS y trata el contenido como no autenticado hasta validar issuer/metadata.
2. Wallet obtiene Credential Issuer Metadata y Authorization Server Metadata.
3. Wallet verifica que soporta el format profile `application/vc+jwt` y canjea el pre-authorized code una sola vez.
4. Token Response devuelve la clase `oid4vci` y `authorization_details[].credential_identifiers` cuando se use `credential_identifier`.
5. Wallet hace `POST nonce_endpoint`, recibe `c_nonce` con `Cache-Control: no-store`.
6. Wallet crea proof JWT `typ=openid4vci-proof+jwt`, con JWK pública, `aud` igual al issuer identifier, `iat` fresco y `nonce=c_nonce`.
7. Credential Request envía `proofs.jwt`.
8. Issuer valida proof, calcula `cnf.jkt`, reserva y firma mediante la coreografía durable.
9. Respuesta inmediata contiene `credentials`; respuesta diferida contiene `transaction_id` e `interval`, nunca ambos.
10. Wallet valida JWS, issuer/kid, `cnf`, VCDM, schema, tiempo y status antes de guardar.

## 8. Subject, holder y recuperación

Key binding prueba qué wallet controla la credencial/presentación; no convierte automáticamente al holder en subject. `credentialSubject.id` MUST NOT copiarse de la clave de wallet por defecto.

El perfil v0 admite:

- `local-only` como default: no existe inventario cloud ni recuperación de la private key;
- `issuer-reauth`: el sistema fuente vuelve a autenticar al subject según su propia policy y emite una credencial nueva a otra clave.

`account-linked` queda fuera de v0 hasta definir assurance de vinculación, reautenticación, cambio de dispositivo, revocación/reemisión, metadata retenida y respuesta a account takeover. El login HukID nunca prueba por sí solo identidad del subject.

## 9. OpenID4VP — presentación directa

El modo v0 es wallet → verifier, sin mediación obligatoria de HukID.

1. Verifier MUST usar OpenID4VP 1.0, `response_type=vp_token` y DCQL.
2. Verifier web de producción SHOULD usar request object firmado con client identifier prefix `x509_san_dns`.
3. El MVP usa `response_mode=direct_post.jwt`; el request MUST publicar una JWK de cifrado utilizable, con `kid`, `use=enc` y algoritmo compatible.
4. Request MUST contener nonce impredecible, state ligado a sesión, response URI exacta y DCQL.
5. Wallet MUST autenticar/verificar al verifier, mostrar propósito y datos revelados, y obtener consentimiento.
6. La wallet crea una VP VCDM 2.0 con el contexto versionado `https://schemas.hukid.pe/contexts/presentation/v1` y la asegura como `application/vp+jwt`; ese contexto define `aud` y `nonce`, que MUST ligar la VP al request.
7. Verifier MUST validar request/response binding, replay, tiempo, firma de VP, que el thumbprint de su signing key coincida con cada `cnf.jkt`, cada VC, status, schema y trust policy.
8. `application/vc+jwt` no da selective disclosure: presentar la VC revela el documento completo. La UI MUST advertirlo.

El ejemplo completo del payload está en `oid4vp-request-payload.json` (artefacto no incluido; ver [registro de pendientes](../05-delivery/documentation-gaps.md)). La Authorization Response `direct_post.jwt` envía `response=<JWE>` como form parameter. La JWK de `client_metadata` sólo cifra esa respuesta y MUST NOT utilizarse para verificar la firma del request object.

## 10. Verifier-as-a-Service opcional

Cuando un cliente contrata el servicio HukID, client identifier, certificado, audience y claves pertenecen a ese verifier/tenant. HukID MUST NOT persistir `vp_token`, raw credential ni claims por defecto. Audit guarda digest, resultado y razones no sensibles. La wallet MUST seguir funcionando con verifiers externos compatibles con el perfil.

## 11. Matriz de errores/retry

| Punto | Error | Retry |
| --- | --- | --- |
| Offer resolve | expirado/no encontrado | no; pedir nueva oferta |
| Token | invalid_grant/code usado | no; nueva oferta |
| Nonce | timeout | sí, POST nuevo |
| Credential proof | invalid_nonce | obtener nonce nuevo y repetir si token válido |
| Signing pendiente | `transaction_id` | poll respetando `interval` |
| Credential response perdida | mismo request válido | mismo artefacto o transacción; nunca duplica |
| Presentation state/nonce replay | invalid request | no; nueva sesión |

## 12. Conformance gate

Antes de promover el perfil:

- validar VC completa y context expansion con vectores positivos/negativos;
- probar header `vc+jwt`, payload VCDM directo y ausencia de contenedor `vc`;
- probar proof→`cnf.jkt`→firma de VP con misma clave y rechazo con clave distinta;
- probar rechazo cruzado de las tres clases de token, audience y grant;
- probar offers con/sin tx code, nonce, crash KMS/DB, status y rotación de issuer keys;
- probar request firmado, respuesta cifrada, audience/nonce/state y replay en OID4VP;
- demostrar presentación a un verifier externo compatible sin contactar HukID;
- publicar vectores exactos con headers, payloads, keys públicas, firmas y resultados esperados.

## 13. Fuentes normativas principales

- [W3C Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/)
- [W3C Securing Verifiable Credentials using JOSE and COSE](https://www.w3.org/TR/vc-jose-cose/)
- [OpenID4VCI 1.0 Final](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html)
- [OpenID4VP 1.0 Final](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html)
