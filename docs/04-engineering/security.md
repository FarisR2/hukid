# Seguridad

## Fuentes y alcance

| Ámbito | Referencia |
| --- | --- |
| Identidad y permisos Events | [Contrato auth](events-auth-and-authorization.md) |
| Protección/retención Events y transferencia a HukID | [Ownership y retención](data-ownership-and-retention.md) |
| Threat model, claves y operación HukID | [Seguridad HukID](hukid-security-and-operations.md) |
| Algoritmos, tokens y protocolos HukID | [Perfil v0.1-draft](../03-design/hukid-profile.md) |

## Identidad y autorización

Events integra OIDC/PKCE y sesiones BFF; las acciones sensibles exigen MFA/autenticación reciente según contrato. Cada servicio autoriza recursos con tenant/actor derivados de credenciales validadas.

HukID separa tres planos: operador, integración y wallet. Se rechazan tokens cruzados por clase, audience, issuer y grant antes de scopes. Un token de integración no autoriza al holder. Aplicar RLS con roles no propietarios, SET LOCAL y pruebas de reutilización de pool.

## Claves y datos

El perfil fija ES256 para VC/VP/proof, SHA-256 para digests, AES-256-GCM para reposo y transporte TLS 1.3 con compatibilidad temporal documentada si hace falta. Conservar agilidad criptográfica sin anunciar algoritmos no probados. Los detalles y alternativas internas permitidas están en el perfil, no se sustituyen por esta síntesis.

Claves issuer en KMS/HSM no exportable; holder keys en dispositivo. Separar claves de VC, access token y webhook. Contextos/JWKS resuelven sólo por ubicaciones autorizadas; limitar fetchers contra SSRF y cambios de contexto.

No almacenar códigos/tokens en claro ni registrar claims/VC/VP completos. Los secretos que sólo se verifican se guardan como hash; el BFF necesita recuperar PKCE y access/refresh tokens, por lo que usa envelopes cifrados de vida limitada según el [modelo de sesión](../03-design/console-auth-contract.md#modelo-lógico-de-sesión-para-auth-t03t06). Esta precisión frente a la prohibición general de material recuperable se registra en [pendientes](../05-delivery/documentation-gaps.md) y ADR-0003, sin cambiar las reglas de ofertas. Aplicar retención por tipo, legal hold y crypto-shredding compatible con reconciliación/evidencia. La política institucional debe ratificar los defaults.

## Entrega, consentimiento y estado

Una oferta es expirable y de un uso. El perfil limita ofertas low-risk a ≤5 minutos. Documentos nominativos no dependen sólo de QR abierto; concretar autenticación o código por canal independiente. Holder binding y biometría local no equivalen a identidad del subject.

La wallet muestra emisor/verifier, propósito y datos antes de aceptar o presentar. El formato v0 revela la VC completa. Status deseado/publicado se mantiene separado y la caída de KMS no habilita firma local de emergencia.

## Operación

Separar ambientes, claves, issuer IDs y secretos. Ensayar rotación, compromiso, KMS caído, status stale, restauración, colas y purga. El objetivo DR inicial no cubre pérdida regional de KMS sin ADR y ejercicio específico. Runbooks y checklist completos en [seguridad/operación HukID](hukid-security-and-operations.md).
