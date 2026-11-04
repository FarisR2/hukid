# Equipo 5 — HukID issuer/node y wallet

## Fuente normativa

Este backlog se complementa con la [arquitectura local de HukID](../../03-design/hukid-architecture.md). Las historias deben cumplir sus decisiones de arquitectura, contratos, perfil HukID v0, modelo PostgreSQL y separación wallet/backend. El estado de los artefactos ejecutables se registra en [pendientes](../../05-delivery/documentation-gaps.md).

## Épica HK-A — Tenant, issuer e integración

| ID | Historia | Criterios de aceptación esenciales |
|---|---|---|
| HK-001 | Como platform admin, quiero crear tenant e issuer lógico. | Aislamiento RLS; issuer URI estable; lifecycle; auditoría; no nodo por cliente en MVP. |
| HK-002 | Como issuer admin, quiero registrar/rotar claves KMS. | Private key nunca sale; kid/JWKS; active/retired/compromised; solapamiento; credenciales antiguas verificables. |
| HK-003 | Como issuer admin, quiero crear/publicar definition version. | Schema/display/policies/hash; immutable published; configuration ID; compatibilidad perfil. |
| HK-004 | Como integration admin, quiero crear client y grants por issuer. | OAuth method/scopes; secret one-use/hash o private-key JWT; expiry/rotate/revoke; cross-client 404. |
| HK-005 | Como auditor, quiero consultar actividad del tenant/issuer/client. | Append-only, actor/action/target/outcome/request ID; no claims/tokens; filtros/retención. |

## Épica HK-B — Integration API y ofertas

| ID | Historia | Criterios de aceptación esenciales |
|---|---|---|
| HK-010 | Como sistema fuente, quiero crear issuance request idempotente. | Client/issuer grant; definition active; Idempotency-Key+request hash; claims AES-GCM; source namespace; expiry. |
| HK-011 | Como backend, quiero crear offer opaca y de un uso. | Reference/code hashes; QR sin PII; expiry; optional tx_code; brute-force lockout; atomic redeem. |
| HK-012 | Como sistema fuente, quiero consultar/cancelar su request. | Sólo client owner/grant; estados separados offer/issuance; cancel terminal según fase; 404 recurso ajeno. |
| HK-013 | Como sistema fuente autorizado, quiero integrar por una API estable sin acceso al bus de HukID. | OAuth client credentials/private-key JWT; `POST /v1/issuance-requests` idempotente; consulta/cancelación por owner; errores y estados versionados; HukID desconoce el bus y la base de Events. |

## Épica HK-C — OID4VCI y firma

| ID | Historia | Criterios de aceptación esenciales |
|---|---|---|
| HK-020 | Como wallet, quiero descubrir metadata/configuration/JWKS. | Endpoints estándares; cache headers; issuer/profile exactos; algoritmos/formats allowlisted. |
| HK-021 | Como wallet, quiero obtener token del grant autorizado. | Pre-authorized/authorization code según config; PKCE donde aplique; nonce; scopes; errores normativos. |
| HK-022 | Como wallet, quiero probar holder binding. | Key local; proof JWT/nonce/aud/iat; jkt; replay rechazado; clock skew limitado. |
| HK-023 | Como issuer, quiero preparar/fijar payload y status slot. | Request-definition-key chain; canonical hash; claims validation; status allocation atómica; ciphertext retention. |
| HK-024 | Como issuer, quiero firmar exactamente una vez. | Lease/CAS; KMS idempotency; artifact object/hash/key version ligados; retry after timeout seguro. |
| HK-025 | Como wallet, quiero recibir o consultar emisión diferida. | Immediate/deferred contract; transaction ID opaco; polling; terminal errors; no duplicate credential. |

## Épica HK-D — Wallet Flutter

| ID | Historia | Criterios de aceptación esenciales |
|---|---|---|
| HK-030 | Como holder, quiero onboarding y lock local. | Consentimiento, PIN/biometría, threat guidance; no cuenta cloud obligatoria; secure storage. |
| HK-031 | Como wallet, quiero generar/usar claves holder. | Keystore/Secure Enclave/StrongBox cuando disponible; no export plain; key ID/jkt; lifecycle. |
| HK-032 | Como holder, quiero escanear/abrir una offer. | URI allowlist/parser; preview issuer/credential; anti-phishing/trust; expiry/error; no auto-accept. |
| HK-033 | Como holder, quiero aceptar y almacenar credencial cifrada. | Consent; OID4VCI; verify antes de persistir; SQLCipher/equivalente; metadata/render. |
| HK-034 | Como holder, quiero listar/ver credenciales y estado. | Agrupación; issuer/trust/vigencia/status; refresh; offline last-checked visible; accesible. |
| HK-035 | Como holder, quiero eliminar una copia local. | Confirmación; no revoca issuer; secure delete best effort; auditoría local mínima. |
| HK-036 | Como holder, quiero recuperar mediante reautenticación y reemisión. | No backup de key plain; issuer reauth; replacement/revocation policy; takeover controls. |

## Épica HK-E — Presentación OID4VP

| ID | Historia | Criterios de aceptación esenciales |
|---|---|---|
| HK-040 | Como wallet, quiero abrir request de presentación. | Valida scheme/redirect/audience/nonce/expiry; trust display; anti-replay. |
| HK-041 | Como holder, quiero seleccionar y consentir atributos/credencial. | Muestra verifier/purpose/datos; no comparte sin acción; minimización según formato; cancelación segura. |
| HK-042 | Como wallet, quiero firmar/enviar presentación. | Key holder correcta; state/nonce; direct response; resultado/error; no VP/claims en logs backend. |
| HK-043 | Como verifier, quiero validar firma, vigencia, holder binding y status. | Trust policy separada de validación criptográfica; códigos de fallo; no persistencia por defecto. |

## Épica HK-F — Status, seguridad y operación

| ID | Historia | Criterios de aceptación esenciales |
|---|---|---|
| HK-050 | Como issuer, quiero suspender/reactivar/revocar. | Scope/client grant; purpose correcto; CAS; revocación terminal; outbox/audit; publicación reconciliada. |
| HK-051 | Como verifier/wallet, quiero consultar status artifact. | Bitstring/list version/cache/signature; privacidad; disponibilidad; fail policy explícita. |
| HK-052 | Como security admin, quiero comprometer/rotar key. | Incident state; deja de emitir; JWKS/history; impacto/reemisión; runbook/alerta. |
| HK-053 | Como privacy admin, quiero aplicar retención/crypto-shredding. | Terminal/no live attempts; legal hold; claims/payload purge; artifact purge event/completion; hashes preservados. |
| HK-054 | Como operador, quiero observabilidad y DLQ. | SLO issuance/status; KMS/DB/broker metrics; traces; redacción; replay auditado. |
| HK-055 | Como operador, quiero backup/restore y continuidad. | PITR/objects/KMS refs; restore drill; RPO/RTO; no backup utilizable sin keys autorizadas. |
| HK-056 | Como QA, quiero conformance e interoperabilidad. | VCDM/Profile/OID4VCI/OID4VP suites; Flutter devices; negative/replay/clock tests; release gate. |

## Contratos que posee

Integration API canónica en `openapi.yaml` (artefacto no incluido; ver [registro de pendientes](../../05-delivery/documentation-gaps.md)); metadata/JWKS/OID4VCI/OID4VP/status según [Perfil HukID v0](../../03-design/hukid-profile.md). El Equipo 4 implementa el adaptador outbound de Events; el Equipo 5 expone únicamente los contratos públicos de HukID.


## Documentación incorporada

El perfil, arquitectura, modelo y flujos de HukID están incluidos localmente. El OpenAPI y DDL citados por las fuentes no fueron adjuntados. Ver [contratos](../../03-design/api-contracts.md) y [artefactos pendientes](../../05-delivery/documentation-gaps.md). En v0, Events reconcilia mediante polling; los webhooks son una optimización posterior, según [wallet/backend](../../03-design/hukid-wallet-backend.md).
