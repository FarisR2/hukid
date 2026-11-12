# Contrato del núcleo de verificación de credenciales

Estado: implementado en laboratorio (paquete `src/platform/internal/verification`, VER-T01–T07 de [FEAT-004](../features/FEAT-004-credential-verification/spec.md)). Es un contrato **interno** del backend Go: no existe endpoint HTTP, OpenAPI ni evento que lo exponga, y su exposición queda diferida (VER-T10/T11). Versión del conjunto de códigos: `CodesVersion = 2`. Los criterios de aceptación están en el [spec](../features/FEAT-004-credential-verification/spec.md); el procedimiento operativo, en el [runbook](../04-engineering/credential-verification-runbook.md); la evidencia, en el [gate V4](../05-delivery/verification-gate.md).

## Entradas y salidas

| Operación | Entrada | Salida |
| --- | --- | --- |
| `Verifier.Verify(jws)` | Una credencial `application/vc+jwt` en forma compacta. | `Report` y un `error`. |
| `Verifier.VerifyPresentation(Response, Request)` | `Response{VP, State}`: la `application/vp+jwt` y el `state` de la respuesta. `Request{Audience, Nonce, State}`: lo que el verifier espera. | `PresentationReport` y un `error`. |

El `error` es distinto de cero **solo** cuando falla una dependencia (`ErrKeyResolution`, `ErrTrustPolicy`, `ErrReplayStore`) o la configuración (`ErrConfig`). Nunca expresa un hallazgo sobre la credencial: ante un error no se devuelve reporte, porque el conjunto de códigos es cerrado y no hay uno para "no se pudo comprobar".

## Reporte

`Report` (credencial) y `PresentationReport` (presentación) llevan solo códigos, un digest y la decisión de confianza. Nunca el JWS, la VP, los claims, el nonce, el state ni el audience.

| Campo | Contenido |
| --- | --- |
| `codesVersion` | Versión del conjunto cerrado de códigos. |
| `checks[]` | Una entrada por criterio: `name`, `result` (`pass`, `fail` o `skipped`), `code` (en fallos y omisiones) y `required`. |
| `credentials[]` | Solo en `PresentationReport`: un `Report` completo por credencial envuelta, en el orden de la VP. |
| `technicalResult` | `valid` solo si hay al menos una comprobación, ninguna falló y toda comprobación requerida pasó. Una requerida omitida lo deja `invalid`. En una presentación exige además que todas las credenciales sean `valid`. |
| `trust` | `trusted`, `untrusted` o `notEvaluated`. Ausente si no hay política configurada. Nunca modifica `technicalResult`. |
| `digest` | `sha256:` y el SHA-256 en hexadecimal de la credencial o de la presentación verificada. |

## Comprobaciones y orden

Credencial: `format`, `issuerKey`, `signature`, `validity`, `status`, `schema`. Si una falla, las siguientes se reportan `skipped` con `skipped.precondition_failed` (requeridas), nunca `pass`. La vigencia de una credencial no autenticada no se evalúa.

Presentación: `format`, `signature` (del holder, con la JWK del header), `requestBinding`, `holderBinding`, y después el reporte de cada credencial. El orden forma parte del contrato: una solicitud se consume **solo** tras una respuesta con firma válida del holder que coincide con ella. Así un remitente no autenticado no puede quemar una solicitud legítima, y una respuesta auténtica se consume aunque después falle el binding o una credencial.

`status` y `schema` no tienen implementación todavía. Si la credencial declara `credentialStatus` o `credentialSchema`, su comprobación queda `skipped.not_implemented` **requerida** y el reporte sale `invalid`; si no las declara, queda `skipped.not_declared` opcional.

## Códigos (versión 2)

| Comprobación | Código | Significado |
| --- | --- | --- |
| `format` | `format.malformed` | Estructura inválida: tamaño, segmentos, base64url, JSON no estricto (miembros duplicados, profundidad), campos obligatorios ausentes o de tipo incorrecto, fechas no RFC 3339, `validFrom` ≥ `validUntil`. |
| `format` | `format.header.alg` | `alg` distinto de `ES256`. |
| `format` | `format.header.typ` | `typ` distinto de `vc+jwt` (credencial) o `vp+jwt` (presentación). |
| `format` | `format.payload.vc_container` | Contenedor `vc` en el payload; el perfil exige el VCDM directo. |
| `format` | `format.payload.duplicate_claim` | `iss`, `nbf` o `sub` duplicando `issuer`, `validFrom` o el sujeto. |
| `format` | `format.context_not_allowed` | Contexto JSON-LD fuera de la lista permitida, o contexto en línea. |
| `issuerKey` | `key.untrusted_header` | La credencial trae su propia clave (`jku`, `jwk`, `x5u`, `x5c`); se rechaza antes de buscar ninguna clave. |
| `issuerKey` | `key.unknown_kid` | El resolver no publica ese `kid`. |
| `issuerKey` | `key.issuer_mismatch` | El emisor declarado no es el dueño de la clave resuelta. |
| `signature` | `signature.invalid` | Firma ES256 inválida, de longitud incorrecta o con valores fuera de rango. |
| `validity` | `validity.not_yet_valid` | Aún no se alcanza `validFrom` (con la tolerancia de reloj). |
| `validity` | `validity.expired` | Se alcanzó `validUntil`: la ventana es `[validFrom, validUntil)`. |
| `holderBinding` | `binding.missing_cnf` | La credencial no lleva `cnf.jkt`. |
| `holderBinding` | `binding.mismatch` | `cnf.jkt` no coincide con el thumbprint RFC 7638 de la clave que firmó la VP. |
| `requestBinding` | `request.audience_mismatch` | `aud` de la VP distinto del audience esperado. |
| `requestBinding` | `request.nonce_mismatch` | `nonce` de la VP distinto del esperado. |
| `requestBinding` | `request.state_mismatch` | `state` de la respuesta distinto del esperado. |
| `requestBinding` | `request.replayed` | La solicitud ya recibió una respuesta. |
| omisión | `skipped.not_declared` | La credencial no declara ese miembro (`status`, `schema`). |
| omisión | `skipped.not_implemented` | La credencial lo declara y su comprobación aún no existe. |
| omisión | `skipped.precondition_failed` | Un criterio previo falló; este no se evaluó. |

Añadir, renombrar o quitar un código exige subir `CodesVersion` y actualizar la prueba que fija el tamaño del conjunto. Una expectativa vacía (audience, nonce o state) nunca coincide con un valor vacío.

## Puertos

| Puerto | Responsabilidad | Implementación de laboratorio |
| --- | --- | --- |
| `IssuerKeyResolver.ResolveKey(issuer, kid)` | Clave pública publicada para un `kid`, con el emisor dueño. `ErrKeyNotFound` si no existe; una clave retirada pero aún publicada debe seguir devolviéndose. | `MemoryKeyResolver`, solo P-256. |
| `Clock.Now()` | Hora actual; el núcleo nunca lee el reloj del sistema. | `ClockFunc`. |
| `ReplayStore.Consume(key)` | Registro atómico: de varias llamadas concurrentes con la misma clave, una sola recibe `firstUse`. | `MemoryReplayStore`, sin límite ni expiración. |
| `TrustPolicy.Evaluate(issuer)` | `trusted` o `untrusted` para un emisor. Recibe solo el identificador, nunca la credencial. Se evalúa solo si el emisor quedó autenticado. | `AllowlistTrustPolicy`. |

## Valores por defecto

Todos son **propuesta** pendiente del owner (ver los supuestos del spec):

| Parámetro | Valor |
| --- | --- |
| Tamaño máximo por credencial / por presentación | 16 KiB / 64 KiB |
| Profundidad JSON máxima / credenciales por presentación | 8 niveles / 8 |
| Tolerancia de reloj | 0 a 5 min, 1 min por defecto |
| Contextos permitidos en credenciales | Solo el contexto base VCDM 2.0, ampliable con `WithCredentialContexts` |
| Contextos permitidos en presentaciones | El base y el de presentación del perfil |

## Lo que este contrato no cubre

Resolución HTTPS del JWKS con las reglas de host y redirects (VER-T12), comprobación de status (VER-T09), validación de `credentialSchema` y expansión JSON-LD (VER-T13), el adaptador OpenID4VP y el Verifier-as-a-Service (VER-T10/T11), la política de confianza de producción y un `kid` del holder resuelto fuera del header. La forma de la VP se infiere de las secciones 2.3, 2.5 y 9.6 del perfil porque el ejemplo de referencia `vp-jwt-structure.json` [no está incluido](../05-delivery/documentation-gaps.md) en el repositorio.
