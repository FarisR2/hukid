# FEAT-004 — Núcleo de verificación de credenciales

- Producto: HukID Platform / Team 5.
- Estado: **núcleo de laboratorio implementado (VER-T01–T08)**, por indicación del owner de iniciar la implementación; la aprobación formal del FEAT y del [ADR-0030](../../decisions/ADR-0030.md) **no está registrada**, y los valores marcados como propuesta siguen pendientes. Es un módulo interno sin endpoint ni proceso; HK-043 sigue incompleta (VER-T09 y T13) y el conformance gate del perfil, abierto. Evidencia y límites en el [gate V4](../../05-delivery/verification-gate.md).
- Depende de: [perfil HukID v0.1-draft](../../03-design/hukid-profile.md) y, para la capa de adaptadores, de las decisiones abiertas de [pendientes](../../05-delivery/documentation-gaps.md). No depende de [FEAT-001](../FEAT-001-authentication/spec.md) para verificar; solo lo reutiliza en los puntos de integración que se listan abajo.
- Salidas: [plan](plan.md), [tareas](tasks.md), [ADR-0030](../../decisions/ADR-0030.md).

## Objetivo y alcance

Decidir, con código y pruebas, si una credencial `application/vc+jwt` es técnicamente válida según el perfil HukID: formato, firma del issuer, resolución de clave, vigencia, holder binding y vínculo de la presentación con su solicitud. El incremento base es la **fase 0 del [roadmap](../../05-delivery/hukid-roadmap.md)** aplicada al lado verifier: una librería interna, sin HTTP y sin base de datos, con pruebas negativas y vectores sintéticos.

Esta feature implementa la historia **HK-043** (validar firma, vigencia, holder binding y status con trust policy separada de la validación criptográfica) y prepara HK-051 y HK-056. No es el servicio de login: no autentica operadores ni sesiones.

**HK-043 solo queda completa cuando se cierren VER-T09 (status) y VER-T13 (schema)**, ambas diferidas por dependencias de otros dominios. El incremento base V0–V4 cubre firma, vigencia, holder binding y vínculo con la solicitud; no cierra la historia. La [arquitectura §3.9](../../03-design/hukid-architecture.md) lista además `schema` y trust policy entre lo que valida el verifier, y el verifier conserva la decisión final.

Fuera de este incremento:

- Emitir credenciales, firmar con KMS, JWKS públicos del issuer y status lists (fases 1–4 del roadmap; ver dependencias).
- Adaptador OpenID4VP y Verifier-as-a-Service como proceso o endpoint ([decisión abierta #1](../../05-delivery/documentation-gaps.md)).
- Pantalla de verificación en la consola ([decisión abierta #2](../../05-delivery/documentation-gaps.md)).
- El payload de negocio de comprobante o de certificado académico ([decisión abierta #4](../../05-delivery/documentation-gaps.md)). El laboratorio usa un tipo sintético y no fija ese corte.
- Selective disclosure, `jwt_vc_json`, SD-JWT, Data Integrity y mdoc (fuera de v0 según el perfil §1).
- La decisión de negocio sobre la credencial (qué hace el tercero con el resultado).

## Requisitos y aceptación

| ID | Comportamiento verificable | Criterio de aceptación |
| --- | --- | --- |
| VER-FR01 | Validar el formato `vc+jwt` del perfil §2. | AC01: se rechazan header sin `alg=ES256` o `typ=vc+jwt`, `alg` `none`/HS*/RS*, payload con contenedor `vc`, y `issuer`/`validFrom` duplicados como `iss`/`nbf`. El rechazo devuelve un código de fallo estable. |
| VER-FR02 | Delegar la resolución de clave al puerto y rechazar las vías prohibidas por el perfil §3. | AC02: se rechazan `jku`/`jwk` suministrados por la credencial y un `kid` que el puerto no resuelve para ese issuer. Un issuer distinto del declarado no valida. El núcleo solo consume la clave que devuelve el puerto. |
| VER-FR11 | Resolver el JWKS por HTTPS con las reglas del perfil §3 (adaptador). | AC11: el adaptador solo acepta el JWKS en `https://issuer.hukid.pe/{issuerSlug}/.well-known/jwks.json`; rechaza JWKS de otro host y redirects cross-origin. **Diferido** hasta que exista la publicación de JWKS del issuer (fase 1, HK-002); ver VER-T12. |
| VER-FR03 | Verificar la firma ES256 del issuer. | AC03: firma alterada, clave de otro issuer y `kid` desconocido fallan con códigos distintos. Una clave retirada pero publicada sigue verificando credenciales antiguas. |
| VER-FR04 | Evaluar vigencia con reloj inyectado. | AC04: `validFrom`/`validUntil` se comparan en UTC contra un reloj inyectable y una tolerancia de reloj explícita y acotada. Credencial futura y vencida fallan; los bordes están probados. |
| VER-FR05 | Comprobar el holder binding del perfil §4.1. | AC05: el thumbprint RFC 7638 de la clave que firmó la VP se compara en tiempo constante con `cnf.jkt` de cada VC. Una VP firmada con otra clave invalida `holderBinding` aunque la firma del issuer sea válida. |
| VER-FR06 | Ligar la presentación a su solicitud. | AC06: `aud` y `nonce` de la VP, y el `state` de la respuesta (parámetro de la Authorization Response, no un claim de la VP), deben coincidir con la solicitud. Nonce o state reutilizado y audience equivocada fallan. El almacén anti-replay es un puerto con implementación en memoria para laboratorio. La expiración de la VP no está definida por el perfil; ver supuestos propuestos. |
| VER-FR07 | Separar resultado técnico y decisión de confianza. | AC07: el reporte lista una comprobación técnica por criterio (formato, firma, vigencia, binding, solicitud) y es independiente de la trust policy. La policy es un puerto aparte: confiar en un issuer nunca convierte una firma inválida en válida ni al revés. |
| VER-FR08 | No persistir material sensible por defecto. | AC08: ni el reporte ni los logs ni la auditoría contienen `vp_token`, JWS crudo ni claims. Solo digest SHA-256, resultado y códigos de fallo no sensibles. Verificado con una prueba que busca el material en todas las salidas. |
| VER-FR09 | Publicar vectores reproducibles del laboratorio. | AC09: los vectores positivos y negativos se generan con claves de prueba sintéticas, deterministas y marcadas como tales, e incluyen headers, payloads, claves públicas, firmas y resultado esperado. No se presentan como evidencia de interoperabilidad con un verifier externo. |
| VER-FR10 | Comprobar status cuando la definition lo declare. | AC10: tipo, purpose, índice, firma, issuer y frescura de la lista (perfil §5), con política de fallo explícita (HK-051). El valor por defecto de esa política está por decidir. **Diferido** hasta que existan las listas de la fase 4; ver tareas. |
| VER-FR12 | Validar la credencial contra su `credentialSchema` y contextos versionados. | AC12: una credencial que no cumple el schema de su definition falla con código propio; solo se usan contextos allowlisted. **Diferido** hasta que exista el Definition Registry (fase 2, HK-003); ver VER-T13. |

## Calidad y límites

| ID | Restricción | Verificación |
| --- | --- | --- |
| VER-QR01 | La librería no hace red por sí sola: el resolver de claves y el cargador de contextos son puertos inyectados. Las reglas de host y redirects viven en el adaptador (VER-FR11). | Pruebas con resolver falso; el paquete no importa `net/http`. |
| VER-QR02 | Solo contextos JSON-LD allowlisted durante una verificación (perfil §2.6). Un contexto no listado, o un contexto en línea (objeto), se rechaza con `format.context_not_allowed` sin salir a la red. Por defecto solo se admite el contexto base VCDM 2.0 (y el de presentación en una VP). | Prueba con contexto remoto no listado: se rechaza sin salir a la red; el paquete no puede hacer red (QR01). |
| VER-QR03 | Comparaciones de thumbprint, audience, nonce y state en tiempo constante. El módulo no compara digests: solo los produce. | Revisión de código y pruebas de coincidencia y discrepancia de la presentación. |
| VER-QR04 | Sin dependencia del módulo de autenticación de la consola. | El paquete no importa `internal/authentication`. **No existe hoy ningún chequeo automático:** VER-T07 lo crea (prueba de imports o regla de lint) y lo ejecuta en CI. |
| VER-QR05 | Propuesta: entrada acotada (tamaño máximo de JWS, número de VCs por VP, profundidad JSON). Los valores no están en el perfil y se fijan en VER-T02. | Pruebas de límites con entradas sobredimensionadas. |

## Supuestos propuestos

Decisiones de diseño de este borrador que **no** vienen del perfil ni de la arquitectura y requieren aprobación del owner:

- Expiración de la VP como criterio de fallo; el perfil solo exige `aud` y `nonce` ligados a la solicitud.
- Valor por defecto de la política de fallo de status (HK-051 exige que sea explícita, no cuál es).
- Los límites de tamaño, número de VCs y profundidad JSON de VER-QR05. Valores implementados: 16 KiB por credencial, 8 niveles, 8 credenciales y 64 KiB por presentación.
- La forma exacta de la VP (`aud` y `nonce` como miembros de primer nivel, credenciales envueltas en `verifiableCredential`, JWK del holder en el header). Se infiere de las secciones 2.3, 2.5 y 9.6 del perfil porque el ejemplo `vp-jwt-structure.json` no está en el repositorio; no se admite un `kid` del holder resuelto fuera del header.
- La tolerancia de reloj de VER-FR04; HK-022 solo pide "clock skew limitado".
- La lista de contextos permitidos por defecto: solo el contexto base VCDM 2.0 (y el de presentación en una VP). No se incluye el contexto `cpe/v1` del perfil, porque permitirlo por defecto prejuzgaría la decisión abierta #4 (qué documento va primero en el piloto); los contextos de cada tipo se añaden por definición (VER-T13).
- El código nuevo `format.context_not_allowed` subió `CodesVersion` de 1 a 2, según la regla de que cambiar el conjunto cerrado exige nueva versión.

## Definition of Done aplicable

La [DoD](../../05-delivery/definition-of-done.md) exige, para este cambio: contrato versionado antes de integrar, pruebas negativas, evidencia de checks ejecutados con sus limitaciones, runbook y documentación. Esta feature lo concreta en VER-T01 (contrato), VER-T07 (pruebas negativas) y VER-T08 (runbook y evidencia). Completar V0–V4 **no** satisface los apartados "Tipo de credencial HukID" (definición de purpose, trust policy y caso de uso del verifier) ni "Release y producción" de la DoD.

No se fija un objetivo de latencia hasta medir un perfil de carga; los objetivos de las APIs de emisión no se aplican automáticamente.

## Integración con lo que ya existe

La verificación de credenciales y la autenticación de la consola son mecanismos distintos. La primera ocurre entre wallet y verifier, sin sesión de operador; la segunda es OIDC/BFF para el panel. No se reutiliza el login ni los tokens `operator` para verificar.

| Pieza existente | Uso en esta feature |
| --- | --- |
| Tenants y RLS ([persistencia](../../03-design/console-persistence.md)) | Solo cuando exista Verifier-as-a-Service: client, audience y claves pertenecen al verifier/tenant (perfil §10). No aplica al incremento base. |
| Auditoría ([AUTH-T09](../../03-design/console-auth-audit.md)) | Reutilizar el puerto de auditoría para registrar digest, resultado y razones no sensibles. |
| Scopes reservados `issuer:read`, `definition:read`, `issuance:read`, `status:read` | Siguen sin concederse. Un cambio de la matriz requiere su propio contrato y ADR. |
| Dashboard [FEAT-003](../FEAT-003-dashboard/spec.md) | Podría mostrar lecturas agregadas cuando exista el dominio; se decide en DASH-T05, no aquí. |
| Clases de token del perfil §6 | Un token de integración o de operador nunca actúa como holder ni autoriza verificar. |

## Trazabilidad y decisiones

HK-043 y HK-056 ([backlog Team 5](../../02-requirements/backlogs/team-5-hukid.md)); [perfil §2, §3, §4.1, §5, §9, §10 y §12](../../03-design/hukid-profile.md); [arquitectura §3.9](../../03-design/hukid-architecture.md) y [ADR-0001](../../decisions/ADR-0001.md) (punto 6: API modular y worker, sin microservicio por módulo). El diseño del módulo y sus límites están en el [ADR-0030](../../decisions/ADR-0030.md), que es una propuesta. Las decisiones #1–#4 las tomó el asistente por delegación del owner el 2026-11-11, de forma revocable y sin modificar el núcleo: ver [ADR-0031](../../decisions/ADR-0031.md).
