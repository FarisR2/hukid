# FEAT-004 — Plan técnico

Referencia: [spec](spec.md), [tareas](tasks.md), [ADR-0030](../../decisions/ADR-0030.md), [perfil HukID](../../03-design/hukid-profile.md). Todo lo de abajo es **propuesta**; no existe ninguno de estos paquetes.

## Arquitectura propuesta

Un paquete interno del backend modular, sin proceso nuevo. HukID arranca como API modular y worker, "sin crear un microservicio por módulo" ([ADR-0001](../../decisions/ADR-0001.md)); cómo se despliega el Verifier-as-a-Service opcional sigue abierto (decisión #1) y este plan no lo fija.

| Componente propuesto | Responsabilidad |
| --- | --- |
| `src/platform/internal/verification` | Casos de uso `VerifyCredential` y `VerifyPresentation`; reglas puras del perfil; reporte técnico. |
| Puerto `IssuerKeyResolver` | Devuelve la clave pública de un `kid` para un issuer. La implementación de laboratorio lee un JWKS en memoria. Las reglas de host único y de redirects del perfil §3 pertenecen al adaptador HTTPS real (VER-T12, fase 1), no al núcleo, que no hace red. |
| Puerto `Clock` | Reloj inyectable para vigencia y expiración. |
| Puerto `ReplayStore` | Registra `nonce`/`state` usados. Implementación en memoria para laboratorio; una persistente queda para el adaptador. |
| Puerto `ContextLoader` | Entrega solo contextos JSON-LD allowlisted. |
| Puerto `TrustPolicy` | Decide si se confía en el issuer, separado de la validación criptográfica. |
| Puerto `Auditor` | Reutiliza la auditoría existente; solo digest, resultado y códigos. |

La librería no importa `net/http`, `database/sql` ni `internal/authentication`. Esto hace verificable VER-QR01 y VER-QR04 y permite montarla después como módulo de la API, como worker o como proceso aparte sin reescribirla.

## Contrato del reporte

Una verificación devuelve un reporte estructurado, nunca un booleano:

| Campo | Contenido |
| --- | --- |
| `checks[]` | Una entrada por criterio: `format`, `issuerKey`, `signature`, `validity`, `holderBinding`, `requestBinding` y, cuando aplique, `status`. Cada una con `result` (`pass`/`fail`/`skipped`) y `code` estable. |
| `technicalResult` | `valid` solo si todas las comprobaciones exigidas pasan. |
| `trust` | Resultado de la `TrustPolicy`, en un campo aparte; ausente si no se evaluó. |
| `digest` | SHA-256 de lo verificado. |

Los códigos de fallo son un conjunto cerrado y versionado; no incluyen claims ni el JWS. `skipped` se distingue de `pass`: un criterio no evaluado nunca se presenta como superado.

## Datos y persistencia

El incremento base no necesita tablas ni migraciones: [no hay tablas de credenciales](../../05-delivery/documentation-gaps.md) y esta feature no las crea. El único estado es el `ReplayStore`, en memoria para laboratorio. Persistirlo, con TTL y por verifier, es parte del adaptador OID4VP y exige su propio diseño de datos y RLS.

## Pruebas y vectores

Las claves de prueba son sintéticas y deterministas. Los vectores se generan con el propio código del laboratorio y declaran en su cabecera que son sintéticos. No sustituyen el [conformance gate del perfil §12](../../03-design/hukid-profile.md), que exige además un verifier externo compatible; ese punto sigue abierto. No se inventan vectores firmados a partir de los artefactos ausentes registrados en [pendientes](../../05-delivery/documentation-gaps.md).

Matriz negativa mínima: header incorrecto, `alg` alterado, contenedor `vc`, `jku`/`jwk` en la credencial, `kid` desconocido, issuer distinto, firma alterada, credencial futura y vencida, `cnf.jkt` distinto, VP con otra clave, nonce/state reutilizado, audience equivocada y entradas sobredimensionadas.

## Hitos y dependencia real

| Hito | Requisitos previos | Gate |
| --- | --- | --- |
| V0 — Contrato y vectores | Perfil v0.1-draft | VER-T01: códigos de fallo, forma del reporte y vectores sintéticos que validan. |
| V1 — Núcleo de credencial | V0 | VER-T02–T04: formato, resolución de clave, firma y vigencia con la matriz negativa correspondiente. |
| V2 — Presentación y binding | V1 | VER-T05: holder binding y vínculo con la solicitud. |
| V3 — Separación de confianza | V1 | VER-T06: `TrustPolicy` como puerto independiente. |
| V4 — Cierre del laboratorio | V2, V3 | VER-T07/T08: matriz completa, no persistencia y documentación de límites. |
| V5 — Status y schema | Fase 4 (status lists, HK-050/051) y fase 2 (HK-003) | VER-T09 y VER-T13, diferidas. Cierran HK-043. |
| V6 — Adaptadores y exposición | Fase 1 (JWKS) y decisiones #1, #2 y #3 | VER-T10/T11/T12, diferidas. |

## Riesgos

- **Confundir laboratorio con interoperabilidad.** Mitigación: los vectores se rotulan sintéticos y el gate §12 permanece abierto.
- **Mezclar validez técnica con confianza.** Mitigación: `trust` es un campo y un puerto aparte, con pruebas de que no se afectan.
- **Fijar el payload antes de la decisión #4.** Mitigación: tipo sintético en el laboratorio; el payload de negocio entra con su propia tarea.
- **Acoplar verificación a la autenticación de la consola.** Mitigación: chequeo de imports y la regla de clases de token del perfil §6.
