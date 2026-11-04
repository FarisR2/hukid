# Estrategia de pruebas

Documento de estrategia. AUTH-T01 incorpora pruebas Go del perímetro del bootstrap (dirección loopback, liveness, métodos y ausencia de rutas de autenticación), typecheck y builds; ver [desarrollo local](local-development.md). Las suites funcionales de las capas siguientes siguen pendientes: se derivan de criterios originales y deben aportar evidencia al release gate.

AUTH-T02 añade pruebas de OpenAPI/ejemplos, política temporal/configuración Go y un AS OIDC de laboratorio con JWT operator/refresh firmados. La evidencia de MFA es sintética y no sustituye tests del futuro middleware, DB/RLS, sesión, factores reales o navegador. Alcance y matriz de escenarios en el [contrato de consola](../03-design/console-auth-contract.md#pruebas-y-cobertura-actual).

AUTH-T03 añade `npm run test:postgres`: ocho pruebas Go de integración, sin skip, en clúster PostgreSQL descartable. Verifica migración vacía/previa con datos, RLS/roles, tenants, pool, FK, bootstrap/CLI y forma de envelopes. Se ejecuta por separado de `npm run check`; las futuras pruebas de sesión/HTTP, restore y carga no se infieren de este resultado. Detalle en [persistencia](../03-design/console-persistence.md#pruebas-y-límites).

| Capa / riesgo | Pruebas necesarias |
| --- | --- |
| Dominio | Estados permitidos/prohibidos, eligibility/versiones, expiración, grant/policy y definición inmutable. |
| Contratos | OpenAPI/AsyncAPI/JSON Schema validables, ejemplos, compatibilidad y tests productor-consumidor. |
| Datos | Migración vacía/previa, constraints, RLS con dos tenants, pool reuse, legal hold y purga. |
| Concurrencia | Cupo/waitlist, ticket/check-in, canje de oferta, request duplicado y firma con CAS/lease. |
| Fallos | Timeout después de commit, caída entre DB/KMS/object store, replay/outbox, deferred y reconciliación. |
| Identidad | Roles/scopes, recursos ajenos, clases operator/integration/oid4vci y audiencias incorrectas. |
| Criptografía HukID | Payload VCDM directo, header/alg/kid, firma alterada, proof/nonce y binding cnf.jkt. |
| Status | Suspender/reactivar/revocar, purpose/índice/firma/freshness, desired vs published y rotación. |
| Wallet | Dispositivos Flutter, key storage, QR/deep link, consentimiento, error/expiración y persistencia cifrada. |
| Presentación | Request autenticado, respuesta cifrada, audience/state/nonce/replay y verifier externo compatible. |
| UX/accesibilidad | Teclado/foco/lector, cámara/conectividad, móvil/escritorio y estados loading/empty/error/forbidden. |
| Rendimiento | Perfiles del piloto, límites DB/KMS/colas, p95 y ausencia de duplicados/sobrecupo bajo carga. |
| Continuidad | Restore DB+objetos+status+metadata, reconciliación y ofertas expiradas que no reviven. |
| Privacidad | Redacción de logs/trazas/DLQ, consentimiento y ausencia de claims/tokens en telemetría. |

## Flujos de aceptación

1. Publicar evento y materializar la misma release en consumidores.
2. Registrar concurrentemente, confirmar/waitlist, emitir QR y rechazar revocado en check-in.
3. Generar PDF elegible, solicitar HukID con consentimiento y reintentar sin duplicado.
4. Abrir oferta, autorizar destinatario según policy, emitir/guardar wallet y reconciliar mediante polling v0.
5. Cuando entre en alcance: presentar a verifier compatible, comprobar status y rechazar replay/otra clave holder.

## Gate HukID

Mantener v0.1-draft hasta publicar vectores exactos positivos/negativos y automatizar el [conformance gate](../03-design/hukid-profile.md#12-conformance-gate). No afirmar interoperabilidad universal por usar OpenID/VCDM. Probar primero wallet/verifier de referencia y documentar implementaciones externas efectivamente verificadas.

## Criterio de evidencia

Registrar escenario, versión, ambiente, carga, resultados y limitaciones. Medir los [objetivos no funcionales](../02-requirements/non-functional-requirements.md); no convertirlos en SLA sin pruebas. Aplicar la [Definition of Done](../05-delivery/definition-of-done.md).

En documentación, verificar enlaces/anclas locales, bloques y estructura con `npm run check:docs` y revisión de diff. Declarar únicamente pruebas de componentes existentes y efectivamente ejecutadas.
