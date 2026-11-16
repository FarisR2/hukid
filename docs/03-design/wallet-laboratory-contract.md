# Contrato de recepción wallet — laboratorio v1

T2 prepara datos ejecutables para una demo ficticia de taller, no una certificación
académica ni evidencia de asistencia real. No confiere derechos, acceso, créditos
ni habilitación. No cambia la prioridad del piloto POS ni acredita interoperabilidad.
Decisión y excepciones: [ADR-0033](../decisions/ADR-0033.md).

## Definición cerrada y artefactos offline

`src/platform/internal/issuancecontract` expone `New(origin) (Definition, error)`,
`Issuer()`, `Example() Credential`, `Validate(Credential) error`, `Schema()` y
`Context()` (bytes nuevos). `ConfigurationID = lab.workshop.vc-jwt.v1`.
Errores fijos: `ErrOrigin`, `ErrCredential`; sin claims en errores ni efectos laterales.

| Elemento | Regla v1 |
| --- | --- |
| Origen | Configurado por operador; HTTPS sin usuario, ruta, query ni fragmento; puerto 1–65535 si se especifica; sin puerto explícito se usa el predeterminado de HTTPS. No derivarlo de una VC no autenticada. |
| Issuer | `{origin}/wallet-lab`; ejemplo reservado `https://wallet-lab.example:8443`, no despliegue real. |
| ID | `{issuer}/credentials/{id}`; segmento de 1–64 caracteres ASCII alfanuméricos o guion. T3 asigna unicidad. |
| Tipo | `VerifiableCredential`, `DemoWorkshopCredential`, en ese orden. |
| Contextos | Base VCDM 2.0 y `{issuer}/contexts/workshop/v1`, en ese orden. |
| Schema local | `{issuer}/schemas/workshop/v1`; JSON Schema 2020-12 con `const` del subject completo. |
| Subject | Sólo `demo: true`, `workshop: Taller ficticio de wallet`, `participation: simulated`. Sin identidad personal ni `subject.id`. |
| Binding | `cnf.jkt` raíz, base64url canónico de 32 bytes. Es sintaxis, no prueba de posesión. Holder no equivale a subject. |
| Tiempo | `validFrom` RFC3339 UTC canónico con segundos; sin `validUntil`. La validación de forma no evalúa vigencia actual. |
| Status | **No aplicable** en esta definición; sin `credentialStatus`, sin afirmar revocación comprobada. |

Los [fixtures](../../src/platform/internal/issuancecontract/fixtures/) son plantillas
versionadas: sólo se sustituye `{issuer}` desde configuración. No se hace fetch remoto.
La igualdad tipada del subject implementa la regla `const` del schema registrado;
no es un motor JSON Schema genérico ni un Definition Registry productivo.
No se incluye `credentialSchema`: no está implementado el perfil VC JSON Schema
para la VC completa. El contexto define términos de demo y binding, sin expansion
JSON-LD comprobada ni conformance declarado. Cambios semánticos requieren nueva versión.

## Uso seguro por T3 y T4

`Example()` es JSON sin firma con ID/fecha/thumbprint sintéticos; nunca se entrega
como credencial válida. T3 reemplaza esos tres valores, valida la forma y firma
el payload VCDM directo (sin `vc`, `iss`, `nbf`, `sub`) con ES256, `typ=vc+jwt`,
`kid` del issuer y preferentemente `cty=vc`. Sólo anuncia `application/vc+jwt`
a clientes que implementan esa extensión HukID sobre OID4VCI 1.0 Final.

T3 implementará oferta de un uso/TTL ≤300 s, canje y validación backend de `proofs.jwt`,
proof `openid4vci-proof+jwt` con JWK pública y aud/iat/nonce exactos, cálculo RFC7638,
clave pública confiable propiedad del issuer y respuesta `credentials` plural.
No hay handlers, signer ni comprobaciones de challenge en T2.
T4 debe rechazar JSON desconocido/duplicado o arrays de longitud incorrecta **antes**
de convertir a tipos Go/Dart: `Validate` no es un parser de JSON no confiable.
Validación de modelo/schema local no sustituye firma, issuer/kid, trust, tiempo,
binding ni HTTPS con certificado y hostname validados. No relajar `verification`:
sigue rechazando schema/status declarados sin implementación; ADR-0031 permanece vigente.

T4 implementará preview y consentimiento explícito en Flutter antes de solicitar
la emisión. T3 validará las condiciones del protocolo en backend; un canje o proof
válido no demuestra por sí solo consentimiento humano ni sustituye esa interfaz.
T5 mantiene cifrado local completo, claves no exportables Android Keystore y
persistencia segura tras reinicio.
## T3a: ciclo puro de código preautorizado

`src/platform/internal/issuance` añade `NewOfferStore(OfferConfig)`, `Create()` y
`Redeem(code)`. Configuración explícita: `0 < TTL <= 300 s`, `Capacity > 0`;
`Now` y `Random` opcionales usan reloj del sistema y `crypto/rand`. Las inyecciones
se serializan y no deben reentrar al almacén. Cada oferta devuelve un código bearer
aleatorio de 32 bytes y un ID independiente no secreto de 32 bytes, ambos base64url
sin padding, más `ExpiresAt`. No registrar el código; sólo se devuelve al crearlo.

Se retienen únicamente SHA-256 con separación de dominio, ID, expiración y estado.
El canje es atómico y de un uso: devuelve `Redemption{ID, ExpiresAt}`, **no** access
token, consentimiento, proof ni credencial. En la expiración exacta se rechaza.
Desconocido, malformado, expirado y consumido producen `ErrInvalidCode`
(`invalid pre-authorized code`). Configuración, capacidad, entropía y colisión
usan `ErrConfig`, `ErrStoreFull`, `ErrEntropy`, `ErrCollision`, sin entrada cruda.
Los fallos no insertan ni sobrescriben ofertas. La creación barre expirados;
los consumidos cuentan hasta expirar y nunca se desalojan registros vivos.

Sólo memoria de un proceso: reiniciar pierde todo; no hay coordinación de réplicas,
HTTP, QR, JWT, signer ni emisión. Resolver la entrega recuperable del código y las
garantías de reintento/reinicio queda pendiente para T3d. Rollback T3a: retirar
`issuance/offers.go`, `issuance/offers_test.go` y esta sección; sin consumidores runtime.

No se ha entregado una wallet funcional ni probado teléfono/interoperabilidad.
Rollback T2: retirar el paquete, este contrato, ADR-0033 y el enlace de API;
no hay estado persistido, migraciones ni consumidores runtime que deshabilitar.
