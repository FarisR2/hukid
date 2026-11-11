# Gate V4 del núcleo de verificación — VER-T08

Fecha: 2026-11-10. Owner: Team 5. Alcance: V0–V4 de [FEAT-004](../features/FEAT-004-credential-verification/spec.md) en laboratorio, con claves y credenciales sintéticas y sin procesos, base de datos ni red. Este gate cierra el **núcleo técnico** de verificación; **no** cierra HK-043 completa, el conformance gate del perfil ni la preparación productiva. El [contrato](../03-design/credential-verification-contract.md) fija las salidas y el [runbook](../04-engineering/credential-verification-runbook.md) el procedimiento.

## Reproducción y evidencia

Desde `src/platform`: `go test ./internal/verification/ -count=1` (Go 1.27.3, `GOTOOLCHAIN=local`). La referencia es el workflow `Authentication laboratory`, que ejecuta `go test ./...`. Estado de la suite en este commit: 256 pruebas y subpruebas pasan en local, 0 fallan y 1 se omite (el generador de vectores, que solo corre con `HUKID_UPDATE_VECTORS=1`). `gofmt` y `go vet` sin hallazgos.

Ejecuciones del CI sobre la rama `feat/verification-report-contract` (lanzadas a mano con `workflow_dispatch`):

| Run | Alcance | Resultado |
| --- | --- | --- |
| `42950428270` | VER-T01 y T02 | `success` |
| `42951483523` | VER-T03 | Intento 1: `failure` en `TestConsoleBrowser` (prueba del panel que el cambio no toca); intento 2: `success`. `ok .../internal/verification` en ambos. |
| `42952831104` | VER-T04 | `success` |
| `42953955890` | VER-T05 | `success` |
| `42954692403` | VER-T06 y T07 (commit `ddf5153`) | `success`, con `ok .../internal/verification` |

Limitaciones de la evidencia: en la máquina del owner, Application Control bloquea de forma intermitente el binario de prueba de este paquete (no se esquivó), por lo que el CI es la verificación de referencia. El fallo intermitente de `TestConsoleBrowser` se observó una vez y no se investigó su causa.

## Requisitos de FEAT-004

| Requisito | Estado | Tarea |
| --- | --- | --- |
| VER-FR01 formato `vc+jwt` | Cumplido | VER-T02 |
| VER-FR02 vías de clave prohibidas | Cumplido | VER-T03 |
| VER-FR03 firma ES256 | Cumplido | VER-T03 |
| VER-FR04 vigencia con reloj inyectado | Cumplido | VER-T04 |
| VER-FR05 holder binding | Cumplido | VER-T05 |
| VER-FR06 vínculo con la solicitud | Cumplido | VER-T05 |
| VER-FR07 confianza separada | Cumplido | VER-T01, VER-T06 |
| VER-FR08 sin persistencia de material sensible | Cumplido en el módulo; el adaptador deberá probarlo en su alcance | VER-T07 |
| VER-FR09 vectores reproducibles | Cumplido como vectores **sintéticos**; no son evidencia de interoperabilidad | VER-T01, T05, T07 |
| VER-FR10 status | **Abierto** (diferido) | VER-T09 |
| VER-FR11 resolución HTTPS del JWKS | **Abierto** (diferido) | VER-T12 |
| VER-FR12 schema | **Abierto** (diferido) | VER-T13 |
| VER-QR01 sin red | Cumplido | VER-T07 |
| VER-QR02 contextos permitidos | Cumplido como lista permitida; no hay expansión JSON-LD | VER-T07 |
| VER-QR03 comparaciones en tiempo constante | Cumplido para thumbprint, audience, nonce y state. El módulo no compara digests: solo los produce. | VER-T05 |
| VER-QR04 sin dependencia de otros paquetes | Cumplido, con chequeo automático en `go test` que cubre imports directos, no transitivos | VER-T07 |
| VER-QR05 entrada acotada | Cumplido con valores **propuestos** pendientes del owner | VER-T02, T05 |

Los 20 escenarios de la matriz negativa pasan; cada vector negativo nuevo debe tener su fila.

## Definition of Done

Correspondencia con la [DoD](definition-of-done.md):

| Apartado | Estado |
| --- | --- |
| Historia o cambio: actor, owner, alcance y aceptación | Cumplido (spec) |
| Contrato versionado antes de integrar | Cumplido: [contrato](../03-design/credential-verification-contract.md) y `CodesVersion`. No existe API ni evento externo todavía. |
| Pruebas negativas de estado, autorización y aislamiento | Cumplido para el núcleo. El aislamiento por tenant no aplica a este incremento. |
| Idempotencia y concurrencia | Cumplido para el almacén de replay (consumo atómico probado con 64 llamadas concurrentes). No hay efectos reintentables. |
| Migraciones y RLS | No aplica: no hay persistencia. |
| Métricas, trazas y auditoría sin PII | **Abierto.** El módulo no emite métricas ni trazas ni tiene sumidero de auditoría; es trabajo del adaptador (VER-T10). |
| Journey y accesibilidad | No hay interfaz. El recorrido real wallet → verifier **no se ha probado**. |
| Runbook y documentación | Cumplido: este gate, el contrato y el runbook. |
| Evidencia de checks y limitaciones | Cumplido: esta página. |
| **Tipo de credencial HukID** (propósito, amenaza, claims, definition, retención, recuperación, trust policy y caso de uso del verifier, pruebas de emisión) | **Abierto.** Depende de la decisión #4 y de las fases 2 y 3. |
| Integración Events→HukID | No aplica a este incremento. |
| **Release y producción** (restauración, SLO y carga, rotación, alertas, retención) | **Abierto.** |

## Conformance gate del perfil (sección 12)

Ninguno de estos puntos cierra el gate: el perfil sigue en `v0.1-draft`.

| Punto del perfil | Estado |
| --- | --- |
| VC completa y *context expansion* con vectores positivos y negativos | Parcial: hay vectores y lista de contextos permitidos; **no hay expansión JSON-LD**. |
| Header `vc+jwt`, payload VCDM directo y ausencia del contenedor `vc` | Cumplido con vectores sintéticos. |
| Proof → `cnf.jkt` → firma de la VP con la misma clave, y rechazo con otra | Cumplido **en el lado del verifier**. El proof JWT de OpenID4VCI (lado de emisión) no existe. |
| Rechazo cruzado de las tres clases de token | **Abierto**: fuera del alcance de este módulo. |
| Offers con y sin `tx_code`, nonce, caída de KMS o base de datos, status y rotación de claves | **Abierto.** Solo está probado que una clave retirada pero publicada sigue verificando. |
| Request firmado, respuesta cifrada, audience, nonce, state y replay en OpenID4VP | Parcial: audience, nonce, state y replay de la VP están probados; **request firmado y respuesta cifrada (`direct_post.jwt`) no**. |
| Presentación a un verifier externo compatible sin contactar a HukID | **Abierto**: no se probó ninguna interoperabilidad externa. |
| Publicar vectores exactos con headers, payloads, claves públicas, firmas y resultados | Parcial: están en `testdata/vectors.json`, pero son sintéticos y la forma de la VP está inferida porque el ejemplo de referencia no está en el repositorio. |

## Lo que sigue abierto

- VER-T09 (status), VER-T12 (adaptador HTTPS del resolver) y VER-T13 (schema), que además cierran HK-043.
- VER-T10 y VER-T11 (adaptador OpenID4VP y Verifier-as-a-Service), bloqueadas por las decisiones #1, #2 y #3.
- La aprobación del owner de los valores propuestos (límites de entrada, tolerancia de reloj, lista de contextos) y del propio FEAT-004 y [ADR-0030](../decisions/ADR-0030.md), que figuran como propuestas.
- La política de confianza de producción y su origen.
- El payload del primer documento del piloto (decisión #4) y las fases 1 a 3 del [roadmap](hukid-roadmap.md): sin emisión no hay credenciales reales que verificar.
