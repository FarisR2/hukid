# FEAT-004 — Tareas

Estado: **propuesta; ninguna tarea iniciada**. Las casillas se marcan solo con implementación y evidencia. Owner: Team 5, backend. Las tareas VER-T09–T13 están diferidas por dependencias externas a esta feature; HK-043 no queda completa hasta cerrar VER-T09 y VER-T13.

| Estado / ID | Objetivo y artefacto | Depende de | Componentes | Aceptación / verificación | Riesgo |
| --- | --- | --- | --- | --- | --- |
| [x] VER-T01 | Fijar el contrato del reporte, el conjunto cerrado de códigos de fallo y los vectores sintéticos base. | Perfil v0.1-draft | `internal/verification`, vectores | VER-FR07/FR09: el reporte distingue `pass`/`fail`/`skipped`; los vectores validan y se rotulan sintéticos. | Códigos ambiguos. |
| [x] VER-T02 | Validar el formato `vc+jwt`: header, payload VCDM directo, sin contenedor `vc`. | VER-T01 | Parser y reglas puras | VER-FR01/AC01 y VER-QR05: casos negativos del header y el payload y límites de tamaño. | Aceptar `alg` no permitido. |
| [x] VER-T03 | Consumir la clave del puerto `IssuerKeyResolver` y verificar la firma ES256. | VER-T02 | Resolver en memoria, firma | VER-FR02/FR03 y VER-QR01: `jku`/`jwk` en la credencial, `kid` desconocido, issuer distinto, firma alterada y clave retirada pero publicada. Las reglas de host y redirects no se prueban aquí (VER-T12). | Resolver que sale a la red. |
| [ ] VER-T04 | Evaluar vigencia con `Clock` inyectado y tolerancia explícita. | VER-T02 | Reglas de tiempo | VER-FR04/AC04: bordes de `validFrom`/`validUntil` y tolerancia acotada. | Zona horaria o desfase. |
| [ ] VER-T05 | Comprobar holder binding y vínculo de la VP con la solicitud, con `ReplayStore`. | VER-T03 | VP, `cnf.jkt`, anti-replay | VER-FR05/FR06 y VER-QR03: otra clave invalida el binding; nonce/state reutilizado y audience equivocada fallan. | Comparación no constante. |
| [ ] VER-T06 | Aislar la `TrustPolicy` como puerto independiente. | VER-T03 | Puerto y política de laboratorio | VER-FR07/AC07: confianza no altera la validez técnica y viceversa. | Mezcla de criterios. |
| [ ] VER-T07 | Ejecutar la matriz negativa completa, verificar la no persistencia y **crear el chequeo de imports** (hoy inexistente). | VER-T02–T06 | Pruebas unitarias/integración, regla de imports | VER-FR08/AC08 y VER-QR02/QR04: ningún JWS ni claims en salidas; contexto no listado rechazado; el chequeo falla si el paquete importa `internal/authentication` o `net/http`, y corre en CI. | Fuga en logs o reporte. |
| [ ] VER-T08 | Documentar el laboratorio, sus límites y la evidencia de [DoD](../../05-delivery/definition-of-done.md): runbook, checks ejecutados y limitaciones. | VER-T07 | Runbook, contrato, pendientes | Incremento V0–V4 identificable; el gate §12, la interoperabilidad externa y los apartados de DoD "Tipo de credencial" y "Release" figuran como abiertos. | Declarar conformance sin evidencia. |
| [ ] VER-T09 | Comprobar status (tipo, purpose, índice, firma, issuer, frescura) con política de fallo explícita. | VER-T07; fase 4 (HK-050/051) | Status | VER-FR10/AC10 con listas reales del dominio; el owner decide el valor por defecto de la política. **Diferida:** no existen listas de status. | Dependencia futura. |
| [ ] VER-T10 | Adaptador OpenID4VP sobre el núcleo. | VER-T08; decisión #1 | Adaptador, persistencia del `ReplayStore` | Se define tras decidir proceso aparte o módulo. **Diferida.** | Decisión abierta. |
| [ ] VER-T11 | Verifier-as-a-Service por tenant y, si se decide, lectura en la consola. | VER-T10; decisiones #1, #2, #3 | Tenancy, RLS, consola | Contrato y ADR propios; sin conceder scopes por inferencia. **Diferida.** | Alcance de producto sin acordar. |
| [ ] VER-T12 | Adaptador HTTPS del resolver: JWKS solo del host del issuer, sin redirects cross-origin ni `jku`. | VER-T03; fase 1 (HK-002, JWKS publicado) | Adaptador, pruebas con servidor local | VER-FR11/AC11: JWKS de otro host y redirects cross-origin rechazados. **Diferida:** no hay publicación de JWKS. | Reglas de host aplicadas en el lugar equivocado. |
| [ ] VER-T13 | Validar `credentialSchema` y contextos versionados contra la definition. | VER-T07; fase 2 (HK-003) | Schema, `ContextLoader` | VER-FR12/AC12 con definitions publicadas. **Diferida:** no existe el Definition Registry. | Dependencia futura. |

## Evidencia

**VER-T01 (2026-11-10).** Paquete `src/platform/internal/verification`: `report.go` (reporte con `pass`/`fail`/`skipped`, 20 códigos cerrados con `CodesVersion = 1`, `technicalResult` derivado de las comprobaciones, `trust` aparte y digest SHA-256), `report_test.go` y `vectors_test.go` con `testdata/vectors.json` (9 vectores sintéticos: 1 válido y 8 negativos). Las claves privadas de prueba son efímeras y no se versionan; el generador solo corre con `HUKID_UPDATE_VECTORS=1`. Una verificación independiente de los vectores, hecha solo con la biblioteca estándar, confirma que las firmas coinciden con lo declarado. Verificado: `gofmt`, `go vet` y `go test ./internal/verification/` en Windows con el toolchain local Go 1.27.3. **No verificado:** no hay verificador todavía; las reglas de formato, vigencia y binding de los vectores se ejercitan en VER-T02 a VER-T05. Los vectores no son evidencia de interoperabilidad externa.

**VER-T02 (2026-11-10).** `parse.go` y `parse_test.go`: `ParseCredential` aplica las reglas de formato del perfil §2 (header `ES256`/`vc+jwt` con `kid`, sin contenedor `vc`, sin `iss`/`nbf`/`sub` duplicados, contexto VCDM base, JSON estricto sin miembros duplicados ni datos finales) y los límites propuestos de VER-QR05 (16 KiB por JWS, 8 niveles de profundidad). Los headers `jku`, `jwk`, `x5u` y `x5c` no se rechazan aquí: se registran para el chequeo de clave de VER-T03. Verificado: `gofmt` y `go vet` en local; `go test ./internal/verification/` **en CI** (run `42950428270`, `workflow_dispatch` sobre la rama, conclusión `success`, paso del gate que ejecuta `go test ./...`). **No verificado en local:** Application Control bloqueó dos veces el binario de prueba de este paquete; no se esquivó. Los límites de QR05 siguen siendo propuesta pendiente del owner.

**VER-T03 (2026-11-10).** `keys.go` (puerto `IssuerKeyResolver`, `ResolvedKey` y `MemoryKeyResolver` de laboratorio, solo P-256) e `integrity.go` (`checkIssuerKey`, `checkSignature` ES256 y `integrityChecks`, que encadena formato, clave y firma). Reglas: los headers de clave propios de la credencial se rechazan **antes** de cualquier búsqueda (`key.untrusted_header`); `kid` no publicado da `key.unknown_kid`; un emisor distinto del dueño de la clave da `key.issuer_mismatch`; firma alterada, de otra clave o con longitud o valores inválidos da `signature.invalid`; una clave retirada pero publicada sigue verificando. Tras un fallo, las comprobaciones siguientes quedan `skipped` (requeridas), nunca `pass`. Un fallo del propio resolver (distinto de `ErrKeyNotFound`) se devuelve como error `ErrKeyResolution`, no como un hallazgo sobre la credencial: el conjunto de códigos es cerrado y no hay uno para "no se pudo resolver". Las reglas de host y redirects siguen en VER-T12. Verificado: `gofmt`, `go vet` y `go test ./internal/verification/` en local (94 pruebas y subpruebas pasan, 0 fallan, 1 omitida: el generador de vectores). Application Control bloqueó el binario de prueba en intentos anteriores de este paquete y esta vez no; el resultado local no es reproducible a voluntad, por eso el CI sigue siendo la verificación de referencia.

## Cobertura requisito → aceptación → tarea

| Requisito | AC | Tareas |
| --- | --- | --- |
| VER-FR01 | AC01 | VER-T02, VER-T07 |
| VER-FR02 | AC02 | VER-T03, VER-T07 |
| VER-FR11 | AC11 | VER-T12 |
| VER-FR12 | AC12 | VER-T13 |
| VER-FR03 | AC03 | VER-T03, VER-T07 |
| VER-FR04 | AC04 | VER-T04, VER-T07 |
| VER-FR05 | AC05 | VER-T05, VER-T07 |
| VER-FR06 | AC06 | VER-T05, VER-T07 |
| VER-FR07 | AC07 | VER-T01, VER-T06 |
| VER-FR08 | AC08 | VER-T07 |
| VER-FR09 | AC09 | VER-T01, VER-T08 |
| VER-FR10 | AC10 | VER-T09 |
| VER-QR01 | AC02/03 | VER-T03 |
| VER-QR02 | AC02 | VER-T07 |
| VER-QR03 | AC05 | VER-T05 |
| VER-QR04 | AC08 | VER-T07 (crea el chequeo) |
| VER-QR05 | AC01 | VER-T02, VER-T07 |

## Orden y trabajo diferido

VER-T01 fija el contrato antes de cualquier regla. VER-T02 a VER-T04 forman el núcleo de credencial; VER-T05 añade la presentación y VER-T06 puede avanzar en paralelo tras VER-T03. VER-T07 y VER-T08 cierran el laboratorio. VER-T09–T11 no se inician hasta que existan los módulos o decisiones de la columna de dependencias. Completar V0–V4 no cierra el conformance gate del perfil ni habilita producción.
