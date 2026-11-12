# Operar el laboratorio del núcleo de verificación

Owner: Team 5. Alcance: VER-T01–T07 de [FEAT-004](../features/FEAT-004-credential-verification/spec.md), solo laboratorio, con claves y credenciales sintéticas. Es un módulo de librería sin proceso, puerto ni endpoint: este procedimiento sirve al desarrollador que ejecuta, diagnostica o extiende sus pruebas; no es un despliegue. El [contrato](../03-design/credential-verification-contract.md) define las salidas y los códigos, y el [gate V4](../05-delivery/verification-gate.md) conserva la evidencia y lo que sigue abierto.

## Ejecutar las pruebas

1. Usar las versiones de [desarrollo local](local-development.md): Go 1.27.3 exacto con `GOTOOLCHAIN=local`. No requiere PostgreSQL, Node ni navegador.
2. Desde `src/platform`, ejecutar `go test ./internal/verification/ -count=1`. Para todo el backend, desde la raíz, `npm run check:platform`.
3. En Windows con Application Control, el binario de prueba de este paquete puede bloquearse de forma intermitente (`An Application Control policy has blocked this file`). No renombrarlo, moverlo ni cambiar rutas para esquivar el bloqueo: es un control de la máquina. Reintentar el mismo comando o usar el CI.
4. Verificación de referencia: el workflow `Authentication laboratory` ejecuta `go test ./...` e incluye este paquete. Se lanza en un PR, en un push a `develop` o `main`, o a mano con `gh workflow run authentication.yml --ref <rama>`. Un nuevo lanzamiento sobre la misma rama cancela el que esté en curso.
5. Aceptar el resultado solo con `ok hukid.local/platform/internal/verification` en el log del paso `Run authentication, members and dashboard laboratory gate`. Una prueba de navegador del panel (`TestConsoleBrowser`) falló una vez de forma intermitente sobre un commit que no la toca y pasó al reintentar; no está relacionada con este módulo, pero conviene anotarla si se repite.

## Regenerar los vectores

`testdata/vectors.json` se genera, no se edita a mano. Las claves del emisor y del holder son efímeras: el generador descarta las privadas y no las guarda en ningún sitio, por lo que los vectores no se pueden "re-firmar" más tarde.

1. Desde `src/platform`: `HUKID_UPDATE_VECTORS=1 go test ./internal/verification/ -run TestGenerateVectors -count=1`. En PowerShell, asignar la variable con `$env:HUKID_UPDATE_VECTORS="1"` y retirarla después.
2. Se reescriben **todas** las firmas (claves nuevas). Ejecutar de inmediato la suite completa y revisar el diff: la estructura, los identificadores y las expectativas deben ser los mismos.
3. Añadir un vector negativo exige una fila en la matriz de `matrix_test.go`; sin ella `TestEveryVectorIsInTheMatrix` falla.
4. Si cambia el conjunto de códigos, subir `CodesVersion` y actualizar el tamaño esperado en `report_test.go` y la tabla del contrato; los vectores guardan la versión y la suite falla si no coincide.
5. Los vectores son sintéticos y no prueban interoperabilidad con ningún verifier, wallet o emisor externo. No usar sus claves ni emisor como identidad real.

## Usar el módulo desde código

El paquete es `internal`: solo lo importa código del módulo `hukid.local/platform`. Configuración mínima:

```go
verifier, err := verification.NewVerifier(keys, clock, verification.DefaultLimits, verification.DefaultClockSkew)
verifier = verifier.WithReplayStore(store).WithTrustPolicy(policy) // ambos son opcionales
report, err := verifier.Verify(jws)
presentation, err := verifier.VerifyPresentation(
    verification.Response{VP: vp, State: responseState},
    verification.Request{Audience: audience, Nonce: nonce, State: state},
)
```

`keys` implementa `IssuerKeyResolver`; `clock`, `Clock`; `store`, `ReplayStore` (obligatorio para presentaciones); `policy`, `TrustPolicy`. En laboratorio se usan `MemoryKeyResolver`, `ClockFunc`, `MemoryReplayStore` y `AllowlistTrustPolicy`. Los de producción pertenecen a los adaptadores diferidos. Para aceptar un contexto JSON-LD adicional, `WithCredentialContexts("https://…")`, y solo cuando una definición publicada lo requiera.

## Diagnóstico

| Síntoma | Comprobación y acción |
| --- | --- |
| `ErrConfig` | `NewVerifier` rechaza dependencias nulas, límites no positivos o una tolerancia fuera de 0 a 5 min. `VerifyPresentation` sin `WithReplayStore` también devuelve `ErrConfig`. |
| `ErrKeyResolution`, `ErrTrustPolicy`, `ErrReplayStore` | Falló una dependencia, no la credencial; no hay reporte. El mensaje envuelve solo el error de la dependencia. Reintentar tras resolverla. Nunca traducirlo a un resultado inválido. |
| `technicalResult` `invalid` con `skipped.precondition_failed` | Un criterio previo falló; buscar el primer `fail` en `checks`. Esas omisiones son requeridas y no cuentan como `pass`. |
| `invalid` sin ningún `fail` y con `skipped.not_implemented` | La credencial declara `credentialStatus` o `credentialSchema` y esas comprobaciones aún no existen (VER-T09, VER-T13). Es esperado: no se puede afirmar validez de lo que no se comprobó. |
| `format.context_not_allowed` | La credencial usa un contexto fuera de la lista. No añadirlo para "hacer pasar" la credencial: solo si una definición lo requiere y el owner lo aprobó. Nunca se descarga. |
| `key.untrusted_header` | La credencial trae `jku`, `jwk`, `x5u` o `x5c`. El perfil lo prohíbe; no se consulta ninguna clave. |
| `key.issuer_mismatch` | El resolver devolvió una clave cuyo dueño no es el emisor declarado. En el adaptador HTTPS (diferido) indicaría una configuración errónea. |
| `request.replayed` | La solicitud ya recibió una respuesta; abrir una sesión nueva. El almacén de laboratorio no expira ni limita entradas. |
| `binding.mismatch` o `binding.missing_cnf` | La VP la firmó otra clave, o la credencial no está ligada a un holder. No es un fallo de la firma del emisor. |
| `trust` ausente | No hay política configurada. Con política, `notEvaluated` indica que el emisor no quedó autenticado o que la presentación no verificó credenciales. |
| Una prueba falla tras regenerar vectores | Comparar el diff de `vectors.json`. Si cambió el conjunto de códigos, ver el paso 4 de la sección anterior. |

## Retirada

El módulo no se activa por configuración ni deja procesos, datos ni estado. Retirarlo es revertir los commits de FEAT-004. Nada del panel, de AUTH, USR o DASH depende de él, y una prueba impide que el paquete importe otros paquetes de la plataforma.
