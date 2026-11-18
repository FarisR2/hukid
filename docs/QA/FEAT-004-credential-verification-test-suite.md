# Suite de pruebas de caja negra — FEAT-004 Verificación de credenciales

- Feature: [FEAT-004](../features/FEAT-004-credential-verification/spec.md) · Contrato: [credential-verification-contract.md](../03-design/credential-verification-contract.md) (códigos versión 2).
- Estándares: ISO/IEC/IEEE 29119-3 (documentación) y 29119-4 (técnicas); ISO/IEC 25010, adecuación funcional.
- Estado: **ejecutada el 2026-11-18** en local con el Go 1.27.3 del proyecto: 93 casos pasan y 1 queda omitido a propósito (CP-71, hallazgo H-07). Total: 94 casos. Ver [§8 Ejecución](#8-ejecución).
- Objeto bajo prueba: módulo interno sin HTTP ni base de datos. La "interfaz" observable es el reporte (`technicalResult`, `checks[]` con `code`, `trust`, `digest`), los errores de configuración (`ErrConfig`) y el estado de la solicitud anti-replay.

## 1. Entorno y datos base

| Alias | Definición |
| --- | --- |
| **E-BASE** | Verifier con resolver de claves que publica `kA1` (clave del issuer A) y `kB1` (clave del issuer B). Reloj fijo en `2026-06-15T12:00:00Z`. Tolerancia de reloj por defecto (1 min). Límites por defecto. Almacén anti-replay vacío. Sin trust policy salvo que el caso diga otra cosa. Claves y vectores sintéticos. |
| **VC-OK** | Credencial `vc+jwt` ES256 del issuer A firmada con `kA1`. `validFrom=2026-01-01T00:00:00Z`, `validUntil=2027-01-01T00:00:00Z`. `cnf.jkt` = thumbprint RFC 7638 de la clave del holder H1. Contexto base VCDM 2.0. Sin `credentialStatus` ni `credentialSchema`. |
| **VC-T** | Como VC-OK, pero `validFrom=2026-06-15T12:00:00Z` y `validUntil=2026-06-15T13:00:00Z`. Se usa en los casos de vigencia. |
| **VP-OK** | Presentación `vp+jwt` firmada con H1 (JWK en el header) que envuelve VC-OK. `aud=AUD-1`, `nonce=N-1`, `state=S-1` en la respuesta. Solicitud pendiente registrada con esos tres valores. |

"Mutar X" significa partir del dato base y cambiar solo X, firmando de nuevo salvo que el caso diga lo contrario.

## 2. Técnica seleccionada por requisito

| Requisito | Naturaleza | Técnica |
| --- | --- | --- |
| VER-FR01 formato | Clases de entrada válidas e inválidas; fronteras de fechas | PE + AVL |
| VER-FR02 / FR03 clave y firma | Clases de fallo con código distinto | PE |
| VER-FR04 vigencia y tolerancia | Fronteras de tiempo y de configuración | AVL + PE |
| VER-FR05 / FR06 binding y solicitud | Combinación de condiciones y estado de la solicitud | TD + TE |
| VER-FR07 resultado técnico y confianza | Combinación de dos dimensiones independientes | TD |
| VER-FR08 sin material sensible | Clases de salida | PE |
| VER-FR09 vectores | Reproducibilidad | PE |
| VER-FR10 / FR12 diferidos | Clases (declarado / no declarado) | PE |
| VER-QR02 contextos | Clases (permitido / no permitido / en línea) | PE |
| VER-QR05 límites de entrada | Fronteras de tamaño, profundidad y cantidad | AVL |

## 3. Tablas de decisión y modelos de estado

### 3.1 Tabla de decisión — presentación (FR05, FR06)

El contrato fija el orden de evaluación: firma de la VP, vínculo con la solicitud, holder binding y credenciales. La solicitud se consume solo tras una respuesta con firma de holder válida que coincide con ella.

| Condición / Acción | R1 | R2 | R3 | R4 | R5 | R6 |
| --- | --- | --- | --- | --- | --- | --- |
| C1 Firma de la VP válida con la JWK del header | N | S | S | S | S | S |
| C2 `aud`, `nonce` y `state` coinciden con la solicitud | – | N | S | S | S | S |
| C3 Solicitud no consumida | – | – | N | S | S | S |
| C4 `cnf.jkt` de cada VC = thumbprint de la clave de la VP | – | – | – | N | S | S |
| C5 Cada VC es técnicamente válida | – | – | – | – | N | S |
| `technicalResult` | invalid | invalid | invalid | invalid | invalid | valid |
| Código de fallo | `signature.invalid` | `request.*_mismatch` | `request.replayed` | `binding.mismatch` o `binding.missing_cnf` | código de la VC | – |
| Solicitud consumida | No | No | Ya lo estaba | **Sí** | **Sí** | **Sí** |

R2 se divide en tres casos (audience, nonce, state), uno por condición que falla.

### 3.2 Tabla de decisión — resultado técnico y confianza (FR07)

| Condición / Acción | R1 | R2 | R3 | R4 | R5 |
| --- | --- | --- | --- | --- | --- |
| C1 Todas las comprobaciones requeridas pasan | S | S | S | N | N |
| C2 Trust policy configurada | N | S | S | S | N |
| C3 Issuer confiable según la policy | – | S | N | S | – |
| `technicalResult` | valid | valid | valid | invalid | invalid |
| `trust` | ausente | `trusted` | `untrusted` | no cambia el resultado técnico | ausente |

### 3.3 Transición de estados — solicitud anti-replay

| Estado actual | Evento | Estado siguiente | Salida observable |
| --- | --- | --- | --- |
| Pendiente | Respuesta con firma de VP inválida | Pendiente | `signature.invalid` |
| Pendiente | Firma válida, `aud`/`nonce`/`state` incorrecto | Pendiente | `request.*_mismatch` |
| Pendiente | Firma válida, solicitud coincide, binding o credencial fallan | **Consumida** | `binding.*` o fallo de la VC |
| Pendiente | Firma válida, todo correcto | **Consumida** | `valid` |
| Consumida | Cualquier respuesta posterior | Consumida | `request.replayed` |

### 3.4 Transición de estados — cadena de comprobaciones de una credencial

Orden: `format → issuerKey → signature → validity → status → schema`. Si una falla, las siguientes quedan `skipped` con `skipped.precondition_failed` (requeridas) y nunca `pass`. Se cubre en CP-02, CP-24, CP-27 y CP-45.

## 4. Casos de prueba

Convenciones de la tabla: **Trazabilidad dinámica** lleva `Clase:`, `Límite:`, `Regla:` o `Transición:` según la técnica. "Falla `X`" significa `technicalResult=invalid` y el criterio correspondiente con `result=fail` y `code=X`.

### 4.1 Formato (VER-FR01)

| ID Caso | ID Requisito | Título | Técnica | Trazabilidad dinámica | Precondiciones | Datos de Entrada | Pasos de Ejecución | Resultado Esperado |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| CP-01 | VER-FR01 | Credencial válida de referencia | PE | Clase: válida — VC conforme al perfil | E-BASE | VC-OK | 1. Verificar VC-OK. | `technicalResult=valid`. `format`, `issuerKey`, `signature` y `validity` en `pass`. `status` y `schema` en `skipped.not_declared`. `digest` presente. |
| CP-02 | VER-FR01 | Rechazo de `alg=none` | PE | Clase: inválida — algoritmo prohibido (none) | E-BASE | VC-OK con header `alg=none` | 1. Verificar. | Falla `format.header.alg`. `issuerKey`, `signature` y `validity` en `skipped.precondition_failed`. `technicalResult=invalid`. |
| CP-03 | VER-FR01 | Rechazo de `alg=HS256` | PE | Clase: inválida — algoritmo simétrico | E-BASE | VC-OK con `alg=HS256` | 1. Verificar. | Falla `format.header.alg`. |
| CP-04 | VER-FR01 | Rechazo de `alg=RS256` | PE | Clase: inválida — algoritmo RSA | E-BASE | VC-OK con `alg=RS256` | 1. Verificar. | Falla `format.header.alg`. |
| CP-05 | VER-FR01 | Rechazo de header sin `alg` | PE | Clase: inválida — `alg` ausente | E-BASE | VC-OK sin `alg` en el header | 1. Verificar. | Falla `format.header.alg`. |
| CP-06 | VER-FR01 | Rechazo de `typ` distinto de `vc+jwt` | PE | Clase: inválida — `typ` incorrecto | E-BASE | VC-OK con `typ=JWT` | 1. Verificar. | Falla `format.header.typ`. |
| CP-07 | VER-FR01 | Rechazo de header sin `typ` | PE | Clase: inválida — `typ` ausente | E-BASE | VC-OK sin `typ` | 1. Verificar. | Falla `format.header.typ`. |
| CP-08 | VER-FR01 | Rechazo de contenedor `vc` | PE | Clase: inválida — payload con contenedor `vc` | E-BASE | Payload `{"vc": {...VCDM...}}` | 1. Verificar. | Falla `format.payload.vc_container`. |
| CP-09 | VER-FR01 | Rechazo de `iss` duplicando `issuer` | PE | Clase: inválida — claim JWT duplicado (`iss`) | E-BASE | VC-OK más claim `iss` | 1. Verificar. | Falla `format.payload.duplicate_claim`. |
| CP-10 | VER-FR01 | Rechazo de `nbf` duplicando `validFrom` | PE | Clase: inválida — claim JWT duplicado (`nbf`) | E-BASE | VC-OK más claim `nbf` | 1. Verificar. | Falla `format.payload.duplicate_claim`. |
| CP-11 | VER-FR01 | Rechazo de `sub` duplicando el sujeto | PE | Clase: inválida — claim JWT duplicado (`sub`) | E-BASE | VC-OK más claim `sub` | 1. Verificar. | Falla `format.payload.duplicate_claim`. |
| CP-12 | VER-FR01 | Rechazo de JWS con 2 segmentos | PE | Clase: inválida — estructura compacta incompleta | E-BASE | `header.payload` sin firma | 1. Verificar. | Falla `format.malformed`. |
| CP-13 | VER-FR01 | Rechazo de JWS con 4 segmentos | PE | Clase: inválida — segmentos de más | E-BASE | `a.b.c.d` | 1. Verificar. | Falla `format.malformed`. |
| CP-14 | VER-FR01 | Rechazo de base64url inválido | PE | Clase: inválida — codificación (`+`, `/` o `=`) | E-BASE | Segmento de payload con `+` y relleno `=` | 1. Verificar. | Falla `format.malformed`. |
| CP-15 | VER-FR01 | Rechazo de miembro JSON duplicado | PE | Clase: inválida — JSON no estricto | E-BASE | Payload con `"issuer"` dos veces | 1. Verificar. | Falla `format.malformed`. |
| CP-16 | VER-FR01 | Rechazo de fecha no RFC 3339 | PE | Clase: inválida — formato de fecha | E-BASE | `validFrom="2026-01-01"` (sin hora ni zona) | 1. Verificar. | Falla `format.malformed`. |
| CP-17 | VER-FR01 | `validFrom` igual a `validUntil` | AVL | Límite: `validFrom = validUntil` (frontera inválida) | E-BASE | Ambas fechas `2026-06-15T12:00:00Z` | 1. Verificar. | Falla `format.malformed`. |
| CP-18 | VER-FR01 | `validFrom` posterior a `validUntil` | AVL | Límite: `validFrom > validUntil` | E-BASE | `validFrom=2026-06-15T13:00:00Z`, `validUntil=2026-06-15T12:00:00Z` | 1. Verificar. | Falla `format.malformed`. |
| CP-19 | VER-FR01 | Ventana mínima válida (`validUntil = validFrom + 1 s`) | AVL | Límite: `validUntil = validFrom + 1 s` (frontera válida) | E-BASE; reloj = `validFrom` | `validFrom=2026-06-15T12:00:00Z`, `validUntil=2026-06-15T12:00:01Z` | 1. Fijar reloj en `validFrom`. 2. Verificar. | `format` en `pass`. `technicalResult=valid`. |

### 4.2 Resolución de clave y firma (VER-FR02, VER-FR03)

| ID Caso | ID Requisito | Título | Técnica | Trazabilidad dinámica | Precondiciones | Datos de Entrada | Pasos de Ejecución | Resultado Esperado |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| CP-20 | VER-FR02 | Rechazo de `jku` en el header | PE | Clase: inválida — clave propia por `jku` | E-BASE | VC-OK con header `jku` | 1. Verificar. | Falla `key.untrusted_header`. El resolver no recibe ninguna consulta. |
| CP-21 | VER-FR02 | Rechazo de `jwk` en el header | PE | Clase: inválida — clave propia por `jwk` | E-BASE | VC-OK con header `jwk` | 1. Verificar. | Falla `key.untrusted_header`. |
| CP-22 | VER-FR02 | Rechazo de `x5u` en el header | PE | Clase: inválida — clave propia por `x5u` | E-BASE | VC-OK con header `x5u` | 1. Verificar. | Falla `key.untrusted_header`. |
| CP-23 | VER-FR02 | Rechazo de `x5c` en el header | PE | Clase: inválida — clave propia por `x5c` | E-BASE | VC-OK con header `x5c` | 1. Verificar. | Falla `key.untrusted_header`. |
| CP-24 | VER-FR02 | `kid` que el resolver no publica | PE | Clase: inválida — `kid` desconocido | E-BASE | VC-OK con `kid=kX9` | 1. Verificar. | Falla `key.unknown_kid`. `signature` y `validity` en `skipped.precondition_failed`. |
| CP-25 | VER-FR02 | Issuer declarado distinto del dueño de la clave | PE | Clase: inválida — issuer distinto del declarado | E-BASE | VC con `issuer`=A y `kid=kB1` (clave publicada para B) | 1. Verificar. | Falla `key.issuer_mismatch`. |
| CP-26 | VER-FR03 | Firma hecha con la clave de otro issuer | PE | Clase: inválida — firmada con clave ajena | E-BASE | VC-OK con `kid=kA1`, firmada con la clave privada de B | 1. Verificar. | Falla `signature.invalid` (código distinto de CP-24 y CP-25). |
| CP-27 | VER-FR03 | Payload alterado tras firmar | PE | Clase: inválida — firma alterada | E-BASE | VC-OK con 1 carácter del payload cambiado, firma original | 1. Verificar. | Falla `signature.invalid`. `validity` en `skipped.precondition_failed`. |
| CP-28 | VER-FR03 | Firma de 63 bytes | AVL | Límite: longitud de firma = 64 − 1 | E-BASE | VC-OK con firma truncada a 63 bytes | 1. Verificar. | Falla `signature.invalid`. |
| CP-29 | VER-FR03 | Firma de 65 bytes | AVL | Límite: longitud de firma = 64 + 1 | E-BASE | VC-OK con un byte añadido a la firma | 1. Verificar. | Falla `signature.invalid`. |
| CP-30 | VER-FR03 | Clave retirada pero publicada | PE | Clase: válida — clave retirada y aún publicada | E-BASE; `kA1` marcada como retirada pero presente en el resolver | VC-OK firmada con `kA1` | 1. Verificar. | `technicalResult=valid`. `signature` en `pass`. |

### 4.3 Vigencia y tolerancia de reloj (VER-FR04)

Se usa VC-T (`validFrom=12:00:00Z`, `validUntil=13:00:00Z` del 2026-06-15). "Tolerancia 0" significa verifier creado con `clockSkew=0`.

| ID Caso | ID Requisito | Título | Técnica | Trazabilidad dinámica | Precondiciones | Datos de Entrada | Pasos de Ejecución | Resultado Esperado |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| CP-31 | VER-FR04 | Un segundo antes de `validFrom` | AVL | Límite: `validFrom − 1 s` (tolerancia 0) | E-BASE; tolerancia 0 | VC-T; reloj `11:59:59Z` | 1. Fijar reloj. 2. Verificar. | Falla `validity.not_yet_valid`. |
| CP-32 | VER-FR04 | Exactamente en `validFrom` | AVL | Límite: `validFrom` (tolerancia 0) | E-BASE; tolerancia 0 | VC-T; reloj `12:00:00Z` | 1. Fijar reloj. 2. Verificar. | `validity` en `pass`. `technicalResult=valid`. |
| CP-33 | VER-FR04 | Un segundo después de `validFrom` | AVL | Límite: `validFrom + 1 s` | E-BASE; tolerancia 0 | VC-T; reloj `12:00:01Z` | 1. Fijar reloj. 2. Verificar. | `validity` en `pass`. |
| CP-34 | VER-FR04 | Un segundo antes de `validUntil` | AVL | Límite: `validUntil − 1 s` | E-BASE; tolerancia 0 | VC-T; reloj `12:59:59Z` | 1. Fijar reloj. 2. Verificar. | `validity` en `pass`. |
| CP-35 | VER-FR04 | Exactamente en `validUntil` | AVL | Límite: `validUntil` (ventana semiabierta `[validFrom, validUntil)`) | E-BASE; tolerancia 0 | VC-T; reloj `13:00:00Z` | 1. Fijar reloj. 2. Verificar. | Falla `validity.expired`. |
| CP-36 | VER-FR04 | Un segundo después de `validUntil` | AVL | Límite: `validUntil + 1 s` | E-BASE; tolerancia 0 | VC-T; reloj `13:00:01Z` | 1. Fijar reloj. 2. Verificar. | Falla `validity.expired`. |
| CP-37 | VER-FR04 | Tolerancia por defecto: 60 s antes de `validFrom` | AVL | Límite: `validFrom − 60 s` (tolerancia 1 min) | E-BASE (tolerancia 1 min) | VC-T; reloj `11:59:00Z` | 1. Fijar reloj. 2. Verificar. | `validity` en `pass`. |
| CP-38 | VER-FR04 | Tolerancia por defecto: 61 s antes de `validFrom` | AVL | Límite: `validFrom − 61 s` (tolerancia 1 min) | E-BASE (tolerancia 1 min) | VC-T; reloj `11:58:59Z` | 1. Fijar reloj. 2. Verificar. | Falla `validity.not_yet_valid`. |
| CP-39 | VER-FR04 | Tolerancia máxima: 5 min antes de `validFrom` | AVL | Límite: `validFrom − 5 min` (tolerancia 5 min) | E-BASE; tolerancia 5 min | VC-T; reloj `11:55:00Z` | 1. Fijar reloj. 2. Verificar. | `validity` en `pass`. |
| CP-40 | VER-FR04 | Tolerancia máxima: 5 min y 1 s antes de `validFrom` | AVL | Límite: `validFrom − 5 min − 1 s` (tolerancia 5 min) | E-BASE; tolerancia 5 min | VC-T; reloj `11:54:59Z` | 1. Fijar reloj. 2. Verificar. | Falla `validity.not_yet_valid`. |
| CP-41 | VER-FR04 | Tolerancias de configuración en los extremos válidos | AVL | Límite: tolerancia configurada = 0 y = 5 min | Dependencias de E-BASE | `clockSkew=0`; luego `clockSkew=5 min` | 1. Crear el verifier con 0. 2. Crear el verifier con 5 min. | Ambas creaciones tienen éxito, sin `ErrConfig`. |
| CP-42 | VER-FR04 | Tolerancia de 5 min y 1 s rechazada | AVL | Límite: tolerancia configurada = 5 min + 1 s | Dependencias de E-BASE | `clockSkew=5 min 1 s` | 1. Crear el verifier. | Devuelve `ErrConfig`. No se obtiene verifier. |
| CP-43 | VER-FR04 | Tolerancia negativa rechazada | AVL | Límite: tolerancia configurada = −1 s | Dependencias de E-BASE | `clockSkew=−1 s` | 1. Crear el verifier. | Devuelve `ErrConfig`. |
| CP-44 | VER-FR04 | Fechas con desfase horario se comparan en UTC | PE | Clase: válida — fecha con zona distinta de UTC | E-BASE; tolerancia 0 | VC con `validFrom=2026-06-15T17:00:00+05:00` (= 12:00:00Z); reloj `12:00:00Z`; luego reloj `11:59:59Z` | 1. Verificar con el primer reloj. 2. Verificar con el segundo. | Primera: `validity` en `pass`. Segunda: falla `validity.not_yet_valid`. |
| CP-45 | VER-FR04 | Vigencia no se evalúa si la firma falla | TE | Transición: `signature=fail → validity=skipped.precondition_failed` | E-BASE | VC-T con payload alterado y reloj fuera de ventana (`14:00:00Z`) | 1. Verificar. | Falla `signature.invalid`. `validity` en `skipped.precondition_failed`, no `fail` ni `pass`. |
| CP-91 | VER-FR04 | Tolerancia por defecto: 59 s después de `validUntil` | AVL | Límite: `validUntil + 59 s` (tolerancia 1 min; la tolerancia ensancha ambos bordes) | E-BASE (tolerancia 1 min) | VC-T; reloj `13:00:59Z` | 1. Fijar reloj. 2. Verificar. | `validity` en `pass`. |
| CP-92 | VER-FR04 | Tolerancia por defecto: 60 s después de `validUntil` | AVL | Límite: `validUntil + 60 s` (tolerancia 1 min) | E-BASE (tolerancia 1 min) | VC-T; reloj `13:01:00Z` | 1. Fijar reloj. 2. Verificar. | Falla `validity.expired`. |

### 4.4 Presentación, holder binding y solicitud (VER-FR05, VER-FR06)

| ID Caso | ID Requisito | Título | Técnica | Trazabilidad dinámica | Precondiciones | Datos de Entrada | Pasos de Ejecución | Resultado Esperado |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| CP-46 | VER-FR06 | Presentación correcta | TD | Regla: R6 (todas las condiciones en S) | E-BASE; solicitud pendiente (AUD-1, N-1, S-1) | VP-OK | 1. Verificar VP-OK con los valores esperados. | `technicalResult=valid`. Reporte de la VC en `valid`. Solicitud en estado Consumida. |
| CP-47 | VER-FR06 | Firma de la VP alterada | TD | Regla: R1 (C1=N) | E-BASE; solicitud pendiente | VP-OK con un carácter del payload cambiado | 1. Verificar. | Falla `signature.invalid`. `requestBinding` y `holderBinding` en `skipped.precondition_failed`. `technicalResult=invalid`. |
| CP-48 | VER-FR06 | Una VP no autenticada no consume la solicitud | TE | Transición: Pendiente → Pendiente (firma inválida) | Resultado de CP-47 (misma solicitud, sin consumir) | VP-OK íntegra | 1. Ejecutar CP-47. 2. Verificar VP-OK con la misma solicitud. | Segunda verificación: `technicalResult=valid`. |
| CP-49 | VER-FR06 | Audience equivocada | TD | Regla: R2 (C2=N por `aud`) | E-BASE; solicitud pendiente | VP firmada con `aud=AUD-2`; `nonce` y `state` correctos | 1. Verificar. | Falla `request.audience_mismatch`. |
| CP-50 | VER-FR06 | Nonce equivocado | TD | Regla: R2 (C2=N por `nonce`) | E-BASE; solicitud pendiente | VP con `nonce=N-2`; `aud` y `state` correctos | 1. Verificar. | Falla `request.nonce_mismatch`. |
| CP-51 | VER-FR06 | State equivocado | TD | Regla: R2 (C2=N por `state`) | E-BASE; solicitud pendiente | VP-OK con respuesta `state=S-2` | 1. Verificar. | Falla `request.state_mismatch`. |
| CP-52 | VER-FR06 | Un desajuste no consume la solicitud | TE | Transición: Pendiente → Pendiente (mismatch) | Solicitud pendiente | VP con `aud=AUD-2`, luego VP-OK | 1. Verificar la VP con `aud=AUD-2`. 2. Verificar VP-OK con la misma solicitud. | Primera: `request.audience_mismatch`. Segunda: `valid`. |
| CP-53 | VER-FR06 | Reutilización de la misma respuesta | TD | Regla: R3 (C3=N) | E-BASE; solicitud pendiente | VP-OK dos veces | 1. Verificar VP-OK. 2. Verificar VP-OK otra vez. | Primera: `valid`. Segunda: falla `request.replayed`, `technicalResult=invalid`. |
| CP-54 | VER-FR05 | VP firmada con otra clave de holder | TD | Regla: R4 (C4=N) | E-BASE; solicitud pendiente | VP firmada con la clave H2, `aud`/`nonce`/`state` correctos; VC-OK con `cnf.jkt` de H1 (firma del issuer válida) | 1. Verificar. | Falla `binding.mismatch`. El reporte de la VC puede tener firma válida, pero la VP es `invalid`. |
| CP-55 | VER-FR05 | Credencial sin `cnf.jkt` | TD | Regla: R4 (C4=N por ausencia) | E-BASE; solicitud pendiente | VC firmada sin `cnf`; VP correcta | 1. Verificar. | Falla `binding.missing_cnf`. |
| CP-56 | VER-FR05 | Dos credenciales, la segunda con otro `cnf.jkt` | TD | Regla: R4 (una de varias VC incumple C4) | E-BASE; solicitud pendiente | VP con VC-OK y VC-2 (`cnf.jkt` de H2) | 1. Verificar. | Falla `binding.mismatch`. `technicalResult=invalid`. `credentials[]` en el orden de la VP. |
| CP-57 | VER-FR06 | VP correcta con una credencial vencida dentro | TD | Regla: R5 (C5=N) | E-BASE; solicitud pendiente | VP-OK que envuelve VC-T; reloj `14:00:00Z` | 1. Verificar. | `credentials[0]` falla `validity.expired`. `technicalResult=invalid`. La firma de la VP y el binding están en `pass`. |
| CP-58 | VER-FR06 | Un fallo de binding consume la solicitud | TE | Transición: Pendiente → Consumida (binding falla) | Solicitud pendiente | VP del CP-54, luego VP-OK | 1. Verificar la VP del CP-54. 2. Verificar VP-OK con la misma solicitud. | Primera: `binding.mismatch`. Segunda: falla `request.replayed`. |
| CP-59 | VER-FR01 | Presentación con `typ` distinto de `vp+jwt` | PE | Clase: inválida — `typ` de VP incorrecto | E-BASE | VP-OK con `typ=JWT` | 1. Verificar. | Falla `format.header.typ`. |
| CP-60 | VER-FR02 | `kid` del holder resuelto fuera del header | PE | Clase: inválida — clave del holder no incluida en el header | E-BASE | VP con `kid` del holder y sin `jwk` en el header | 1. Verificar. | `technicalResult=invalid`. Falla `format.malformed`. |
| CP-93 | VER-FR06 | Presentación sin credenciales | PE | Clase: inválida — `verifiableCredential` vacío | E-BASE; solicitud pendiente | VP firmada por H1 con `verifiableCredential=[]` | 1. Verificar. | Falla `format.malformed`. |

### 4.5 Resultado técnico y confianza (VER-FR07)

| ID Caso | ID Requisito | Título | Técnica | Trazabilidad dinámica | Precondiciones | Datos de Entrada | Pasos de Ejecución | Resultado Esperado |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| CP-61 | VER-FR07 | Técnica válida sin trust policy | TD | Regla: R1 | E-BASE sin policy | VC-OK | 1. Verificar. | `technicalResult=valid`. El campo `trust` no aparece. |
| CP-62 | VER-FR07 | Técnica válida con issuer confiable | TD | Regla: R2 | E-BASE con policy que confía en A | VC-OK | 1. Verificar. | `technicalResult=valid`. `trust=trusted`. |
| CP-63 | VER-FR07 | Técnica válida con issuer no confiable | TD | Regla: R3 | E-BASE con policy que no confía en A | VC-OK | 1. Verificar. | `technicalResult=valid`. `trust=untrusted`. |
| CP-64 | VER-FR07 | Firma inválida con issuer confiable | TD | Regla: R4 | E-BASE con policy que confía en A | VC-OK con payload alterado | 1. Verificar. | `technicalResult=invalid` con `signature.invalid`. La confianza no lo convierte en válido. `trust=notEvaluated`: el emisor de una credencial no autenticada solo es una afirmación. |
| CP-65 | VER-FR07 | Firma inválida sin policy | TD | Regla: R5 | E-BASE sin policy | VC-OK con payload alterado | 1. Verificar. | `technicalResult=invalid`. `trust` ausente. `checks[]` con una entrada por criterio (`name`, `result`, `code`, `required`). |
| CP-94 | VER-FR07 | Credencial vencida con issuer confiable | TD | Regla: R4 (falla de vigencia, policy confía) | E-BASE con policy que confía en A; reloj 1 h después de `validUntil`; tolerancia 0 | VC-T | 1. Verificar. | `technicalResult=invalid` con `validity.expired`. `trust=trusted`: la confianza no cambia el resultado técnico en ninguno de los dos sentidos. |

### 4.6 Sin material sensible (VER-FR08)

| ID Caso | ID Requisito | Título | Técnica | Trazabilidad dinámica | Precondiciones | Datos de Entrada | Pasos de Ejecución | Resultado Esperado |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| CP-66 | VER-FR08 | Reporte exitoso sin JWS ni claims | PE | Clase: salida de verificación exitosa | E-BASE; captura de reporte, logs y auditoría | VP-OK | 1. Verificar. 2. Buscar en todas las salidas el `vp_token`, el JWS de la VC y los valores de los claims. | Ninguna coincidencia. Solo digest SHA-256, resultado y códigos. |
| CP-67 | VER-FR08 | Salidas de una verificación fallida sin material sensible | PE | Clase: salida de verificación fallida | E-BASE; captura de salidas | VP-OK con firma alterada | 1. Verificar. 2. Buscar el material en todas las salidas. | Ninguna coincidencia. |
| CP-68 | VER-FR08 | Digest = SHA-256 de la entrada | PE | Clase: salida — `digest` | E-BASE | VC-OK | 1. Verificar. 2. Calcular el SHA-256 de la credencial con una herramienta independiente. | `digest` tiene la forma `sha256:` + 64 hex y es igual al calculado. |
| CP-69 | VER-FR08 | El digest cambia con la entrada | PE | Clase: salida — sensibilidad del `digest` | E-BASE | VC-OK y una copia con 1 byte distinto | 1. Verificar ambas. 2. Comparar `digest`. | Los digests son distintos. Verificar VC-OK dos veces da el mismo digest. |

### 4.7 Vectores del laboratorio (VER-FR09)

| ID Caso | ID Requisito | Título | Técnica | Trazabilidad dinámica | Precondiciones | Datos de Entrada | Pasos de Ejecución | Resultado Esperado |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| CP-70 | VER-FR09 | Contenido completo de cada vector | PE | Clase: vector positivo y negativo | Archivo de vectores del repositorio | Archivo de vectores | 1. Recorrer cada vector. | Cada vector trae header, payload, clave pública, firma y resultado esperado. Hay al menos un positivo y uno negativo por código de fallo del contrato. |
| CP-71 | VER-FR09 | Los vectores se regeneran idénticos | PE | Clase: reproducibilidad | Procedimiento de generación del runbook | Claves sintéticas del laboratorio | 1. Generar los vectores dos veces. 2. Comparar byte a byte con el archivo publicado. | Las dos generaciones y el archivo publicado son idénticos. |
| CP-72 | VER-FR09 | Cada vector produce el resultado esperado y está marcado como sintético | PE | Clase: vector ejecutado contra el verifier | E-BASE | Todos los vectores | 1. Verificar cada vector. 2. Revisar el marcado de claves. | Resultado obtenido = esperado en todos. Las claves están marcadas como sintéticas y el material no se presenta como evidencia de interoperabilidad externa. |

### 4.8 Comprobaciones diferidas: status y schema (VER-FR10, VER-FR12)

El comportamiento real de status y schema está **diferido**. Estos casos prueban lo observable hoy: la credencial que los declara no puede salir `valid`.

| ID Caso | ID Requisito | Título | Técnica | Trazabilidad dinámica | Precondiciones | Datos de Entrada | Pasos de Ejecución | Resultado Esperado |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| CP-73 | VER-FR10 | Credencial con `credentialStatus` | PE | Clase: declara status | E-BASE | VC-OK con `credentialStatus` | 1. Verificar. | `status` en `skipped.not_implemented` y requerido. `technicalResult=invalid`. |
| CP-74 | VER-FR10 | Credencial sin `credentialStatus` | PE | Clase: no declara status | E-BASE | VC-OK | 1. Verificar. | `status` en `skipped.not_declared`, no requerido. `technicalResult=valid`. |
| CP-75 | VER-FR12 | Credencial con `credentialSchema` | PE | Clase: declara schema | E-BASE | VC-OK con `credentialSchema` | 1. Verificar. | `schema` en `skipped.not_implemented` y requerido. `technicalResult=invalid`. |
| CP-76 | VER-FR12 | Credencial con status y schema a la vez | PE | Clase: declara ambos | E-BASE | VC-OK con ambos miembros | 1. Verificar. | Ambos en `skipped.not_implemented`. `technicalResult=invalid`. |

### 4.9 Contextos, red y límites de entrada (VER-QR01, QR02, QR05)

Los límites por defecto son los de la spec: 16 KiB por credencial (16 384 bytes del JWS compacto), 8 niveles de profundidad JSON, 8 credenciales y 64 KiB (65 536 bytes) por presentación. Las fronteras se tratan como inclusivas (el valor máximo se acepta); ver H-03.

| ID Caso | ID Requisito | Título | Técnica | Trazabilidad dinámica | Precondiciones | Datos de Entrada | Pasos de Ejecución | Resultado Esperado |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| CP-77 | VER-QR02 | Solo el contexto base VCDM 2.0 | PE | Clase: válida — contexto permitido | E-BASE | VC-OK (`@context` = base VCDM 2.0) | 1. Verificar. | `format` en `pass`. |
| CP-78 | VER-QR02 | Contexto remoto no listado | PE | Clase: inválida — contexto no allowlisted | E-BASE; monitor de tráfico de red | VC con `@context` que incluye `https://example.test/ctx/v1` | 1. Verificar. 2. Revisar el tráfico saliente. | Falla `format.context_not_allowed`. Cero conexiones salientes. |
| CP-79 | VER-QR02 | Contexto en línea | PE | Clase: inválida — contexto como objeto | E-BASE | VC con un objeto dentro de `@context` | 1. Verificar. | Falla `format.context_not_allowed`. |
| CP-80 | VER-QR02 | Contexto `cpe/v1` fuera de la lista por defecto | PE | Clase: inválida — contexto de tipo no incluido | E-BASE | VC con `@context` base + `cpe/v1` | 1. Verificar. | Falla `format.context_not_allowed`. |
| CP-81 | VER-QR02 | Mezcla de contexto permitido y no permitido | PE | Clase: inválida — lista mixta | E-BASE | `@context` = [base VCDM 2.0, no listado] | 1. Verificar. | Falla `format.context_not_allowed`. |
| CP-82 | VER-QR01 | Verificación sin acceso a red | PE | Clase: válida — operación local | E-BASE con salida de red bloqueada; resolver falso que registra las consultas | VC-OK | 1. Bloquear la red saliente. 2. Verificar. | `technicalResult=valid`. Solo el resolver falso recibe consultas; no hay conexiones salientes. |
| CP-83 | VER-QR05 | Credencial en el límite de tamaño | AVL | Límite: JWS de 16 384 bytes | E-BASE | VC-OK con relleno hasta 16 384 bytes | 1. Verificar. | `format` en `pass`. |
| CP-84 | VER-QR05 | Credencial un byte sobre el límite | AVL | Límite: JWS de 16 385 bytes | E-BASE | VC-OK con relleno hasta 16 385 bytes | 1. Verificar. | Falla `format.malformed`. |
| CP-85 | VER-QR05 | Profundidad JSON en el límite | AVL | Límite: profundidad 8 | E-BASE | VC-OK con un claim anidado hasta profundidad 8 | 1. Verificar. | `format` en `pass`. |
| CP-86 | VER-QR05 | Profundidad JSON sobre el límite | AVL | Límite: profundidad 9 | E-BASE | Igual al anterior con profundidad 9 | 1. Verificar. | Falla `format.malformed`. |
| CP-87 | VER-QR05 | Presentación con 8 credenciales | AVL | Límite: 8 credenciales por VP | E-BASE; solicitud pendiente | VP con 8 VC válidas | 1. Verificar. | `credentials[]` con 8 entradas. `technicalResult=valid`. |
| CP-88 | VER-QR05 | Presentación con 9 credenciales | AVL | Límite: 9 credenciales por VP | E-BASE; solicitud pendiente | VP con 9 VC válidas | 1. Verificar. | Falla `format.malformed`. |
| CP-89 | VER-QR05 | Presentación en el límite de tamaño | AVL | Límite: VP de 65 536 bytes | E-BASE; solicitud pendiente | VP-OK con relleno hasta 65 536 bytes | 1. Verificar. | `format` de la VP en `pass`. |
| CP-90 | VER-QR05 | Presentación un byte sobre el límite | AVL | Límite: VP de 65 537 bytes | E-BASE; solicitud pendiente | VP-OK con relleno hasta 65 537 bytes | 1. Verificar. | Falla `format.malformed`. |

## 5. Matriz de trazabilidad

| Requisito | Casos |
| --- | --- |
| VER-FR01 | CP-01 a CP-19, CP-59 |
| VER-FR02 | CP-20 a CP-25, CP-60 |
| VER-FR03 | CP-26 a CP-30 |
| VER-FR04 | CP-31 a CP-45, CP-91, CP-92 |
| VER-FR05 | CP-54 a CP-56 |
| VER-FR06 | CP-46 a CP-53, CP-57, CP-58, CP-93 |
| VER-FR07 | CP-61 a CP-65, CP-94 |
| VER-FR08 | CP-66 a CP-69 |
| VER-FR09 | CP-70 a CP-72 |
| VER-FR10 | CP-73, CP-74 |
| VER-FR12 | CP-75, CP-76 |
| VER-QR01 | CP-78, CP-82 |
| VER-QR02 | CP-77 a CP-81 |
| VER-QR03 | Indirecta: CP-49 a CP-51 y CP-54 prueban coincidencia y discrepancia. El tiempo constante no se mide por caja negra. |
| VER-QR05 | CP-83 a CP-90 |

### 5.1 Parte del sistema que cubre cada caso

Todo el módulo vive en `src/platform/internal/verification`. Los casos se ejecutan por su interfaz pública (`Verify`, `VerifyPresentation`, `NewVerifier`); la columna indica qué componente interno ejercitan, según la estructura actual del paquete.

| Componente | Archivo |
| --- | --- |
| Orquestación y vigencia | `verifier.go` |
| Parser de formato y límites | `parse.go` |
| Resolución de clave y firma | `integrity.go`, `keys.go` |
| Presentación y holder binding | `presentation.go` |
| Anti-replay | `replay.go` |
| Trust policy | `trust.go` |
| Reporte, resultado técnico y digest | `report.go` |

| Caso | Componente cubierto |
| --- | --- |
| CP-01 | Orquestación (`Verify`) de extremo a extremo |
| CP-02 a CP-05 | Parser: header (`alg`) |
| CP-06, CP-07 | Parser: header (`typ`) |
| CP-08 a CP-11 | Parser: payload (contenedor `vc`, claims duplicados) |
| CP-12 a CP-15 | Parser: estructura compacta, base64url y JSON estricto |
| CP-16 a CP-18 | Parser: fechas y coherencia de la ventana |
| CP-19 | Parser (ventana mínima) y vigencia |
| CP-20 a CP-23 | Resolución de clave: claves propias en el header |
| CP-24, CP-25 | Resolución de clave: `kid` desconocido y dueño de la clave |
| CP-26 a CP-29 | Firma ES256 |
| CP-30 | Resolución de clave (`MemoryKeyResolver`) y firma |
| CP-31 a CP-40, CP-91, CP-92 | Vigencia (`checkValidity`) |
| CP-41 a CP-43 | Configuración de `NewVerifier` (`ErrConfig`) |
| CP-44 | Parser de fechas y vigencia |
| CP-45 | Orquestación: orden y omisión de comprobaciones |
| CP-46 | Presentación, holder binding y anti-replay en conjunto |
| CP-47 | Presentación: firma de la VP |
| CP-48 | Presentación y anti-replay (no consumir con firma inválida) |
| CP-49 a CP-51 | Presentación: vínculo con la solicitud (`matchRequest`) |
| CP-52 | Vínculo con la solicitud y anti-replay |
| CP-53 | Anti-replay (`ReplayStore`) |
| CP-54 a CP-56 | Holder binding (`JWKThumbprint`, comparación en tiempo constante) |
| CP-57 | Presentación que delega en `Verify` por credencial (vigencia) |
| CP-58 | Holder binding y anti-replay |
| CP-59 | Parser de la presentación: header |
| CP-60 | Presentación: JWK del holder en el header |
| CP-61 a CP-63 | Trust policy y reporte (`trust`) |
| CP-64, CP-65, CP-94 | Trust policy frente al resultado técnico (`report.go`) |
| CP-93 | Parser de la presentación: lista de credenciales |
| CP-66, CP-67 | Reporte, logs y puerto de auditoría (no fuga de material) |
| CP-68, CP-69 | Digest (`report.go`) |
| CP-70 a CP-72 | Vectores sintéticos (`testdata/vectors.json`) y verifier |
| CP-73 a CP-76 | Comprobaciones diferidas: omisión de status y schema |
| CP-77 a CP-81 | Parser: lista de contextos permitidos |
| CP-82 | Paquete completo: ausencia de acceso a red |
| CP-83 a CP-86 | Parser: límite de tamaño y profundidad de la credencial |
| CP-87 a CP-90 | Parser de la presentación: número de credenciales y tamaño |

## 6. Fuera de esta suite

- **VER-FR11** (JWKS por HTTPS): diferido hasta que exista la publicación de JWKS del issuer (fase 1). No hay comportamiento que probar hoy.
- **Comportamiento real de VER-FR10 y VER-FR12** (verificar lista de status y schema): diferido. Hoy solo se prueba que declararlos impide `valid` (CP-73 a CP-76).
- **VER-QR03** (tiempo constante) y **VER-QR04** (el paquete no importa `internal/authentication`): requieren revisión de código y de imports, que es caja blanca.
- Request firmado y respuesta cifrada de OpenID4VP, e interoperabilidad con un verifier externo: no existen en el incremento actual.

## 7. Hallazgos

Resueltos al ejecutar la suite: el comportamiento observado queda como resultado esperado de los casos indicados.

| ID | Duda | Resolución |
| --- | --- | --- |
| H-01 | Código de un header sin `alg` o sin `typ`. | Resuelto: `format.header.alg` y `format.header.typ` (CP-05, CP-07). Un `kid` ausente da `format.malformed`. |
| H-02 | Código cuando el `kid` del holder está fuera del header. | Resuelto: `format.malformed` (CP-60). |
| H-03 | Si el límite de tamaño es inclusivo y sobre qué se mide. | Resuelto: se mide sobre el JWS compacto y el valor máximo se acepta (CP-83 a CP-90). La profundidad cuenta el objeto raíz como nivel 1. |
| H-04 | Si la tolerancia de reloj aplica también a `validUntil`. | Resuelto: ensancha ambos bordes. Con tolerancia 1 min, `validUntil + 59 s` pasa y `+ 60 s` vence (CP-91, CP-92). |
| H-05 | Resultado de una VP con 0 credenciales. | Resuelto: `format.malformed` (CP-93). |
| H-06 | Valor de `trust` cuando el resultado técnico es `invalid`. | Resuelto: `notEvaluated` si la credencial no se autenticó (firma o clave fallan, CP-64) y la decisión real si solo falla la vigencia (CP-94). |

Abierto:

| ID | Hallazgo | Impacto |
| --- | --- | --- |
| H-07 | Los vectores publicados **no son deterministas**: se generan con claves efímeras y ECDSA aleatorio, y dos generaciones dan bytes distintos. El AC09 de VER-FR09 pide claves "deterministas". Hoy solo es reproducible el archivo publicado, no su generación. | CP-71 queda **omitido** (`t.Skip`) hasta que el generador sea determinista o el AC09 se reformule. |

## 8. Ejecución

- **Automatización:** `src/platform/internal/verification/blackbox_suite_test.go`, paquete externo `verification_test` (solo API pública). Cada subprueba lleva su ID `CP-NN` en el nombre. CP-52 va dentro de CP-49 a CP-51, que verifican que un desajuste no consume la solicitud.
- **Comando:** desde `src/platform`, con el Go del proyecto: `go test -count=1 -run '^TestBB_' -v ./internal/verification/`.
- **Resultado (2026-11-18, local):** 93 casos pasan, 0 fallan, 1 omitido (CP-71, H-07). `gofmt -l`, `go vet ./...` y `go test ./...` completos en verde. Falta la evidencia del CI.
- **Límites de la ejecución:** CP-78 y CP-82 comprueban la ausencia de red reemplazando `http.DefaultTransport` dentro del proceso; no cierran el acceso a la red a nivel de sistema. Las claves de la suite son efímeras y generadas en cada ejecución. CP-66 y CP-67 revisan reporte y renderizados (`json`, `%v`, `%+v`, `%#v`); el módulo no tiene logger propio ni emite auditoría, así que no hay más salidas que revisar.
