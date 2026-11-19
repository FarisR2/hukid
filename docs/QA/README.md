# QA — Pruebas de caja negra de HukID

Carpeta de documentación de aseguramiento de calidad. Los casos se diseñan desde la especificación (ISO/IEC/IEEE 29119-4, ISTQB) y no dependen del código interno: solo usan entradas y salidas observables según el contrato.

## Suites

| Suite | Feature | Estado |
| --- | --- | --- |
| [FEAT-004 — Verificación de credenciales](FEAT-004-credential-verification-test-suite.md) | [spec](../features/FEAT-004-credential-verification/spec.md) | Ejecutada en local (93 pasan, 1 omitido); falta evidencia de CI |

## Convenciones

- **ID de caso:** `CP-NN`, único dentro de su suite.
- **Técnicas:** Partición de Equivalencia (PE), Análisis de Valores Límite (AVL), Tabla de Decisión (TD) y Transición de Estados (TE).
- **Columna de trazabilidad dinámica:** su valor lleva el prefijo de la técnica: `Clase:`, `Límite:`, `Regla:` o `Transición:`.
- **Un caso, un resultado esperado:** cada caso es atómico, reproducible y con criterio de aceptación objetivo (código de fallo estable o `technicalResult`).
- **Fuente de verdad:** la spec de la feature y el [contrato versionado](../03-design/credential-verification-contract.md). Si dos fuentes difieren, el caso lo declara en "Hallazgos" y no elige en silencio.
- **Estado de ejecución:** cada suite indica qué casos están automatizados y cuáles pasaron; solo cuenta lo ejecutado con evidencia.
