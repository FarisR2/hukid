# Índice canónico de backlogs y balance de carga

## Fuentes de implementación

| Equipo | Backlog | Historias | Superficies | Factor que equilibra carga |
|---|---|---:|---|---|
| 1 — Content & Platform | [TEAM-1](../02-requirements/backlogs/team-1-content-platform.md) | 40 | Astro público, React Admin, auth/gateway, CMS, plataforma | más historias; se organiza en dos pares internos: Platform y Experience |
| 2 — Event Configuration | [TEAM-2](../02-requirements/backlogs/team-2-event-configuration.md) | 27 | React backoffice, API, release/outbox | menos historias pero alto modelado, validación y versionado |
| 3 — Participation | [TEAM-3](../02-requirements/backlogs/team-3-participation.md) | 32 | isla React, Admin, API de alta concurrencia, archivos | concurrencia, PII y dos journeys completos: registro y convocatoria |
| 4 — Onsite Operations | [TEAM-4](../02-requirements/backlogs/team-4-onsite-operations.md) | 31 | PWA, dashboard, APIs, workers, reporting/certificación | más runtimes, operación en vivo y adaptador outbound HukID |
| 5 — HukID | [TEAM-5](../02-requirements/backlogs/team-5-hukid.md) | 33 | Flutter, Go issuer/API, KMS/status | criptografía, interoperabilidad y conformance elevan incertidumbre |

El conteo comprueba cobertura, no esfuerzo. No se reutilizan los puntos del resumen legado. Sprint 0 termina con estimación relativa por el equipo ejecutor, contratos compilables y ajuste para que ningún equipo supere ±15% de la mediana comprometida.

## Corte MVP vendible

| Equipo | Incluido en MVP | Posterior al primer cliente |
|---|---|---|
| 1 | organización/owner, OIDC/sesión, membresías/RBAC, dominio, gateway, CMS básico, publicación, landing comercial/demo, sitio cliente, Admin shell, CI/CD/telemetría | SEO/temas avanzados, soporte cross-tenant sofisticado |
| 2 | lifecycle evento, programas/sesiones/sedes, formulario/consentimiento, binding, validación y release completo | optimizaciones editoriales y diffs avanzados |
| 3 | registro/autoservicio, cupo/waitlist, ticket/revocación, emprendimiento/equipo, adjuntos, submit/subsanación, backoffice mínimo | importaciones masivas y privacy automation avanzada |
| 4 | dispositivo/readiness, check-in/out/void/búsqueda, comunicaciones transaccionales, dashboard/reporte básico, certificado PDF | campañas complejas, exports avanzados y HukID opcional si no bloquea la venta |
| 5 | tenant/issuer/definition/client, Integration API, OID4VCI mínimo, wallet recibir/guardar/ver, firma/status/operabilidad | OID4VP completo y recuperación avanzada si el piloto no los exige |

## Gates de inicio

1. **Sprint 0:** ownership, auth, estados, OpenAPI/AsyncAPI, entornos, CI/CD, seeds y contract-test harness.
2. **Gate público:** publicar evento → materializar Content → ver landing/demo coherente.
3. **Gate participación:** release → registro concurrente → confirmación/waitlist → QR/revocación.
4. **Gate onsite:** QR → check-in/void → dashboard/reporte/certificado.
5. **Gate HukID:** certificado elegible → HTTP Integration API → offer → wallet → status, sin bus ni DB compartidos.

Una historia sólo entra a sprint si declara scope/rol, precondiciones, estados alternos, contrato, datos, criterios observables, pruebas negativas y telemetría.
