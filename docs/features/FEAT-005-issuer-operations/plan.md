# FEAT-005 — Plan de operación administrativa del issuer

## Decisiones y componentes

| Área | Implementación objetivo | Estado |
| --- | --- | --- |
| API privada | Management operator, bearer de sesión, tenant activo y BFF same-origin existente. Nuevos GET `/issuance-requests` y `/credentials`. | Implementada en la rama; capability `issuance:read` reservado sin concesión. |
| Autorización | Tenant scope más `issuance:read`; filtrar issuer asignado cuando aplique. Mutaciones requieren política separada con MFA reciente, idempotencia por operador y auditoría. | Lecturas implementadas; asignación de capability y política de mutación requieren owner/ADR. |
| Persistencia | Consultas tenant-RLS, columnas mínimas, orden estable y limit/offset; sin nueva tabla ni migration. | Implementada en memoria y PostgreSQL; necesita gate. |
| Consola | Solicitudes y credenciales muestran resumen y paginación; ninguna acción de status hasta aprobar su autoridad. | UI conectada; no aparece a roles actuales mientras capability esté reservado. |
| Definición POS | Una definition versionada aprobada por owner con mapping y consentimiento. | Bloqueada por decisión de producto; no inferir claims. |
| Integración | Fuente→offer→wallet→VC y polling; adapter Events es propiedad de Team 4, wallet Flutter de Team 5. | No incluida en este incremento técnico. |

## Secuencia

1. Revisar esta feature y ADR-0031 con product owner; aprobar roles/capability para lectura y política de status operator.
2. Mantener los listados metadata-only ya implementados; validar autorización negativa, paginación, RLS y no exposición de material sensible.
3. Tras decisión de status, añadir una operación de operador separada del API de integración, con actor operator, step-up, auditoría y almacenamiento idempotente coherente.
4. Resolver payload POS con owner y Team 4; actualizar definition/API/claims/consentimiento únicamente después de esa decisión.
5. Coordinar adaptación Events→HukID y wallet dentro de owners; reconciliar por polling en v0.
6. Ejecutar tests Go, `npm run test:postgres`, checks de contratos/docs, build de consola y backend; hacer el recorrido autenticado cuando el entorno local completo esté disponible.

## No-go

- No conceder `issuance:read` por inferencia: actualmente está reservado por el contrato DASH.
- No adaptar `status:write` de cliente como identidad operator ni usar MFA de operador a modo de sustituto sin contrato.
- No introducir claims, definition canónica POS, webhook v0, dependencia de Events bus, migración ni wallet alternativa sin decisión/owner.
- No declarar el issuer completo o listo para producción por pasar builds/tests locales.
