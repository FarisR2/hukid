> Revisión histórica del paquete anterior a la incorporación local de HukID. No acredita que existan los artefactos ejecutables; consultar el [registro actual](../documentation-gaps.md).

# Auditoría de cobertura del paquete anterior

Fecha: 2026-11-03

## Veredicto

El paquete anterior definía correctamente los límites de despliegue y algunos flujos críticos, pero no era suficiente para implementar el producto. Sus 38 historias describían capacidades grandes como si fueran historias individuales y omitían journeys transversales, estados alternos, administración, seguridad y operación.

## Omisiones encontradas

| Área | Faltaba | Corrección |
|---|---|---|
| Autenticación | login/logout, callback OIDC, refresh, expiración, recuperación, MFA privilegiado, sesiones y dispositivos | Backlog completo de Platform Foundation y contrato de identidad |
| Autorización | roles, membresías, invitaciones, suspensión, cambio de organización, service accounts y matriz de scopes | Matriz RBAC/ABAC y pruebas negativas por endpoint |
| Tenant | alta/configuración, dominio, resolución pública, aislamiento y lifecycle de organización | Historias tenant y endpoints `/organizations`, `/memberships`, `/domains` |
| Frontends | shell, rutas, estados loading/error/empty/forbidden, accesibilidad y ownership de la isla de registro | Historias separadas Astro, React Admin, Participation island y PWA |
| CMS | medios, SEO, preview, rollback, navegación, temas, sanitización, leads y demo data | Épica CMS/public experience completa |
| Eventos | borrador/publicación/cierre/cancelación/duplicación, recursos, conflictos, formularios y release manifest | Backlog Event Configuration y contrato de release |
| Participación | autoservicio, consentimiento, duplicados, waitlist, invitaciones de equipo, anexos, retiro, subsanación y admisibilidad | Backlog Participation completo |
| Check-in | dispositivos, precarga, sesión/scope, check-out, void, búsqueda, duplicados y revocación fresca | Backlog Onsite y contrato antifraude |
| Comunicaciones | plantillas, preferencias, programación, retry, bounce y auditoría | Épica Communications Worker |
| Reportes/certificados | jobs, snapshots, permisos, retención, templates, elegibilidad, revocación y descarga | Épicas Reporting y Certificates |
| HukID | onboarding issuer, wallet lifecycle, OID4VCI/OID4VP, status, recovery, KMS y soporte | Backlog HukID enlazado con su arquitectura canónica |
| Contratos | inventario de endpoints, request/response, errores, scopes, idempotencia, eventos, replay y compatibilidad | Catálogos normativos API/auth/eventos; materialización OpenAPI/AsyncAPI por owner es gate obligatorio de Sprint 0 |
| Operación | CI/CD, entornos, secretos, backups, SLO, alertas, DLQ, runbooks y soporte | Historias Platform/Operations y Definition of Done transversal |

## Regla de completitud

Una capacidad sólo se considera especificada cuando tiene: actor autorizado, precondiciones, camino exitoso, estados alternos, errores, datos poseídos, contrato API/evento, criterios de aceptación observables, requisitos de seguridad y evidencia de operación.
