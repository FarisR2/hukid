> Revisión histórica del paquete anterior a la incorporación local de HukID. No acredita que existan los artefactos ejecutables; consultar el [registro actual](../documentation-gaps.md).

# Gate de corrección — 2026-11-03

## Veredicto

El paquete corregido es apto para estimación, asignación y Sprint 0. Ya no debe usarse `TEAM-BACKLOGS.md`: sus 38 macrohistorias fueron reemplazadas por 163 historias canónicas con criterios verificables.

Todavía no es responsable iniciar cinco implementaciones independientes únicamente desde Markdown. Antes del primer story de dominio, cada owner debe convertir su parte del catálogo en OpenAPI 3.1/AsyncAPI/JSON Schema compilable y aprobar contract tests. El OpenAPI original de 30 paths sirve como baseline y ahora incluye el flujo auth básico, pero no representa por sí solo toda la superficie de 163 historias.

## Cobertura verificada

| Exigencia | Evidencia | Estado |
|---|---|---|
| Auth básico y seguro | `AUTH-AND-AUTHORIZATION-CONTRACT.md`, PF-004/005/007/010, endpoints BFF en catálogo y OpenAPI baseline | cubierto |
| Usuarios, tenants, roles, invitaciones, sesiones, MFA, workloads | PF-001–025 y matriz scopes | cubierto |
| Cada frontend | PF-040–046 (landing/demo/sitio/shell), PA-001–008/020–033 (isla/admin), OO-001–017/030–045 (PWA/dashboard), HK-030–043 (Flutter) | cubierto |
| CMS/publicación/caché | PF-030–038/042/046 y contracts Content | cubierto |
| Eventos, agendas paralelas, forms/releases | EC-001–043 | cubierto |
| Registro individual y emprendimientos | PA-001–043 | cubierto |
| Check-in y operación | OO-001–052 | cubierto; offline diferido explícitamente |
| HukID independiente | HK-001–056 y arquitectura canónica externa | cubierto; adaptador outbound pertenece a T4 |
| APIs | catálogo de endpoints, auth/scopes, requests base, errors, idempotencia/ETag | inventario normativo completo; codegen por owner pendiente Sprint 0 |
| Eventos | envelope único, catálogo, minimización, ordering/replay/retención/compatibilidad | cubierto |
| Estado y datos | máquinas de estado, invariantes, ownership, clasificación y retención | cubierto |
| PostgreSQL/migraciones | tablas por owner, constraints, RLS, expand/contract y gates | cubierto a nivel de diseño; DDL por servicio pendiente implementación |
| Carga de equipos | 40/27/32/31/33 historias ajustadas por complejidad/riesgo, corte MVP y gates | cubierto; puntos deben estimarlos ejecutores |

## Riesgos residuales que no deben ocultarse

1. Las políticas de retención son defaults técnicos; UNAS/IncubaUNAS debe validarlas jurídica e institucionalmente.
2. El proveedor OIDC, canales de email/SMS, CDN, object storage y KMS aún son decisiones de compra/despliegue.
3. Los objetivos de carga necesitan números de campaña: usuarios simultáneos, inscripciones/minuto, check-ins/minuto y tamaño de archivos.
4. HukID mantiene su propio gate de interoperabilidad; no debe acoplar su release al MVP comercial de Events salvo que el piloto lo exija.
5. Offline check-in no está en el MVP y no puede “activarse” sólo con una cola local; requiere diseño de seguridad/reconciliación separado.

## Criterio para pasar de Sprint 0 a construcción

- Cada endpoint de `contracts/API-CONTRACTS.md` aparece en un OpenAPI owner-specific con request/response/error/examples.
- Cada topic de `contracts/EVENT-CONTRACTS.md` tiene AsyncAPI/JSON Schema y test de compatibilidad.
- Matriz rol×acción×recurso está automatizada con pruebas negativas cross-tenant.
- Migrations iniciales crean constraints/RLS/outbox/inbox y pasan test de dos tenants.
- Se acuerdan SLO y perfiles de carga por flujo.
- Los cinco pares de contract tests del `BACKLOG-INDEX.md` pasan en CI.

Hasta cumplir este gate, “contrato completo” significa cobertura funcional/semántica completa, no que el código generado esté listo.
