# Mapa de reorganización documental

Fecha: 2026-11-03. Se conserva el contenido de las fuentes recibidas, con enlaces relativos actualizados y notas de alcance/procedencia. Las entradas por categoría sintetizan y enlazan el detalle; no reemplazan IDs de historias ni promueven el perfil draft.

## Correspondencia de fuentes

Las rutas de origen son las que existían bajo docs al comenzar la reorganización. No son enlaces activos.

| Origen | Ubicación actual |
| --- | --- |
| `docs/README.md` | [docs/05-delivery/archive/original-project-overview.md](archive/original-project-overview.md) |
| `docs/ARCHITECTURE-SPINE.md` | [docs/03-design/events-architecture-spine.md](../03-design/events-architecture-spine.md) |
| `docs/MICROSERVICES-ARCHITECTURE.md` | [docs/03-design/events-architecture.md](../03-design/events-architecture.md) |
| `docs/AUTH-AND-AUTHORIZATION-CONTRACT.md` | [docs/04-engineering/events-auth-and-authorization.md](../04-engineering/events-auth-and-authorization.md) |
| `docs/INTEGRATION-CONTRACTS.md` | [docs/03-design/contracts/events-integration.md](../03-design/contracts/events-integration.md) |
| `docs/BACKLOG-INDEX.md` | [docs/05-delivery/backlog-index.md](backlog-index.md) |
| `docs/TEAM-DELIVERY-PLAN.md` | [docs/05-delivery/events-team-plan.md](events-team-plan.md) |
| `docs/TEAM-BACKLOGS.md` | [docs/05-delivery/archive/team-backlogs.md](archive/team-backlogs.md) |
| `docs/COVERAGE-AUDIT.md` | [docs/05-delivery/reviews/coverage-audit.md](reviews/coverage-audit.md) |
| `docs/reviews/CORRECTION-GATE.md` | [docs/05-delivery/reviews/correction-gate.md](reviews/correction-gate.md) |
| `docs/contracts/API-CONTRACTS.md` | [docs/03-design/contracts/events-api-contracts.md](../03-design/contracts/events-api-contracts.md) |
| `docs/contracts/EVENT-CONTRACTS.md` | [docs/03-design/contracts/events-event-contracts.md](../03-design/contracts/events-event-contracts.md) |
| `docs/contracts/STATE-MACHINES.md` | [docs/03-design/contracts/events-state-machines.md](../03-design/contracts/events-state-machines.md) |
| `docs/contracts/DATABASE-BOUNDARIES-AND-MIGRATIONS.md` | [docs/03-design/contracts/events-database-boundaries.md](../03-design/contracts/events-database-boundaries.md) |
| `docs/contracts/DATA-OWNERSHIP-AND-RETENTION.md` | [docs/04-engineering/data-ownership-and-retention.md](../04-engineering/data-ownership-and-retention.md) |
| `docs/backlogs/TEAM-1-CONTENT-PLATFORM.md` | [docs/02-requirements/backlogs/team-1-content-platform.md](../02-requirements/backlogs/team-1-content-platform.md) |
| `docs/backlogs/TEAM-2-EVENT-CONFIGURATION.md` | [docs/02-requirements/backlogs/team-2-event-configuration.md](../02-requirements/backlogs/team-2-event-configuration.md) |
| `docs/backlogs/TEAM-3-PARTICIPATION.md` | [docs/02-requirements/backlogs/team-3-participation.md](../02-requirements/backlogs/team-3-participation.md) |
| `docs/backlogs/TEAM-4-ONSITE-OPERATIONS.md` | [docs/02-requirements/backlogs/team-4-onsite-operations.md](../02-requirements/backlogs/team-4-onsite-operations.md) |
| `docs/backlogs/TEAM-5-HUKID.md` | [docs/02-requirements/backlogs/team-5-hukid.md](../02-requirements/backlogs/team-5-hukid.md) |
| `docs/add/01-estandares-y-modelo.md` | [docs/03-design/hukid-standards-and-model.md](../03-design/hukid-standards-and-model.md) |
| `docs/add/02-arquitectura-de-solucion.md` | [docs/03-design/hukid-architecture.md](../03-design/hukid-architecture.md) |
| `docs/add/03-casos-de-uso-y-flujos.md` | [docs/03-design/hukid-ux-flows.md](../03-design/hukid-ux-flows.md) |
| `docs/add/04-apis-y-contratos.md` | [docs/03-design/hukid-api-contracts.md](../03-design/hukid-api-contracts.md) |
| `docs/add/05-seguridad-y-operacion.md` | [docs/04-engineering/hukid-security-and-operations.md](../04-engineering/hukid-security-and-operations.md) |
| `docs/add/06-roadmap.md` | [docs/05-delivery/hukid-roadmap.md](hukid-roadmap.md) |
| `docs/add/07-perfil-hukid-v0.md` | [docs/03-design/hukid-profile.md](../03-design/hukid-profile.md) |
| `docs/add/08-blockchain-y-anclaje.md` | [docs/decisions/blockchain-and-anchoring.md](../decisions/blockchain-and-anchoring.md) |
| `docs/add/09-modelo-de-datos-postgresql.md` | [docs/03-design/hukid-data-model.md](../03-design/hukid-data-model.md) |
| `docs/add/10-wallet-backend-y-nodos.md` | [docs/03-design/hukid-wallet-backend.md](../03-design/hukid-wallet-backend.md) |
| `docs/.memlog.md` | [docs/decisions/source-notes.md](../decisions/source-notes.md) |
| `docs/.gitignore` | [.gitignore](../../.gitignore) |

## Entradas canónicas nuevas

Producto: vision, scope y glossary. Requisitos: functional-requirements, non-functional-requirements, business-rules y user-stories. Diseño: architecture, data-model, api-contracts y ux-flows. Ingeniería: coding-standards, security y testing-strategy. Entrega: implementation-plan y definition-of-done. Decisiones: ADR-0001.

README navega las categorías; AGENTS contiene instrucciones compartidas y CLAUDE las referencia. [src/README](../../src/README.md) describe la implementación real: Platform Go y panel React hasta AUTH-T08. Este mapa conserva procedencia de la reorganización; el [plan vigente](implementation-plan.md), el [índice de features](../features/README.md) y sus tasks.md mantienen la ruta y el estado actual. El [roadmap HukID](hukid-roadmap.md) conserva las fases de credenciales pendientes.

## Criterios de conservación

- Los 31 documentos/nota Markdown de origen se trasladan; .gitignore vuelve a la raíz.
- Backlogs conservan PF/EC/PA/OO/HK y criterios originales. TEAM-BACKLOGS queda explícitamente histórico.
- Los ejemplos JSON/HTTP y bloques Mermaid recibidos se conservan; no se generan firmas, SQL ni OpenAPI ausentes.
- Referencias personales disponibles en Markdown apuntan a sus equivalentes locales. Artefactos no adjuntos se registran en [pendientes](documentation-gaps.md).
- Revisiones anteriores y descripción original se distinguen del estado actual.
- Las decisiones v0, el estado draft y las diferencias entre los cortes Events/HukID se explicitan sin ampliar el alcance comercial.

Volver al [índice del proyecto](../../README.md).
