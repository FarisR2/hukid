# Plataforma de eventos y HukID

Este repositorio reúne la especificación de Events y del producto independiente HukID, junto con el bootstrap local AUTH-T01 de Platform y consola. Ese bootstrap no implementa autenticación ni acredita interoperabilidad; el resto del producto sigue descrito como trabajo por construir.

## Documentación

| Área | Punto de entrada |
| --- | --- |
| Producto | [Visión](docs/01-product/vision.md), [alcance](docs/01-product/scope.md), [glosario](docs/01-product/glossary.md) |
| Requisitos | [Funcionales](docs/02-requirements/functional-requirements.md), [no funcionales](docs/02-requirements/non-functional-requirements.md), [reglas](docs/02-requirements/business-rules.md), [historias](docs/02-requirements/user-stories.md) |
| Diseño | [Arquitectura](docs/03-design/architecture.md), [datos](docs/03-design/data-model.md), [APIs](docs/03-design/api-contracts.md), [flujos](docs/03-design/ux-flows.md) |
| Ingeniería | [Código](docs/04-engineering/coding-standards.md), [seguridad](docs/04-engineering/security.md), [pruebas](docs/04-engineering/testing-strategy.md) |
| Entrega | [Plan](docs/05-delivery/implementation-plan.md), [Definition of Done](docs/05-delivery/definition-of-done.md) |
| Features de consola HukID | [Índice y orden de implementación](docs/features/README.md): autenticación, gestión de miembros y dashboard, con spec/plan/tasks. |
| Decisiones | [ADR-0001](docs/decisions/ADR-0001.md), [ADR-0002 — propuesta de consola](docs/decisions/ADR-0002.md) |

Para Team 5, leer además el [perfil HukID v0.1-draft](docs/03-design/hukid-profile.md), los [contratos HukID](docs/03-design/hukid-api-contracts.md) y el [modelo PostgreSQL](docs/03-design/hukid-data-model.md).

La [correspondencia de documentos](docs/05-delivery/documentation-map.md) permite localizar todos los archivos anteriores. El [registro de pendientes](docs/05-delivery/documentation-gaps.md) identifica artefactos referenciados que no se adjuntaron y decisiones aún abiertas.

## Trabajo en el repositorio

Leer [AGENTS.md](AGENTS.md). El código inicial vive en [src](src/README.md); las versiones, checks y comandos de arranque están en [desarrollo local](docs/04-engineering/local-development.md).
