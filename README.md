# Plataforma de eventos y HukID

Este repositorio reúne la especificación de Events y del producto independiente HukID, bootstrap, contratos, foundation PostgreSQL, login OIDC y [autorización operator con /me AUTH-T05](docs/03-design/console-operator-context.md) de laboratorio. AUTH-T06 añade [ciclo de sesión, refresh/logout y purga](docs/03-design/console-session-lifecycle.md); AUTH-T07 añade [MFA/step-up y contexto AUTH-T07](docs/03-design/console-reauthentication.md); AUTH-T08 añade [interfaz y navegador](docs/03-design/console-auth-interface.md); auditoría integrada y gate operativo siguen pendientes. No acredita interoperabilidad ni preparación productiva.

## Documentación

| Área | Punto de entrada |
| --- | --- |
| Producto | [Visión](docs/01-product/vision.md), [alcance](docs/01-product/scope.md), [glosario](docs/01-product/glossary.md) |
| Requisitos | [Funcionales](docs/02-requirements/functional-requirements.md), [no funcionales](docs/02-requirements/non-functional-requirements.md), [reglas](docs/02-requirements/business-rules.md), [historias](docs/02-requirements/user-stories.md) |
| Diseño | [Arquitectura](docs/03-design/architecture.md), [datos](docs/03-design/data-model.md), [APIs](docs/03-design/api-contracts.md), [flujos](docs/03-design/ux-flows.md) |
| Ingeniería | [Código](docs/04-engineering/coding-standards.md), [seguridad](docs/04-engineering/security.md), [pruebas](docs/04-engineering/testing-strategy.md) |
| Entrega | [Plan](docs/05-delivery/implementation-plan.md), [Definition of Done](docs/05-delivery/definition-of-done.md) |
| Features de consola HukID | [Índice y orden de implementación](docs/features/README.md): autenticación, gestión de miembros y dashboard, con spec/plan/tasks. |
| Contrato de autenticación de consola | [Baseline AUTH-T02 y límites del laboratorio](docs/03-design/console-auth-contract.md) |
| Persistencia de consola | [Migraciones, roles/RLS y pruebas AUTH-T03](docs/03-design/console-persistence.md) |
| Login de consola | [OIDC y callback de un uso AUTH-T04](docs/03-design/console-oidc-login.md) |
| Decisiones | [ADR-0001](docs/decisions/ADR-0001.md), [ADR-0002 — propuesta de consola](docs/decisions/ADR-0002.md), [ADR-0003 — laboratorio AUTH-T02](docs/decisions/ADR-0003.md), [ADR-0004 — PostgreSQL AUTH-T03](docs/decisions/ADR-0004.md) |

Para Team 5, leer además el [perfil HukID v0.1-draft](docs/03-design/hukid-profile.md), los [contratos HukID](docs/03-design/hukid-api-contracts.md) y el [modelo PostgreSQL](docs/03-design/hukid-data-model.md).

La [correspondencia de documentos](docs/05-delivery/documentation-map.md) permite localizar todos los archivos anteriores. El [registro de pendientes](docs/05-delivery/documentation-gaps.md) identifica artefactos referenciados que no se adjuntaron y decisiones aún abiertas.

## Trabajo en el repositorio

Leer [AGENTS.md](AGENTS.md). El código inicial vive en [src](src/README.md); las versiones, checks y comandos de arranque están en [desarrollo local](docs/04-engineering/local-development.md).
