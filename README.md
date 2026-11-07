# Plataforma de eventos y HukID

Este repositorio reúne la especificación de Events y del producto independiente HukID, bootstrap, contratos, foundation PostgreSQL, login OIDC y [autorización operator con /me AUTH-T05](docs/03-design/console-operator-context.md) de laboratorio. AUTH-T06 añade [ciclo de sesión, refresh/logout y purga](docs/03-design/console-session-lifecycle.md); AUTH-T07 añade [MFA/step-up y contexto AUTH-T07](docs/03-design/console-reauthentication.md); AUTH-T08 añade [interfaz y navegador](docs/03-design/console-auth-interface.md); AUTH-T09 añade [auditoría integrada](docs/03-design/console-auth-audit.md); AUTH-T10 añade [runbook y gate de laboratorio](docs/05-delivery/authentication-gate.md). No acredita interoperabilidad ni preparación productiva.

## Documentación

USR-T01 materializa el [contrato de miembros e invitaciones](docs/03-design/console-members-contract.md), con schemas, política test y reglas puras; USR-T02 añade [persistencia, RLS, locks y evidencia transaccional](docs/03-design/console-members-persistence.md). USR-T03–T08 conectan sus doce operaciones API/BFF y la UI; USR-T09 añade el [gate integral de laboratorio](docs/05-delivery/members-gate.md). Para continuar, consultar el [plan de implementación vigente](docs/05-delivery/implementation-plan.md): DASH-T03 entrega [API/BFF](docs/03-design/console-dashboard-http.md) y DASH-T04 conecta la [interfaz base](docs/03-design/console-dashboard-interface.md). Siguiente: DASH-T06 para la matriz base; DASH-T05 conserva fuentes futuras cuando existan sus módulos. El orden del panel web es AUTH→USR→DASH; el [roadmap del producto](docs/05-delivery/hukid-roadmap.md) describe el negocio de emisión, wallet y verificación, aún pendiente. Completar autenticación no entrega por sí solo dashboard ni validación de credenciales.

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
