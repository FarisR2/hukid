# Implementación HukID

AUTH-T01 incorpora `platform/` (bootstrap HTTP local Go) y `console/` (entry point React/TypeScript con Vite), según la estructura acordada con el owner. La consola aún no tiene pantallas; no se han implementado login, BFF, Management ni wallet.

AUTH-T02 añade contratos/configuración en `platform/contracts` y `platform/config`, reglas Go en `platform/internal/authentication`, y tests OIDC aislados bajo `tests/`. Ver [contrato y alcance del laboratorio](../docs/03-design/console-auth-contract.md). El IdP del harness no forma parte del backend de producción.

AUTH-T03 añade migraciones y acceso PostgreSQL en `platform/internal/adapters/postgres`, un CLI test-only en `platform/cmd/testdb` y harness de clúster descartable en `scripts/test-postgres.mjs`. Ver [persistencia y límites](../docs/03-design/console-persistence.md). La API no conecta aún con esa DB ni ejecuta bootstrap al arrancar.

Ver [desarrollo local](../docs/04-engineering/local-development.md) para versiones, instalación, checks y arranque. Seguir el [plan](../docs/05-delivery/implementation-plan.md), los [estándares](../docs/04-engineering/coding-standards.md) y [AGENTS.md](../AGENTS.md). La arquitectura distingue productos Events y HukID; no mezclar sus bases, identidades o convenciones por compartir repositorio.
