# Implementación HukID

AUTH-T01 incorpora `platform/` (bootstrap HTTP local Go) y `console/` (entry point React/TypeScript con Vite), según la estructura acordada con el owner. La consola aún no tiene pantallas; no se han implementado login, BFF, Management, migraciones ni wallet.

Ver [desarrollo local](../docs/04-engineering/local-development.md) para versiones, instalación, checks y arranque. Seguir el [plan](../docs/05-delivery/implementation-plan.md), los [estándares](../docs/04-engineering/coding-standards.md) y [AGENTS.md](../AGENTS.md). La arquitectura distingue productos Events y HukID; no mezclar sus bases, identidades o convenciones por compartir repositorio.
