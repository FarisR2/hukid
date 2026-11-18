# Guía de Claude

Leer y seguir [AGENTS.md](AGENTS.md), la guía compartida de este repositorio. El mapa de lectura está en [README.md](README.md).

Para HukID, leer el [perfil local](docs/03-design/hukid-profile.md), los [contratos](docs/03-design/api-contracts.md) y los [pendientes](docs/05-delivery/documentation-gaps.md). Mantener Events y HukID como productos independientes y distinguir documentación de implementación verificada.

## Memoria (Engram)

Al empezar una sesión, antes de responder sobre estado, pendientes o decisiones, llamar `mem_current_project` y `mem_context` (proyecto `hukid`), y `mem_search` si el tema es concreto. Tras una compactación, repetir `mem_context`. Si Engram contradice a `tasks.md` o al repositorio, avisar la diferencia en lugar de elegir en silencio.
