# Guía para agentes y colaboradores

## Contexto

Repositorio de especificación de Events y HukID. La reorganización documental no implica que el código, OpenAPI, migraciones o pruebas estén implementados. Consultar [README](README.md) para navegar.

## Orden de lectura

1. [Visión](docs/01-product/vision.md) y [alcance](docs/01-product/scope.md).
2. [Reglas de negocio](docs/02-requirements/business-rules.md) y la historia del [equipo propietario](docs/02-requirements/user-stories.md).
3. [Arquitectura](docs/03-design/architecture.md), [datos](docs/03-design/data-model.md) y [contratos](docs/03-design/api-contracts.md).
4. [Seguridad](docs/04-engineering/security.md), [pruebas](docs/04-engineering/testing-strategy.md) y [Definition of Done](docs/05-delivery/definition-of-done.md).
5. [Decisiones](docs/decisions/ADR-0001.md) y [pendientes](docs/05-delivery/documentation-gaps.md).

Para implementar consola HukID, continuar con [docs/features](docs/features/README.md). Leer spec.md, plan.md y tasks.md de la feature antes de editar código; respetar las dependencias AUTH→USR→DASH y distinguir contrato propuesto de artefacto ejecutable. La [propuesta ADR-0002](docs/decisions/ADR-0002.md) fija las validaciones iniciales; no heredar el login de Events ni alterar la wallet.

Usar el [plan vigente](docs/05-delivery/implementation-plan.md) para retomar trabajo: AUTH-T01–T10 y USR-T01–T08 entregadas en laboratorio; USR-T09 siguiente. Consola significa panel web administrativo, no terminal. Las tareas del panel no completan el [roadmap HK](docs/05-delivery/hukid-roadmap.md); la propuesta de adelantar emisión/verificación después de AUTH-T10 no cambia por sí sola la prioridad acordada. Los tasks.md son la fuente de estado por tarea y las evidencias fechadas conservan el alcance histórico de su incremento.

## Autoridad documental

- Las entradas solicitadas por categoría son la navegación principal; sus anexos conservan el detalle normativo y los IDs originales.
- Para interfaces de HukID rige el [perfil v0.1-draft](docs/03-design/hukid-profile.md). Mantener su estado draft hasta demostrar el conformance gate.
- Aplicar los contratos Events únicamente a Events. HukID conserva sus clases de token, audiences, tenant_id, camelCase de API y convenciones propias.
- El adaptador Events→HukID pertenece a Team 4. Team 5 posee backend Go y wallet Flutter. HukID no consume el bus ni comparte DB de Events.
- En v0, la reconciliación Events→HukID usa polling. Los ejemplos de webhooks describen evolución posterior.
- Los documentos en archive y las revisiones históricas no sustituyen los backlogs vigentes ni prueban disponibilidad de artefactos.
- Si dos fuentes discrepan, documentar la diferencia y su alcance antes de cambiar contratos; no ocultarla normalizando nombres o versiones.

## Cambios

- Usar enlaces relativos dentro del repositorio. Evitar rutas personales como /Users/… y no enlazar como existentes archivos ausentes.
- Conservar identificadores PF/EC/PA/OO/HK, ejemplos, estados, invariantes y procedencia al mover contenido.
- Separar decisiones ya documentadas, propuestas y trabajo de implementación pendiente.
- Los cambios de diseño deben actualizar los contratos, las historias afectadas y un ADR cuando cambien límites o compatibilidad.
- No introducir datos personales, secretos, tokens reales ni claves privadas en documentación o ejemplos.
- No inventar OpenAPI, DDL, vectores firmados o evidencia de interoperabilidad a partir de una referencia incompleta.
- Mantener una única fuente de detalle por tema y enlazarla desde los resúmenes.

## Implementación y validación

El código vive en src; el owner acordó src/platform (Go) y src/console (React/TypeScript) para AUTH-T01. Existen bootstrap, baseline contractual AUTH-T02, [persistencia AUTH-T03](docs/03-design/console-persistence.md), [login/callback AUTH-T04](docs/03-design/console-oidc-login.md) y [middleware operator y /me AUTH-T05](docs/03-design/console-operator-context.md) probados en laboratorio. Para autenticación, seguir [contrato y política](docs/03-design/console-auth-contract.md), [ADR-0003](docs/decisions/ADR-0003.md), [ADR-0004](docs/decisions/ADR-0004.md), [ADR-0005](docs/decisions/ADR-0005.md) y [ADR-0006](docs/decisions/ADR-0006.md); no usar el fixture sintético como MFA productiva ni confundir RLS con validación JWT. AUTH-T06 añade [ciclo de sesión, refresh/logout y purga](docs/03-design/console-session-lifecycle.md) según [ADR-0007](docs/decisions/ADR-0007.md). AUTH-T07 implementa [MFA/step-up y cambio de tenant](docs/03-design/console-reauthentication.md) según [ADR-0008](docs/decisions/ADR-0008.md). AUTH-T08 conecta [interfaz y navegador](docs/03-design/console-auth-interface.md) según [ADR-0009](docs/decisions/ADR-0009.md). AUTH-T09 añade [auditoría integrada](docs/03-design/console-auth-audit.md) según [ADR-0010](docs/decisions/ADR-0010.md); AUTH-T10 añade [operación y gate de laboratorio](docs/05-delivery/authentication-gate.md); producción conserva sus bloqueos explícitos. USR-T03 conecta [lecturas de miembros/invitaciones](docs/03-design/console-members-directory.md) según [ADR-0013](docs/decisions/ADR-0013.md); USR-T04 conecta [creación/revocación y entrega sintética](docs/03-design/console-invitation-delivery.md) según [ADR-0014](docs/decisions/ADR-0014.md); USR-T05 conecta [aceptación/reingreso y evidencia OIDC](docs/03-design/console-invitation-acceptance.md) según [ADR-0015](docs/decisions/ADR-0015.md); USR-T06 conecta [cambios de membresías con ETag](docs/03-design/console-members-lifecycle.md) según [ADR-0016](docs/decisions/ADR-0016.md); USR-T07 conecta [revalidación/reconciliación de contexto](docs/03-design/console-authorization-revalidation.md) según [ADR-0017](docs/decisions/ADR-0017.md); USR-T08 conecta la [UI de miembros/invitaciones y aceptación](docs/03-design/console-members-interface.md) según [ADR-0018](docs/decisions/ADR-0018.md); gate USR-T09 pendiente. Consultar [desarrollo local](docs/04-engineering/local-development.md) para manifiestos, versiones y checks. Acordar cambios de estructura con el owner antes de introducir otros productos. Seguir [coding standards](docs/04-engineering/coding-standards.md) y no anunciar tests/builds de aplicación sin ejecutarlos.

En cambios documentales, validar destinos y anclas de enlaces locales, estructura requerida, bloques de código y git diff --check. Registrar las limitaciones reales en [pendientes](docs/05-delivery/documentation-gaps.md). No crear commits ni publicar cambios salvo solicitud del usuario.

En cambios de persistencia ejecutar también `npm run test:postgres`, además de los checks generales. El harness usa un clúster descartable propio; el CLI de provisioning conserva sus restricciones de laboratorio y no se conecta a bases productivas.
