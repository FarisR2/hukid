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

El código vive en src; el owner acordó src/platform (Go) y src/console (React/TypeScript) para AUTH-T01. Existe bootstrap, baseline contractual AUTH-T02 y [persistencia AUTH-T03](docs/03-design/console-persistence.md) probada en laboratorio, sin handlers de login. Para autenticación, seguir [contrato y política](docs/03-design/console-auth-contract.md), [ADR-0003](docs/decisions/ADR-0003.md) y [ADR-0004](docs/decisions/ADR-0004.md); no usar el fixture sintético como MFA productiva ni confundir RLS con validación JWT. Consultar [desarrollo local](docs/04-engineering/local-development.md) para manifiestos, versiones y checks. Acordar cambios de estructura con el owner antes de introducir otros productos. Seguir [coding standards](docs/04-engineering/coding-standards.md) y no anunciar tests/builds de aplicación sin ejecutarlos.

En cambios documentales, validar destinos y anclas de enlaces locales, estructura requerida, bloques de código y git diff --check. Registrar las limitaciones reales en [pendientes](docs/05-delivery/documentation-gaps.md). No crear commits ni publicar cambios salvo solicitud del usuario.

En cambios de persistencia ejecutar también `npm run test:postgres`, además de los checks generales. El harness usa un clúster descartable propio; el CLI de provisioning conserva sus restricciones de laboratorio y no se conecta a bases productivas.
