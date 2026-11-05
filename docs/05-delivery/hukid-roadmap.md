# 06 — Roadmap de implementación

## Estado de ejecución — 2026-11-05

Este roadmap describe el producto completo; no es evidencia de fases terminadas. AUTH-T01–T09 implementan autenticación y acceso al panel web en laboratorio. AUTH-T10, miembros y dashboard siguen pendientes; el [plan vigente](implementation-plan.md) enlaza su secuencia y la siguiente tarea. Completar autenticación no equivale a completar foundation ni el flujo documental.

| Fase de este roadmap | Relación con historias del [backlog Team 5](../02-requirements/backlogs/team-5-hukid.md) | Estado verificable |
| --- | --- | --- |
| 0 — Laboratorio de credenciales | Preparación del perfil y conformance HK-056; firma/proof/binding requeridos por las historias de emisión y verificación. | Pendiente. El laboratorio OIDC de AUTH no valida VC, wallet ni verifier. |
| 1 — Foundation | HK-001/002/004/005; FEAT-001/002 concretan parte del acceso administrativo. | Parcial: AUTH-T01–T09 entregadas. Emisores, keys/KMS, clientes/grants y cierre de auditoría/operación no están completos. |
| 2 — Definition Registry | HK-003. | Pendiente. |
| 3 — Emisión y recepción | HK-010–013, HK-020–025 y las historias de wallet HK-030–033 necesarias para el recorrido. | Pendiente. |
| 4 — Status y verificación | HK-040–043, HK-050/051; las lecturas de wallet se amplían según HK-034. | Pendiente. |
| 5 — Segundo vertical educativo | Nuevas definiciones/integraciones sobre las mismas historias y núcleo. | Pendiente; el tipo de documento y el corte del piloto deben acordarse. |
| 6 — Hardening/piloto | HK-052–056 y gates de cada dominio. | Pendiente; las pruebas de autenticación no sustituyen estos gates. |

La tabla es trazabilidad de alcance, no nuevos IDs ni una declaración de que cada historia pertenezca exclusivamente a una fase. Seguridad, retención y status también imponen requisitos previos a emitir. No se renumeran las historias ni se rellenan los artefactos ausentes por inferencia.

El dashboard pertenece al panel administrativo FEAT-003 y puede incorporar lecturas de los dominios cuando existan. El negocio de credenciales vive en Platform Go, wallet Flutter y verifier según sus límites; la verificación técnica, la confianza en el emisor y la decisión de negocio deben distinguirse. Un servicio de verifier en Platform es opcional: el modo primario de presentación es wallet ↔ verifier externo, según la [arquitectura](../03-design/hukid-architecture.md).

## Principio de entrega

Construir un **thin vertical slice** real: POS → oferta → wallet → credencial → verificación. No empezar por un diseñador genérico ilimitado ni por microservicios. Luego agregar un segundo vertical académico para probar agnosticismo.

## Fase 0 — Decisiones y prototipo de interoperabilidad

**Objetivo:** eliminar incertidumbre de estándares antes de producto.

Entregables:

- Perfil HukID v0 documentado: VCDM 2.0, `application/vc+jwt`, OID4VCI/OID4VP 1.0, ES256 y holder binding por `cnf.jkt`.
- Payload VC de comprobante y certificado.
- Metadata issuer y credential offer estáticos.
- CLI/laboratorio que firma, verifica y hace pruebas negativas.
- Spike de librerías Go/Flutter y compatibilidad KMS.
- Decisión issuer identifier/key resolution.

Criterios de salida:

- Wallet de prueba puede obtener y validar una VC.
- Firma alterada, nonce equivocado, offer replay y issuer incorrecto fallan.
- Riesgos o drafts del perfil están registrados.

## Fase 1 — Foundation multi-tenant

Entregables:

- tenants, users, memberships, issuers;
- IAM OIDC/OAuth y RBAC;
- integration clients y grants;
- migrations PostgreSQL;
- audit/outbox;
- KMS signing port;
- ambientes separados e infraestructura base.

Criterios:

- aislamiento probado en repository/API/RLS;
- ninguna clave privada en app/db;
- rotación de client secret/key ensayada;
- audit de cambios críticos.

## Fase 2 — Definition Registry

Entregables:

- drafts y publicación inmutable;
- schema validator;
- mapping declarativo;
- configuration compiler;
- public schema/context hosting;
- ejemplos y contract tests.

Criterios:

- no se emite desde draft;
- definition version identificable y verificable por hash;
- cambios incompatibles obligan nueva versión/configuration.

## Fase 3 — Emisión POS end-to-end

Entregables:

- `POST /v1/issuance-requests`;
- idempotency store;
- offer endpoint y QR;
- metadata/token/nonce/credential OID4VCI;
- wallet scan, verification y encrypted storage;
- credential metadata y webhook.

Criterios:

- reintentos POS no duplican;
- offer expira y sólo se consume una vez;
- proof liga wallet a nonce/audience;
- no PII/token en logs;
- carga objetivo satisfecha.

## Fase 4 — Status y verifier

Entregables:

- status allocation/publication;
- suspend/reactivate/revoke;
- OpenID4VP request/response;
- verification report;
- trust policy v1;
- verifier demo.

Criterios:

- revoked no vuelve a active;
- freshness policy comprobada;
- resultado técnico separado de policy/business decision;
- presentation replay falla.

## Fase 5 — Segundo vertical: educación

Entregables:

- definition de certificado académico;
- integración SIS;
- display y verifier policy;
- comparación de cambios necesarios.

Criterio arquitectónico principal: ningún módulo central contiene condiciones específicas de POS o SIS. Las diferencias se expresan como configuración, mapping o policy.

## Fase 6 — Hardening y piloto

- pentest y threat-model refresh;
- conformance/interoperability;
- DR test;
- privacy/legal review;
- soporte/runbooks/on-call;
- dashboard SLO y alertas;
- piloto con cohortes pequeñas;
- métricas de activación: offers → scans → issued → retained/used.

## Backlog posterior, no MVP

- `dc+sd-jwt`/selective disclosure;
- Data Integrity/BBS;
- sync cifrado multi-dispositivo;
- delegated issuers/custom domains;
- trust registry/federation;
- marketplace de definitions;
- emisión batch;
- hardware-backed key attestation;
- offline presentation;
- mdoc.

## Convenciones de despliegue compatible

- Migraciones expand/contract: agregar antes de usar; backfill idempotente; retirar sólo cuando ninguna versión anterior dependa.
- API y worker deben ser compatibles al menos con una versión adyacente durante rolling deploy.
- Eventos son aditivos; consumidores ignoran campos desconocidos.
- Feature flags tenant-scoped tienen owner, fecha de expiración y default seguro.
- Publicar una definition es irreversible; un error se corrige desactivando nuevas emisiones y publicando una sucesora, no mutando la versión.
- Rollback de código no revierte migraciones destructivamente ni vuelve canjeables ofertas expiradas.
- Cada release ejecuta contract tests privados, vectores del perfil HukID y prueba de migración/rollback.

## Equipos/ownership sugerido

| Área | Owner lógico |
| --- | --- |
| Domain/platform API | Platform backend |
| OID4VCI/VP profiles | Interoperability/security |
| Wallet | Mobile/identity |
| KMS/status/trust | Security platform |
| POS/SIS adapters | Integrations |
| Infra/observability | Platform/SRE |
| Definitions/data minimization | Product + domain + privacy |

Con equipo pequeño, son responsabilidades, no necesariamente equipos separados.

## ADRs que deben escribirse antes de implementar

1. ADR-001 Backend runtime y librerías OpenID/VC.
2. ADR-002 Issuer identifier y resolución de claves.
3. ADR-003 Perfil criptográfico MVP.
4. ADR-004 Estrategia de tenant isolation.
5. ADR-005 Wallet key storage y perfiles de reemisión/recovery.
6. ADR-006 Claims mínimos del comprobante y semántica SUNAT.
7. ADR-007 Status purpose y freshness.
8. ADR-008 Retención/evidencia/audit.
9. ADR-009 Hosting versionado de schema/context.
10. ADR-010 Trust policy v1.

## Definition of Done de una credential type

- Purpose y amenaza documentados.
- Issuer/subject/holder definidos.
- Claims con tipo, sensibilidad y propósito.
- Schema/context versionados.
- Mapping y ejemplos positive/negative.
- Formato, algoritmo, binding y status.
- Display y accesibilidad.
- Retención y recovery/reissue.
- Trust policy/verifier use case.
- Tests de emisión, presentación y errores.
- Métricas/runbook.

## Preguntas de producto que bloquean decisiones finales

- ¿Quién es el cliente pagador: issuer, integrador, verifier o usuario?
- ¿HukID wallet es obligatoria para el ecosistema o una implementación de referencia?
- ¿La promesa principal es archivo personal, portabilidad, automatización o prueba de autenticidad?
- ¿El recibo debe contener identidad del comprador o sólo evidencia de transacción?
- ¿Qué incentivo tiene el comercio para mostrar el QR?
- ¿Qué tercero verificará una factura VC y qué decisión mejorará?
- ¿Qué organización asume soporte cuando el holder pierde acceso?

La tecnología permite emitir. El riesgo de negocio es crear credenciales que nadie necesita presentar. El piloto debe medir no sólo descargas, sino recuperación posterior del documento, presentación/verificación y ahorro operativo para issuer/verifier.

## Hitos medibles del piloto

| Métrica | Pregunta que responde |
| --- | --- |
| % tickets con oferta | ¿La integración POS funciona operacionalmente? |
| % ofertas escaneadas | ¿Existe interés del consumidor? |
| % scans que terminan emitidos | ¿El onboarding/protocolo tiene fricción? |
| % credenciales abiertas después de 7/30 días | ¿La wallet aporta archivo útil? |
| % presentadas/verificadas | ¿Hay utilidad más allá del almacenamiento? |
| tiempo/costo de soporte | ¿Recovery y fallos son sostenibles? |
| costo por credencial | ¿La unidad económica escala? |


## Relación con Events y decisiones

Este roadmap conserva los verticales POS/SIS del producto HukID. El orden de integración del cliente Events se describe en el [plan conjunto](implementation-plan.md). OID4VP completo es posterior al primer cliente Events si el piloto no lo exige; la compatibilidad de presentación descrita por el perfil debe validarse antes de anunciarla. Las decisiones existentes y las propuestas se distinguen en [ADR-0001](../decisions/ADR-0001.md).
