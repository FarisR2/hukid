# Plan de implementación

## Estado actual y siguiente implementación

Actualizado: 2026-11-05, con AUTH-T08 integrado en develop mediante PR #7 (merge `94785b0`, implementación `e822529`). AUTH-T01–T08 entregan autenticación de laboratorio: backend Go, persistencia PostgreSQL, OIDC, contexto autorizado, sesiones y [panel web React conectado](../03-design/console-auth-interface.md). El IdP y la MFA de las pruebas son sintéticos. No hay evidencia productiva ni entrega de emisión/verificación de credenciales.

La siguiente tarea es **AUTH-T09: auditoría/redacción integrada y pruebas negativas/concurrencia**. AUTH-T10 cierra operación, rollout, reversión y evidencia de la autenticación. Sus criterios están en [tareas FEAT-001](../features/FEAT-001-authentication/tasks.md); no completan por sí solos usuarios, dashboard ni el negocio documental.

Autoridad: los `tasks.md` de cada feature mantienen estado y evidencia por tarea; este plan mantiene la secuencia global; el [roadmap HukID](hukid-roadmap.md) mantiene las fases del producto y el [backlog Team 5](../02-requirements/backlogs/team-5-hukid.md) conserva las historias HK. Las secciones fechadas de evidencia describen su incremento histórico, no el estado actual completo.

## Ruta del panel web de administración

En estos documentos, **consola significa panel web de administración en el navegador**, no terminal. La terminal se usa para arrancar servicios y ejecutar comprobaciones de desarrollo. El backend vive en `src/platform` y el panel en `src/console`; la wallet Flutter es un cliente distinto y aún no está implementada.

| Orden de entrega | Resultado | Estado |
| --- | --- | --- |
| 1. AUTH-T01–T08 | Login, /me, selección tenant, sesión, refresh/logout, step-up y pantallas accesibles. | Implementado y probado en laboratorio. |
| 2. AUTH-T09 | Eventos de auditoría integrados, redacción de secretos y pruebas negativas/concurrencia de la feature. | Siguiente tarea; pendiente. |
| 3. AUTH-T10 | Runbook, rollout, reversión y evidencia del gate A4 de autenticación. | Pendiente; depende de AUTH-T09. |
| 4. USR-T01–T09 | Miembros, invitaciones, roles, suspensión y sus pantallas/gate. | Pendiente en [FEAT-002](../features/FEAT-002-user-management/tasks.md). |
| 5. DASH-T01–T08 | Navegación y resumen con miembros/actividad autorizados; fuentes de otros dominios cuando existan. | Pendiente en [FEAT-003](../features/FEAT-003-dashboard/tasks.md). |

Es el orden de entrega de [features del panel](../features/README.md); sus tareas conservan dependencias concretas y permiten trabajo preparatorio cuando estén satisfechas. Tener la capacidad dashboard:read o cerrar AUTH-T10 no implementa un dashboard. DASH-T05 permanece abierto para las fuentes ausentes, sin bloquear la entrega base con fuentes disponibles.

Estos paquetes concretan parte de foundation; no sustituyen el recorrido de emisión/verificación ni completan todas sus dependencias. La propuesta de pasar directamente a un primer flujo HK después de AUTH-T10, posponiendo miembros/dashboard, no está adoptada como cambio de prioridad. Debe acordarse su alcance antes de modificar el backlog; no existe una dependencia técnica global que obligue a terminar todo el dashboard para iniciar el laboratorio de credenciales.

## Cómo retomar AUTH-T09

1. Leer [spec](../features/FEAT-001-authentication/spec.md), [plan](../features/FEAT-001-authentication/plan.md) y [tareas](../features/FEAT-001-authentication/tasks.md) vigentes de FEAT-001; conservar los contratos y límites ya adoptados en sus ADR.
2. Inspeccionar auditoría/outbox existentes y los handlers de login/callback, sesión, step-up y contexto. Registrar qué eventos, redacción y pruebas ya existen antes de ampliar la implementación.
3. Integrar los eventos mínimos correlacionables y verificar que no se registren códigos, cookies, tokens, secretos ni datos personales innecesarios. Resolver fallos/concurrencia según la spec sin anunciar auditoría completa por disponer de tablas.
4. Ejecutar los checks aplicables de [desarrollo local](../04-engineering/local-development.md), incluidos PostgreSQL cuando cambie persistencia y navegador para el recorrido integrado; registrar evidencia y límites en las tareas.
5. Completar AUTH-T09 antes de declarar el gate de AUTH-T10. Esta actualización documental no implementa ninguna de las dos tareas.

## Preparación común / Sprint 0

1. Revisar alcance, historias, owners, estados y compatibilidad del perfil.
2. Incorporar/materializar OpenAPI, AsyncAPI/JSON Schema, DDL, ejemplos y vectores citados; registrar faltantes en [pendientes](documentation-gaps.md).
3. Probar librerías Go/Flutter, perfil ES256 y KMS; fijar toolchain, infraestructura y decisiones mediante ADR.
4. Preparar entornos, CI/CD, secretos, auth, fixtures, telemetría y contract-test harness.
5. Estimar historias con equipos y fijar perfiles de carga/SLO del piloto.

## Ruta Events

| Etapa | Resultado verificable | Owners |
| --- | --- | --- |
| 1 | Publicar evento y ver landing/demo con release coherente. | Teams 1 y 2 |
| 2 | Registro concurrente, cupo/waitlist y QR sin duplicados. | Teams 2 y 3 |
| 3 | Check-in, reporte y equipo/postulación básico. | Teams 3 y 4 |
| 4 | Certificado PDF; adaptador HukID opcional con polling v0. | Team 4 con Team 5 |

Detalle de coordinación y dependencias: [plan Events](events-team-plan.md). Corte de historias: [índice](backlog-index.md).

## Ruta HukID

| Fase | Resultado | Criterio principal |
| --- | --- | --- |
| 0 | Laboratorio de perfil/interoperabilidad. | Firma, proof, binding y pruebas negativas. |
| 1 | Foundation multi-tenant, IAM, clients, auditoría/outbox y puerto KMS. | Aislamiento y rotación comprobados. |
| 2 | Definition Registry y publicación inmutable. | Mapping/validación/configuration sin emitir desde draft. |
| 3 | Oferta→OID4VCI→wallet→credencial. | Un uso, idempotencia, persistencia cifrada y errores/reintentos. |
| 4 | Status, trust policy y verifier. | Revocación, freshness y presentación según corte acordado. |
| 5 | Segundo vertical educativo; Events usa adaptador fuente propio. | Núcleo sin condiciones específicas de POS/SIS/Events. |
| 6 | Hardening/piloto y operación. | Evidencia de seguridad, carga, restore y soporte. |

El [roadmap HukID original](hukid-roadmap.md) conserva entregables POS/SIS y preguntas de negocio. El primer cliente Events puede diferir OID4VP completo; anunciar compatibilidad del perfil requiere su gate aunque la entrega comercial sea menor.

La fase 0 de credenciales sigue pendiente: probar OIDC para operadores no demuestra firma/verificación de VC ni interoperabilidad wallet/verifier. La fase 1 sólo tiene una base parcial con AUTH-T01–T08; faltan, entre otros, administración real, emisores, clientes/grants de integración, auditoría integrada y puerto KMS. Las fases 2–6 no se declaran implementadas por disponer de sus especificaciones.

El primer recorrido de negocio objetivo es **sistema fuente → oferta → wallet → credencial firmada → verificación y estado**. Ver la relación fase/historias en el roadmap antes de descomponer un incremento HK. El producto documentado verifica credenciales digitales y su emisor/estado; comprobar la autenticidad de un PDF o fotografía arbitrarios requiere requisitos propios y no se asume incluido.

## Dependencias y salida

Team 4 no implementa el issuer y Team 5 no consume el bus Events. Acordar definition de participación, vínculo entre organizaciones/issuers, entrega al destinatario, revocación/reemplazo y evidencias de consentimiento antes de integrar. El canal final de invitación y la distribución de wallet se validan con el piloto.

Cada etapa cumple [Definition of Done](definition-of-done.md), [pruebas](../04-engineering/testing-strategy.md) y contratos. No desplegar integraciones independientes sólo desde tablas narrativas sin artefactos verificables.
