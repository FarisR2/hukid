# Plan de implementación

## Estado actual y siguiente implementación

Actualizado: 2026-11-06. AUTH-T01–T10 entregan autenticación de laboratorio: backend Go, persistencia PostgreSQL, OIDC, contexto autorizado, sesiones y [panel web React conectado](../03-design/console-auth-interface.md), auditoría y operación. El IdP y la MFA de las pruebas son sintéticos. No hay evidencia productiva ni entrega de emisión/verificación de credenciales.

AUTH-T09 añade [auditoría/redacción integrada](../03-design/console-auth-audit.md), con eventos/outbox y pruebas negativas/concurrencia. AUTH-T10 completa [operación, reversión y gate de laboratorio](authentication-gate.md). USR-T01 materializa el [contrato de miembros/invitaciones](../03-design/console-members-contract.md), políticas y reglas puras; USR-T02 añade [persistencia, RLS y transacciones](../03-design/console-members-persistence.md). USR-T03 añade [cuatro lecturas API/BFF autorizadas con filtros/cursor](../03-design/console-members-directory.md); USR-T04 conecta [creación/revocación y entrega sintética cifrada](../03-design/console-invitation-delivery.md). USR-T05 conecta [aceptación/reingreso con evidencia OIDC](../03-design/console-invitation-acceptance.md); USR-T06 conecta [ambos PATCH de membresías](../03-design/console-members-lifecycle.md) con ETag y protección del último administrador. USR-T07 conecta [revalidación/reconciliación de contexto](../03-design/console-authorization-revalidation.md). USR-T08 conecta [UI administrativa y aceptación](../03-design/console-members-interface.md). USR-T09 cierra el [gate U4 de laboratorio](members-gate.md). DASH-T01 materializa el [contrato overview/activity](../03-design/console-dashboard-contract.md), reglas UTC y fixtures sin handlers. DASH-T02 implementa [lectura base tenancy/audit autorizada](../03-design/console-dashboard-reads.md) sin endpoints. La siguiente tarea es **DASH-T03**, con criterios en [tareas FEAT-003](../features/FEAT-003-dashboard/tasks.md). La evidencia de autenticación está en [FEAT-001](../features/FEAT-001-authentication/tasks.md); estos incrementos completan miembros en laboratorio; dashboard y el negocio documental siguen pendientes.

Autoridad: los `tasks.md` de cada feature mantienen estado y evidencia por tarea; este plan mantiene la secuencia global; el [roadmap HukID](hukid-roadmap.md) mantiene las fases del producto y el [backlog Team 5](../02-requirements/backlogs/team-5-hukid.md) conserva las historias HK. Las secciones fechadas de evidencia describen su incremento histórico, no el estado actual completo.

## Ruta del panel web de administración

En estos documentos, **consola significa panel web de administración en el navegador**, no terminal. La terminal se usa para arrancar servicios y ejecutar comprobaciones de desarrollo. El backend vive en `src/platform` y el panel en `src/console`; la wallet Flutter es un cliente distinto y aún no está implementada.

| Orden de entrega | Resultado | Estado |
| --- | --- | --- |
| 1. AUTH-T01–T08 | Login, /me, selección tenant, sesión, refresh/logout, step-up y pantallas accesibles. | Implementado y probado en laboratorio. |
| 2. AUTH-T09 | Eventos de auditoría integrados, redacción de secretos y pruebas negativas/concurrencia de la feature. | Implementado y probado en laboratorio. |
| 3. AUTH-T10 | Runbook, rollout, reversión y evidencia del gate A4 de autenticación. | Completado y probado para laboratorio; producción NO-GO. |
| 4. USR-T01–T09 | Miembros, invitaciones, roles, suspensión y sus pantallas/gate. | USR-T01–T09 entregadas en laboratorio; gate U4 completado en [FEAT-002](../features/FEAT-002-user-management/tasks.md). |
| 5. DASH-T01–T08 | Navegación y resumen con miembros/actividad autorizados; fuentes de otros dominios cuando existan. | DASH-T01 contractual y DASH-T02 lectura base completadas; DASH-T03–T08 pendientes en [FEAT-003](../features/FEAT-003-dashboard/tasks.md). |

Es el orden de entrega de [features del panel](../features/README.md); sus tareas conservan dependencias concretas y permiten trabajo preparatorio cuando estén satisfechas. Tener la capacidad dashboard:read o cerrar AUTH-T10 no implementa un dashboard. DASH-T05 permanece abierto para las fuentes ausentes, sin bloquear la entrega base con fuentes disponibles.

Estos paquetes concretan parte de foundation; no sustituyen el recorrido de emisión/verificación ni completan todas sus dependencias. La propuesta de pasar directamente a un primer flujo HK después de AUTH-T10, posponiendo miembros/dashboard, no está adoptada como cambio de prioridad. Debe acordarse su alcance antes de modificar el backlog; no existe una dependencia técnica global que obligue a terminar todo el dashboard para iniciar el laboratorio de credenciales.

## Cómo retomar DASH-T03

1. Leer [spec](../features/FEAT-003-dashboard/spec.md), [plan](../features/FEAT-003-dashboard/plan.md) y [tareas](../features/FEAT-003-dashboard/tasks.md) de FEAT-003.
2. Conectar API/BFF sobre la [lectura base DASH-T02](../03-design/console-dashboard-reads.md), con credencial SQL dedicada y el [contrato DASH-T01](../03-design/console-dashboard-contract.md). Autenticar cursor dentro del snapshot tras reautorizar revisión/scopes, aplicar filtros, estados, errores y no-store. UI queda para DASH-T04.
3. Reutilizar autorización viva, matriz y contexto AUTH/USR; conservar los límites del [gate U4](members-gate.md). Sin fuente confiable de ownership issuer no conceder grants ni inventar dominios.
4. Mantener AUTH→USR→DASH y el roadmap HK separado. El dashboard base no acredita emisión, wallet, verificación ni preparación productiva.

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

La fase 0 de credenciales sigue pendiente: probar OIDC para operadores no demuestra firma/verificación de VC ni interoperabilidad wallet/verifier. La fase 1 sólo tiene una base parcial con AUTH-T01–T10 de laboratorio; faltan, entre otros, administración real, emisores, clientes/grants de integración, auditoría institucional/publicación y puerto KMS. Las fases 2–6 no se declaran implementadas por disponer de sus especificaciones.

El primer recorrido de negocio objetivo es **sistema fuente → oferta → wallet → credencial firmada → verificación y estado**. Ver la relación fase/historias en el roadmap antes de descomponer un incremento HK. El producto documentado verifica credenciales digitales y su emisor/estado; comprobar la autenticidad de un PDF o fotografía arbitrarios requiere requisitos propios y no se asume incluido.

## Dependencias y salida

Team 4 no implementa el issuer y Team 5 no consume el bus Events. Acordar definition de participación, vínculo entre organizaciones/issuers, entrega al destinatario, revocación/reemplazo y evidencias de consentimiento antes de integrar. El canal final de invitación y la distribución de wallet se validan con el piloto.

Cada etapa cumple [Definition of Done](definition-of-done.md), [pruebas](../04-engineering/testing-strategy.md) y contratos. No desplegar integraciones independientes sólo desde tablas narrativas sin artefactos verificables.
