# Plan de implementación

## Estado de partida

Especificaciones Events y HukID reunidas localmente. AUTH-T01 incorpora [bootstrap local](../04-engineering/local-development.md) en src/platform y src/console, sin login ni pantalla funcional. Primero cerrar contratos ejecutables y decisiones del piloto; luego construir según dependencias. La reorganización y este bootstrap no modifican la prioridad comercial ni declaran completadas fases.

## Paquetes para comenzar la consola HukID

El usuario confirmó el ámbito Team 5. Los paquetes [FEAT-001 autenticación](../features/FEAT-001-authentication/spec.md), [FEAT-002 miembros](../features/FEAT-002-user-management/spec.md) y [FEAT-003 dashboard](../features/FEAT-003-dashboard/spec.md) incluyen spec, plan y tasks. El [índice](../features/README.md) define el orden. AUTH-T01/T02/T03 entregan toolchain, [contrato/política/IdP de laboratorio](../03-design/console-auth-contract.md) y [foundation PostgreSQL](../03-design/console-persistence.md); la siguiente tarea es AUTH-T04 (OIDC/callback). Las funcionalidades integradas de los tres paquetes aún no están implementadas.

Estos paquetes concretan la consola dentro de foundation, sin reemplazar el thin slice de emisión ni exigir implementar primero todos los módulos HukID. Los contratos nuevos propuestos y las políticas de sesión/permisos se validan en [ADR-0002](../decisions/ADR-0002.md) y sus tareas iniciales.

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

## Dependencias y salida

Team 4 no implementa el issuer y Team 5 no consume el bus Events. Acordar definition de participación, vínculo entre organizaciones/issuers, entrega al destinatario, revocación/reemplazo y evidencias de consentimiento antes de integrar. El canal final de invitación y la distribución de wallet se validan con el piloto.

Cada etapa cumple [Definition of Done](definition-of-done.md), [pruebas](../04-engineering/testing-strategy.md) y contratos. No desplegar integraciones independientes sólo desde tablas narrativas sin artefactos verificables.
