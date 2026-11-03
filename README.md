# Replanteamiento: plataforma de eventos para cinco equipos

Este paquete reemplaza la estrategia de implementación monolítica para el desarrollo paralelo. Conserva las reglas de negocio aprobadas en la arquitectura anterior, pero transforma los límites de despliegue y ownership para soportar tráfico público, picos de inscripción y operación presencial sin depender de una sola API.

## Entregables

1. [Auditoría de omisiones del paquete anterior](COVERAGE-AUDIT.md)
2. [Architecture Spine](ARCHITECTURE-SPINE.md) y [arquitectura de microservicios](MICROSERVICES-ARCHITECTURE.md)
3. [Plan de equipos y cargas](TEAM-DELIVERY-PLAN.md) e [índice de backlog](BACKLOG-INDEX.md)
4. Historias canónicas: [Equipo 1](backlogs/TEAM-1-CONTENT-PLATFORM.md), [Equipo 2](backlogs/TEAM-2-EVENT-CONFIGURATION.md), [Equipo 3](backlogs/TEAM-3-PARTICIPATION.md), [Equipo 4](backlogs/TEAM-4-ONSITE-OPERATIONS.md), [Equipo 5](backlogs/TEAM-5-HUKID.md)
5. [Autenticación y autorización](AUTH-AND-AUTHORIZATION-CONTRACT.md)
6. [Contratos entre servicios](INTEGRATION-CONTRACTS.md), [APIs](contracts/API-CONTRACTS.md), [eventos](contracts/EVENT-CONTRACTS.md), [estados](contracts/STATE-MACHINES.md), [ownership/retención](contracts/DATA-OWNERSHIP-AND-RETENTION.md) y [bases/migraciones](contracts/DATABASE-BOUNDARIES-AND-MIGRATIONS.md)
7. [Gate de corrección y riesgos residuales](reviews/CORRECTION-GATE.md)

`TEAM-BACKLOGS.md` se conserva únicamente como historial del primer reparto y no debe usarse para estimación o implementación.

## Decisión central

No se crea un microservicio para cada tabla o pantalla. Se crean cinco productos desplegables con datos propios y un único ownership por agregado:

| Equipo | Producto principal | Motivo de aislamiento |
|---|---|---|
| 1 | Content & Platform Foundation | tráfico público/CDN, CMS, gateway y base de identidad compartida |
| 2 | Event Configuration | configuración editorial, agenda y formularios |
| 3 | Participation | picos de registro, cupos, QR, equipos y postulaciones |
| 4 | Onsite Operations | check-in de alta escritura, certificados/reportes purpose-bound, notificaciones y workers |
| 5 | HukID | issuer node/backend Go y wallet Flutter, independiente de Events |

Los servicios se coordinan por contratos versionados y eventos asíncronos; nunca comparten tablas ni realizan una transacción distribuida.
