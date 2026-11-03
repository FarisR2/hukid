---
name: "Plataforma de Eventos — despliegue por cinco equipos"
type: architecture-spine
purpose: build-substrate
altitude: initiative
paradigm: "event-driven microservices with independently owned data and CQRS public projections"
scope: "five-team delivery split for public content, event configuration, participation, onsite operations and HukID"
status: draft
created: 2026-11-02
updated: 2026-11-02
sources:
  - "../../architecture/events-platform-2026-11-02/ARCHITECTURE-SPINE.md"
  - "../../architecture/events-platform-2026-11-02/TECHNICAL-DESIGN.md"
  - "../../briefs/brief-plataforma-eventos-convocatorias-unas-2026-11-02/brief.md"
companions:
  - "MICROSERVICES-ARCHITECTURE.md"
  - "TEAM-DELIVERY-PLAN.md"
  - "TEAM-BACKLOGS.md"
  - "INTEGRATION-CONTRACTS.md"
---

# Architecture Spine — cinco equipos y microservicios

## Design Paradigm

Microservicios orientados a eventos, con ownership exclusivo de datos y proyecciones CQRS para lectura pública. Se separan sólo los dominios con perfiles de concurrencia, disponibilidad o ownership distintos; no se crean servicios por entidad.

## Inherited invariants

Se mantienen las reglas funcionales de la arquitectura original: snapshots publicados inmutables, formularios versionados, cupo/waitlist atómico, asistencia append-only, certificados antes de HukID, idempotencia, ETag para edición, datos minimizados y migraciones forward-only.

### AD-1 — Cinco productos desplegables, cinco dueños

- **Binds:** TEAMS, DEPLOYMENT, OWNERSHIP
- **Prevents:** repositorios/servicios compartidos sin responsable y división por pantallas.
- **Rule:** los equipos entregan Content & Platform Foundation, Event Configuration, Participation, Onsite Operations y HukID. Cada uno posee código, base lógica, migraciones, APIs, eventos, observabilidad y runbook de su producto. Content & Platform Foundation es dueño de gateway, integración OIDC, tenant directory, resolución dominio→sitio, librería de autorización y plantilla CI/CD; los demás equipos aplican ese contrato, no lo redefinen.

### AD-2 — La carga pública no alcanza el núcleo transaccional

- **Binds:** CONTENT, PUBLIC-API, SCALE
- **Prevents:** que una campaña de Facebook degrade edición, registros o check-in.
- **Rule:** Astro/CDN y Content sirven sólo snapshots/proyecciones publicadas cacheables. Content consume eventos de publicación/disponibilidad; una visita pública normal no hace llamada encadenada a Configuration ni Participation.

### AD-3 — Participation decide cupos y emite tickets

- **Binds:** REGISTRATION, CAPACITY, TICKETS
- **Prevents:** sobrecupo por coordinación distribuida o doble fuente de verdad.
- **Rule:** Participation materializa la policy publicada y es único escritor de registro, contador/cupo, waitlist y ticket. Configuration sólo publica versiones de regla; Onsite sólo consume tickets y hechos de asistencia.

### AD-4 — Check-in tolera picos y degradación sin cambiar registros

- **Binds:** ONSITE, ATTENDANCE, AVAILABILITY
- **Prevents:** filas por dependencia sincrónica con registro y correcciones destructivas.
- **Rule:** Onsite valida ticket contra su proyección versionada y escribe hechos append-only idempotentes. Nunca confirma, cancela ni reactiva registros. El modo offline persiste cola cifrada y requiere reconciliación explícita.

### AD-5 — Un servicio no escribe la base de otro

- **Binds:** DATA, INTEGRATION, SECURITY
- **Prevents:** acoplamiento invisible, joins remotos y despliegues coordinados obligatorios.
- **Rule:** cada servicio tiene credenciales/base lógica propias. Toda integración se hace por HTTP versionado o eventos desde outbox con inbox idempotente; no hay FK, consulta SQL ni transacción distribuida entre servicios.

### AD-6 — Publicar es el corte de consistencia entre dominios

- **Binds:** EVENTS, FORMS, CONTENT, PARTICIPATION
- **Prevents:** que landing, formulario y capacidad usen revisiones distintas.
- **Rule:** Configuration crea un `publication_id` y emite un único manifiesto `configuration.event.release_published.v1` con snapshot completo, hashes y artefactos requeridos. Cada consumidor carga la versión como `pending` y sólo la activa localmente cuando tiene el manifiesto completo; `aggregate.version` ordena replays. No se activan agenda, formularios y policy por separado.

### AD-7 — Eventos tienen contrato primero y compatibilidad explícita

- **Binds:** API, EVENT-BUS, TEAMS
- **Prevents:** romper consumidores durante trabajo paralelo.
- **Rule:** OpenAPI y schemas de eventos se revisan antes de código. Todo evento lleva envelope canónico, topic con versión y datos mínimos. Cambios incompatibles crean nueva versión y período de convivencia.

### AD-8 — PII permanece en Participation; operaciones usa mínimo necesario

- **Binds:** PRIVACY, CONTENT, ONSITE, REPORTING
- **Prevents:** copias de formularios y PII en proyecciones o logs.
- **Rule:** Participation conserva el registro canónico. Content sólo guarda datos públicos; Onsite recibe únicamente `organization_id`, `event_id`, ticket opaco/hash, versión/estado/vigencia, reglas de acceso y pseudónimo no reversible. Operations puede recibir una proyección purpose-bound cifrada para certificado/export, con allowlist, key ID, retención y acceso de reporte explícitos; nunca hace SQL remoto. Logs, métricas, DLQ y eventos prohíben email, DNI, teléfono, nombre, respuestas, documentos, QR y tokens salvo la proyección cifrada autorizada.

### AD-9 — HukID sigue siendo otro producto

- **Binds:** HUKID, CERTIFICATES, INTEGRATION
- **Prevents:** acoplar wallet/issuer a la operación de eventos.
- **Rule:** Operations emite `operations.certificate.issued.v1` para el PDF. Sólo cuando el usuario/organización lo solicita, un worker/adaptador propiedad del Equipo 4 crea la solicitud en la Integration API de HukID por HTTP idempotente y reconcilia su estado por polling/webhook. El Equipo 5 posee únicamente HukID (API, issuer/node y wallet): no consume el bus interno, no comparte base ni autentica usuarios de Events.

### AD-10 — Escalar exige límites y evidencia, no sólo réplicas

- **Binds:** OPERATIONS, PERFORMANCE, RELIABILITY
- **Prevents:** autoscaling sin protección de DB o promesas de capacidad sin prueba.
- **Rule:** gateway aplica WAF/cuotas; servicios miden p95, errores, pool DB, cola/DLQ y lag de proyección. Antes de cada evento masivo se prueba 3× el pico esperado de registro/check-in y se publica un runbook de contingencia.

### AD-11 — El ticket es una credencial operativa verificable

- **Binds:** PARTICIPATION, ONSITE, SECURITY
- **Prevents:** QR predecible, replay, doble ingreso y aceptación de tickets revocados.
- **Rule:** Participation emite QR JWS asimétrico con `kid` rotatable, `jti` opaco, audience `onsite`, organización, evento, vigencia y versión. Onsite verifica firma, audience, evento, versión y revocación; su tabla impone un único check-in efectivo por `(ticket_id,event_id,scope)`. Online rechaza si su lista de revocación firmada tiene más de 15 s; un QR recién emitido se valida criptográficamente aun antes de materializarse. Offline queda fuera del incremento inicial.

### AD-12 — Autorización y tenant son datos firmados, no headers

- **Binds:** IDENTITY, API, DATA
- **Prevents:** acceso cross-tenant por body/header o APIs internas sin actor.
- **Rule:** gateway y llamadas service-to-service validan JWT/mTLS con audience, scopes, `organization_id` y actor firmados. Cada base usa rol no propietario con `FORCE RLS` y sólo establece tenant desde claims validados. Participante cancela sólo su registro mediante sesión o enlace de propósito único; check-in exige `onsite:checkin` por evento/sede; reportes exigen `reports:read` por organización/evento.

## Deferred

- Separar físicamente cada base a clúster distinto: decidir al superar límites de rendimiento, residencia o aislamiento contractual.
- Kafka/Pulsar frente a broker administrado simple: decidir tras estimar volumen, retención y presupuesto; el contrato de eventos no depende del broker.
- Pagos/SUNAT, evaluación avanzada, mentorías y multiinstitución: no entran al primer incremento paralelo.
- Offline check-in: se implementa sólo después de completar las historias OO-04 y prueba de conflicto en campo.
