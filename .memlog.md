---
scope: Replanteamiento microservicios para cinco equipos
purpose: Distribuir ownership y backlog con aislamiento de concurrencia
altitude: initiative
updated: 2026-11-02
---

- (constraint) React para backoffice/PWA; Astro para landing comercial, demo y sitios públicos; PostgreSQL como almacenamiento relacional por servicio.
- (direction by user) Separar los caminos de alta concurrencia: landing/demo, registros y check-in; distribuir desarrollo entre cinco equipos, incluyendo nodo y wallet HukID.
- (decision) Separar por perfiles de carga y ownership: Content & Experience, Event Configuration, Participation, Onsite Operations y HukID.
- (decision) Landing pública usa CDN/proyección CQRS; registro controla capacidad local atómica; check-in valida contra proyección local y almacena hechos append-only.
- (decision) Comunicación entre equipos mediante HTTP/eventos versionados, outbox/inbox e independencia de bases de datos.
- (decision) Platform Foundation pertenece al Equipo 1 y es dueño de gateway, OIDC, tenant directory, autorización compartida y despliegue base; evita plataforma transversal sin owner.
- (decision) Configuration publica un release manifiesto completo; consumidores activan pending→active por publication_id, sin mezclar agenda/formulario/policy.
- (decision) Participation emite QR JWS y revocaciones firmadas; Onsite valida localmente y el modo offline se difiere fuera del primer incremento.
- (decision, supersedes previous) Operations crea certificados/reportes desde proyecciones purpose-bound cifradas y el Equipo 4 posee el adaptador outbound hacia la Integration API de HukID; HukID no consume el bus de Events.
