# Alcance y cortes de entrega

## MVP comercial Events

Incluye CMS y sitios públicos, identidad/organizaciones/permisos, configuración de eventos y agenda, formularios versionados, registros individuales, cupos y lista de espera, emprendimientos/equipos/postulaciones, tickets QR, check-in online, comunicaciones transaccionales, reportes básicos y certificados PDF.

Fuera del primer incremento: pagos/facturación, evaluación avanzada, mentorías, check-in offline e integraciones institucionales complejas. El diseño contempla múltiples instituciones; las capacidades avanzadas de operación multiinstitución se difieren. El [índice de backlogs](../05-delivery/backlog-index.md) es la fuente del corte por equipo.

## Entrega inicial HukID

Team 5 entrega tenants/issuers/definitions/clients, Integration API, OID4VCI mínimo, firma/status/operabilidad y wallet para recibir, guardar y consultar. La integración Events→HukID es opcional para el primer cliente Events.

El [perfil v0.1-draft](../03-design/hukid-profile.md) define VCDM 2.0, application/vc+jwt, ES256, holder binding, status y presentación directa. Define compatibilidad objetivo; no demuestra que esos componentes estén implementados. OID4VP completo y recuperación avanzada son posteriores al primer cliente Events si el piloto no los exige. El roadmap independiente de HukID conserva fases POS, verifier y educación.

## Límites v0

- Issuers administrados en HukID, con URL HTTPS y key ring exclusivo. No nodo desplegado por institución.
- Wallet local-only por defecto; reemisión issuer-reauth según policy. Account-linked y sincronización multidispositivo fuera de v0.
- Events reconcilia por polling. Webhooks son evolución posterior.
- Formato v0 sin selective disclosure: compartir la VC revela su contenido completo.
- Sin dependencia de blockchain. Anclaje por lotes es una capacidad futura opcional.
- Custom domains, self-hosted, SD-JWT, BBS, mdoc y presentación offline quedan fuera de v0.

## Estado del paquete

Este repositorio contiene especificaciones Markdown y el [bootstrap local AUTH-T01](../04-engineering/local-development.md), con login/callback, lecturas autorizadas y [ciclo de sesión de laboratorio](../03-design/console-session-lifecycle.md), con [interfaz de autenticación AUTH-T08](../03-design/console-auth-interface.md) de laboratorio. El perfil permanece draft y faltan artefactos ejecutables citados por las fuentes. El OpenAPI de consola y el DDL propio se validan en laboratorio; esto no acredita los artefactos históricos ausentes, suites de conformidad ni un servicio desplegado. Consultar [pendientes](../05-delivery/documentation-gaps.md).

## Fuentes

[Corte por equipos](../05-delivery/backlog-index.md), [roadmap HukID](../05-delivery/hukid-roadmap.md), [wallet/backend](../03-design/hukid-wallet-backend.md), [anclaje](../decisions/blockchain-and-anchoring.md).
