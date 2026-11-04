# Historias de usuario por equipo

> **Documento reemplazado.** Este fue el primer resumen y sus macrohistorias no son implementables. Los backlogs normativos y completos están en [índice de backlogs](../backlog-index.md) y la carpeta [backlogs](../../02-requirements/backlogs). No estimar ni desarrollar desde este archivo.

Las historias usan puntos relativos. Cada equipo debe conservar margen del 15–20% para integración, pruebas de carga y corrección de incidencias; no se compromete el 100% de su capacidad a historias nuevas.

## Equipo 1 — Content & Platform Foundation — 47 pts

**Resultado:** una organización puede presentar su oferta en una landing comercial/demo y publicar sitios/eventos rápidos sin exponer datos privados.

| ID | Historia | Pts | Criterios de aceptación |
|---|---|---:|---|
| CE-01 | Como visitante, quiero consultar la landing comercial y solicitar una demo para entender el producto y contactar al equipo. | 5 | Astro entrega páginas estáticas/edge; formulario tiene validación, anti-spam y confirmación; no almacena secretos en cliente. |
| CE-02 | Como prospecto, quiero recorrer una landing demo con eventos y una convocatoria ficticios para entender ambos flujos sin usar datos reales. | 5 | Demo aislada del entorno productivo; incluye catálogo, detalle, agenda paralela y CTA; datos seed versionados. |
| CE-03 | Como editor, quiero crear páginas con bloques tipados para publicar contenido institucional sin escribir código. | 8 | Bloques permitidos/versionados; borrador, preview y publicación inmutable; HTML/script arbitrario rechazado; auditoría de editor. |
| CE-04 | Como visitante, quiero ver catálogo y detalle de eventos publicados con baja latencia aunque una campaña genere miles de visitas. | 8 | Astro/CDN sirve cache hit sin DB transaccional; Content consume snapshots; ETag y purge tags funcionan; p95 medido bajo carga. |
| CE-05 | Como usuario autenticado, quiero una navegación administrativa consistente para entrar a CMS, configuración, participación y operaciones según mi rol. | 5 | Shell React/OIDC, ruta protegida, design tokens y estados de sesión/error; enlaces sólo a capacidades autorizadas. |
| CE-06 | Como sistema, quiero reflejar cupo/estado y agenda publicada en la landing sin consultas encadenadas a otros servicios. | 7 | Consume eventos de configuración/availability; inbox idempotente; proyección versionada; eventual consistency visible mediante timestamp. |
| CE-07 | Como responsable de calidad, quiero métricas de cache, errores públicos y accesibilidad para operar la experiencia pública. | 5 | Dashboard p95/cache hit/error rate; WCAG básico en flujos principales; alertas por degradación; runbook de invalidación. |
| CE-08 | Como equipo de producto, quiero gateway, OIDC, tenant directory y plantilla de despliegue compartidos para no redefinir seguridad ni infraestructura cinco veces. | 4 | JWT/mTLS, scopes/audience/organización firmados; dominio→sitio; CI/CD, secretos, broker, DLQ y telemetría base documentados; cada API aplica librería común. |

## Equipo 2 — Event Configuration — 44 pts

**Resultado:** un organizador puede configurar y publicar un evento o convocatoria con programas simultáneos y formularios sin alterar servicios de alta concurrencia.

| ID | Historia | Pts | Criterios de aceptación |
|---|---|---:|---|
| EC-01 | Como organizador, quiero crear un evento o convocatoria en borrador con fechas, sitio, cupo y reglas de publicación. | 5 | Validación de fechas/zona IANA/roles; comando idempotente; borrador no público; auditoría. |
| EC-02 | Como organizador, quiero definir programas o tracks paralelos y sesiones con salas/ponentes para mostrar agendas simultáneas. | 8 | Programas independientes; conflictos de sala/recurso exclusivo detectados; ETag/If-Match; UTC persistido y zona devuelta. |
| EC-03 | Como organizador, quiero crear y publicar formularios versionados para registro o postulación. | 8 | Schema/UI schema/consentimiento con hash; binding por evento y ventana; sólo un binding abierto por propósito; consumidor recibe snapshot. |
| EC-04 | Como organizador, quiero publicar un release completo de evento para que sitios, inscripción y check-in activen la misma versión. | 8 | Publish atómico; emite `configuration.event.release_published.v1` con `publication_id`, manifiesto/hashes de evento, agenda, policy y form binding; consumidor activa pending→active de forma idempotente. |
| EC-05 | Como organizador, quiero cerrar, cancelar o cambiar reglas de inscripción con trazabilidad y sin sobrepasar confirmados. | 5 | Nueva versión de policy; reducción bajo confirmados devuelve conflicto operable; consumidores reciben versión; no hay cancelación silenciosa. |
| EC-06 | Como administrador, quiero gestionar sedes, ponentes y permisos de organizador sin acceso a datos de participantes. | 5 | RBAC por organización; autorización negativa probada; API no expone respuestas de formularios. |
| EC-07 | Como equipo consumidor, quiero un contrato versionado y entorno sandbox para integrar snapshots de configuración. | 5 | OpenAPI/event schemas publicados; contract tests; datos seed; changelog y política de compatibilidad. |

## Equipo 3 — Participation — 47 pts

**Resultado:** personas y emprendimientos pueden registrarse o postular con seguridad durante picos, sin sobrecupo y con confirmación/QR trazable.

| ID | Historia | Pts | Criterios de aceptación |
|---|---|---:|---|
| PA-01 | Como participante, quiero inscribirme desde una isla React en la página Astro del evento usando el formulario vigente. | 8 | Content es dueño del shell/ruta; Participation entrega la isla y API; valida site/event/binding/snapshot; `Idempotency-Key`; rate limit y challenge anti-abuso; errores RFC 9457 sin filtrar PII. |
| PA-02 | Como sistema, quiero asignar confirmación o waitlist de forma atómica para no superar el cupo. | 8 | Policy local versionada; bloqueo/contador transaccional por evento; posición waitlist estable; pruebas de concurrencia 3× pico. |
| PA-03 | Como participante confirmado, quiero recibir un ticket QR único que sea verificable y revocable. | 5 | JWS asimétrico con `jti` opaco, `kid`, audience, organización/evento/scope, expiración y versión; emisión sólo al confirmar; cancelación revoca y emite lista firmada; no expone PII. |
| PA-04 | Como líder, quiero registrar un emprendimiento, invitar integrantes y guardar una postulación hasta el cierre. | 8 | Mínimo dos miembros configurable; invitación/aceptación; PII y archivos con control de acceso; borrador editable hasta cierre. |
| PA-05 | Como líder, quiero enviar la postulación y conservar exactamente la versión evaluable. | 5 | Submit crea snapshot inmutable de equipo/respuestas/archivos/form hash; subsanación crea nueva revisión; evento emitido. |
| PA-06 | Como organizador, quiero buscar, filtrar, confirmar/cancelar y exportar participantes o postulaciones autorizadas. | 5 | Filtros paginados; exportación delegada a Operations; cambios autorizados auditados; no permite editar respuestas enviadas. |
| PA-07 | Como servicio consumidor, quiero recibir cambios de ticket, disponibilidad y registro mediante eventos confiables. | 4 | Outbox/inbox; topics versionados; replay y duplicados probados; datos minimizados/pseudonimizados. |
| PA-08 | Como responsable de operación, quiero medir rechazo, latencia y conflicto de capacidad durante campañas de inscripción. | 4 | Métricas por evento; alertas de saturación/429/errores; traces y runbook de pico. |

## Equipo 4 — Onsite Operations — 44 pts

**Resultado:** el personal opera ingreso rápido con QR y obtiene comunicaciones/reportes sin afectar a los servicios de configuración o registro.

| ID | Historia | Pts | Criterios de aceptación |
|---|---|---:|---|
| OO-01 | Como staff, quiero iniciar sesión y seleccionar mi evento/sede autorizados antes de escanear. | 4 | OIDC/roles/event scope; dispositivo identificado; no muestra otros eventos; auditoría de sesión operativa. |
| OO-02 | Como staff, quiero escanear un QR y recibir una respuesta clara en menos de un segundo. | 8 | PWA cámara + búsqueda manual; valida ticket en proyección local; hecho append-only/idempotente; p95 online <700 ms. |
| OO-03 | Como supervisor, quiero anular un check-in con razón sin borrar el historial. | 4 | Void compensatorio; mismo ticket/event scope; actor/dispositivo/razón obligatorios; proyección efectiva recalculable. |
| OO-04 | Como organizador, quiero enviar confirmaciones y recordatorios desde eventos de dominio sin perder ni duplicar mensajes. | 5 | Worker outbox, plantillas, preferencias básicas, retry/DLQ; correo de prueba; no registra tokens ni respuestas sensibles. |
| OO-05 | Como organizador, quiero ver dashboard de asistencia y solicitar reportes/certificados sin efectuar joins remotos. | 7 | Métricas pseudonimizadas; proyección de certificado/export purpose-bound cifrada con key ID/retención; job asíncrono, watermark, URL temporal de un uso y auditoría. |
| OO-06 | Como equipo, quiero observar colas, check-ins, fallos y reportes para atender incidentes durante el evento. | 5 | Métricas, trazas, health/readiness, alertas, DLQ y runbooks; simulación de incidente. |
| OO-07 | Como plataforma, quiero evaluar elegibilidad y emitir certificado PDF antes de iniciar cualquier integración con HukID. | 6 | Consume attendance + subject envelope autorizado; regla/version/watermark congelados; certificado idempotente; emite `operations.certificate.issued.v1`; el adaptador outbound de Events puede llamar a HukID sin dependencia síncrona del flujo PDF. |
| OO-08 | Como responsable de seguridad, quiero validar QR contra clave, audience, revocación y unicidad para evitar fraude y doble ingreso. | 4 | Rechaza lista de revocación online con antigüedad >15 s; índice único para check-in efectivo; void append-only con actor/dispositivo/razón; offline explícitamente fuera del incremento. |

## Equipo 5 — HukID — 50 pts

**Resultado:** una organización puede emitir y conservar credenciales verificables desde una wallet, sin que Events custodie llaves del titular.

| ID | Historia | Pts | Criterios de aceptación |
|---|---|---:|---|
| HK-01 | Como administrador issuer, quiero configurar tenant, issuer, definición y claves de firma para emitir credenciales aisladas. | 7 | Tenant/issuer/key ownership compuesto; KMS ref; RLS; definition version publicada inmutable; metadata/JWKS. |
| HK-02 | Como sistema fuente, quiero crear una solicitud de emisión idempotente usando mi client y issuer autorizado. | 7 | OAuth scopes/grants; request hash; client no opera recursos ajenos; claims cifrados; oferta expirable/uso único. |
| HK-03 | Como wallet, quiero canjear una oferta OID4VCI y recibir una credencial firmada vinculada a mi clave. | 8 | Flutter parsea oferta, proof holder binding, almacena local cifrado; backend aplica nonce/tx-code/lockout; no sincroniza credencial en claro. |
| HK-04 | Como issuer, quiero firmar una vez y publicar status de forma concurrente segura. | 7 | Lease/CAS, KMS idempotency, artifact hash/key version ligados; status purpose correcto, revocación terminal y publicación CAS. |
| HK-05 | Como holder, quiero consultar, validar y presentar una credencial desde la wallet. | 7 | Validación firma/JWKS/vigencia/status; consentimiento previo a presentar; OpenID4VP directo; logs sin claims. |
| HK-06 | Como sistema fuente, quiero solicitar una credencial sin acoplar bases de datos. | 5 | HukID expone Integration API idempotente; el adaptador y polling pertenecen al sistema fuente; contract tests. |
| HK-07 | Como operador, quiero recuperar incidentes y aplicar retención sin perder trazabilidad. | 6 | Outbox/audit, RLS, crypto-shredding, purge de artefacto, métricas, backups/restore drill y runbooks. |

## Historias de integración obligatorias

Estas historias no pertenecen a un único equipo; se hacen en pares y se consideran incompletas sin prueba de contrato.

1. **INT-01:** Equipo 2 publica un evento y equipos 1/3/4 materializan exactamente la versión indicada.
2. **INT-02:** Equipo 3 confirma/cancela un ticket y equipo 4 permite o rechaza el check-in según su proyección, incluido replay.
3. **INT-03:** Equipo 4 emite certificado y su adaptador llama a la Integration API del Equipo 5 sin FK, bus compartido ni transacción distribuida.
4. **INT-04:** Todos los equipos demuestran aislamiento entre dos organizaciones, tokens/scopes y actor de servicio con pruebas negativas automatizadas.
