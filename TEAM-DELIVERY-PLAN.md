# Plan de equipos y cargas

## Reparto recomendado

La comparación es por tamaño de entrega, riesgo técnico, superficies frontend/backend, datos e integración; no por número exacto de endpoints.

| Equipo | Entregable end-to-end | Frontend | Backend/datos | Estimación relativa |
|---|---|---|---|---:|
| 1. Content & Platform Foundation | CMS, demo, sitios públicos y base transversal | Astro + React CMS/shell | Content API + gateway/OIDC/tenant directory | alta; 40 historias, repartir plataforma y experiencia en dos pares |
| 2. Event Configuration | configurar/publicar eventos, agenda y formularios | React backoffice | Config API + DB + outbox | media-alta; 27 historias con fuerte modelado/versionado |
| 3. Participation | registros, cupos, QR, postulaciones y proyección autorizada | Isla React en Astro + React admin | Participation API + DB | alta; 32 historias y mayor prueba de concurrencia |
| 4. Onsite Operations | check-in PWA, workers, reportes/certificados y comunicaciones | React PWA/dashboard | Operations API + DB + colas | alta; 31 historias y cuatro runtimes/workers |
| 5. HukID | issuer/node, Integration API y wallet | Flutter + consola mínima | Go + DB/KMS adapters | alta por riesgo; 33 historias y reserva para conformance/criptografía |

Los puntos anteriores fueron retirados porque estaban asignados a macrohistorias incompletas y daban una falsa precisión. Los cinco equipos tienen una carga comparable por combinación de volumen, complejidad, superficies y riesgo, no por cantidad de filas. Cada equipo debe estimar las historias canónicas después del Sprint 0; si la capacidad es idéntica, el Equipo 1 necesita dos pares de trabajo internos y el Equipo 5 reserva 20% para spikes/conformance. El alcance MVP se congela con el índice de backlog, no con este conteo.

## Ruta de integración

```text
Sprint 0: contratos, repositorios, OIDC, CI/CD, observabilidad mínima
Sprint 1: publicación de evento → proyección pública → landing demo
Sprint 2: configuración publicada → registro concurrente → ticket QR
Sprint 3: ticket → check-in → reporte; equipo/postulación básico
Sprint 4: certificados y adaptador outbound HukID opcional, propiedad del Equipo 4
```

## Dependencias explícitas

| Productor | Consumidor | Contrato / condición |
|---|---|---|
| Equipo 2 | Equipos 1, 3, 4 | `configuration.event.release_published.v1` con `publication_id` y manifiesto completo |
| Equipo 3 | Equipos 1, 4 | `participation.registration.confirmed.v1`, `participation.ticket.revoked.v1`, `participation.availability.changed.v1` |
| Equipo 4 | Equipo 5 | Equipo 4 posee el adaptador outbound y llama `POST /v1/issuance-requests`; Equipo 5 posee la API HukID; no hay acceso a DB ni bus ajeno |
| Equipo 1 | Equipos 2–4 | gateway, OIDC, tenant directory, autorización compartida, design system y CI/CD; no decide reglas de dominio |

## Definition of Done común

- OpenAPI/AsyncAPI actualizado y versionado antes de integrar.
- Migraciones propias forward-only y prueba de restore en staging.
- Idempotencia en comandos expuestos y consumer inbox en eventos.
- Métricas de latencia/error/lag, trazas con `trace_id` y logs sin PII/tokens.
- Tests de contrato productor-consumidor y e2e del flujo que toque.
- Autorización negativa probada: otra organización, rol o client no puede leer/modificar el recurso.
- Runbook de operación y dashboard mínimo entregados con el servicio.
