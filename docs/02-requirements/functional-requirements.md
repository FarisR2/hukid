# Requisitos funcionales

Los grupos FR facilitan navegación; los criterios verificables completos siguen en las historias PF/EC/PA/OO/HK enlazadas. No sustituyen sus IDs ni agregan alcance comercial.

## Events

| Grupo | Capacidad requerida | Owner / evidencia |
| --- | --- | --- |
| FR-E01 | Organizaciones, membresías, login OIDC, sesiones, permisos, dominios y service accounts. | Team 1, PF-001–025 |
| FR-E02 | CMS, medios, preview/publicación, sitios públicos, demo y shell administrativo. | Team 1, PF-030–046 |
| FR-E03 | Ciclo de evento, agenda paralela, recursos, formularios/consentimientos y releases coherentes. | Team 2, EC-001–043 |
| FR-E04 | Registro, verificación, autoservicio, cupos, waitlist, emisión/revocación de ticket. | Team 3, PA-001–015 |
| FR-E05 | Emprendimientos, equipos, invitaciones, archivos, envío/subsanación y admisibilidad. | Team 3, PA-020–035 |
| FR-E06 | Dispositivos, turnos, readiness, check-in/out, búsqueda y void auditable. | Team 4, OO-001–017 |
| FR-E07 | Comunicaciones, dashboards, reportes, elegibilidad y certificados PDF. | Team 4, OO-020–044 |
| FR-E08 | Solicitar credencial opcional y reconciliar con HukID sin compartir DB/bus. | Team 4, OO-045 |

## HukID

| Grupo | Capacidad requerida | Evidencia Team 5 |
| --- | --- | --- |
| FR-H01 | Administrar tenant/issuer, claves, definitions publicadas y clientes con grants. | HK-001–005 |
| FR-H02 | Crear, consultar y cancelar solicitudes idempotentes; generar ofertas opacas y temporales. | HK-010–013 |
| FR-H03 | Publicar metadata/JWKS; autorizar wallet, validar proof y entregar emisión inmediata/diferida. | HK-020–025 |
| FR-H04 | Onboarding y bloqueo local, claves protegidas, escaneo, consentimiento y almacenamiento cifrado. | HK-030–033 |
| FR-H05 | Consultar estado, eliminar copia local y reemitir bajo policy. | HK-034–036 |
| FR-H06 | Solicitar, consentir, generar y verificar presentaciones directas. | HK-040–043; corte posterior según piloto |
| FR-H07 | Suspender/reactivar/revocar, publicar status, rotar claves, retener/purgar y operar. | HK-050–056 |

## Aceptación

Cada historia declara actor, permiso, precondiciones, estados alternativos, contrato, datos, pruebas negativas y telemetría. El [alcance](../01-product/scope.md) determina qué capacidades entran en la primera entrega.

Fuentes: [historias por equipo](user-stories.md), [casos de uso HukID](../03-design/hukid-ux-flows.md), [API](../03-design/api-contracts.md).
