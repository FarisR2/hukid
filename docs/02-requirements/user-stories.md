# Historias de usuario

Los backlogs originales se conservan completos con sus IDs y criterios de aceptación. El índice informa 163 historias; el conteo no mide esfuerzo ni confirma implementación.

La [consola HukID](../features/README.md) dispone de paquetes FEAT-001/002/003 con requisitos, planes y tareas. Detallan y amplían la foundation HK; no modifican los IDs ni el conteo de historias originales. AUTH-T01–T05 implementan bootstrap, contratos, persistencia, [login/callback](../03-design/console-oidc-login.md) y [autorización operator con /me](../03-design/console-operator-context.md) de laboratorio. AUTH-T06/T07 añaden ciclo de sesión y [step-up/contexto](../03-design/console-reauthentication.md) de laboratorio. AUTH-T08 conecta [interfaz y navegador](../03-design/console-auth-interface.md); USR-T01–T08 conectan [gestión de miembros e invitaciones](../03-design/console-members-interface.md); USR-T09 completa el [gate de laboratorio](../05-delivery/members-gate.md); DASH-T01 fija el [contrato del dashboard](../03-design/console-dashboard-contract.md), DASH-T02 conecta lectura autorizada y DASH-T03 [API/BFF/cursor](../03-design/console-dashboard-http.md); UI sigue pendiente en DASH-T04.

| Equipo | Responsabilidad | Backlog | Historias declaradas |
| --- | --- | --- | ---: |
| 1 | Content & Platform Foundation: sitios, CMS, identidad y plataforma. | [PF](backlogs/team-1-content-platform.md) | 40 |
| 2 | Event Configuration: eventos, agenda, formularios y publicación. | [EC](backlogs/team-2-event-configuration.md) | 27 |
| 3 | Participation: registros, cupos, QR, equipos y postulaciones. | [PA](backlogs/team-3-participation.md) | 32 |
| 4 | Onsite Operations: asistencia, comunicaciones, PDF y adaptador HukID. | [OO](backlogs/team-4-onsite-operations.md) | 31 |
| 5 | HukID: issuer/API Go y wallet Flutter. | [HK](backlogs/team-5-hukid.md) | 33 |

## Historias de integración

- Configuration→Content/Participation/Onsite: misma release completa, replay y recuperación de gaps.
- Participation→Onsite: emisión/revocación de ticket y acceso con proyección consistente.
- Operations→HukID: certificado elegible, consentimiento, request idempotente, oferta, wallet y polling v0.
- Issuer→wallet→verifier: firma, binding, status y consentimiento según el corte de producto.
- Seguridad: pruebas negativas entre tenants, issuers, clients, roles y clases de token.

## Preparación de una historia

Debe declarar actor y scope, precondiciones, estados alternativos, contrato, datos propietarios, criterios observables, pruebas negativas y telemetría. Cumplir la [Definition of Done](../05-delivery/definition-of-done.md) antes de marcarla entregada.

El [índice de entrega](../05-delivery/backlog-index.md) determina el MVP. El [resumen legado](../05-delivery/archive/team-backlogs.md) es histórico y no se usa para estimación ni implementación.
