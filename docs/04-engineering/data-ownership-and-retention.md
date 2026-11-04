# Ownership, privacidad y retención de datos

Los plazos son defaults de producto y deben ratificarse con la política institucional y legislación aplicable antes de producción. Legal hold suspende purga; las copias de seguridad expiran por su ciclo normal y no reintroducen datos purgados al restaurar.

| Dominio/owner | Datos propios | Consumidores permitidos | Retención default |
|---|---|---|---|
| T1 Platform | organizations, users `(issuer,sub)`, memberships, invitations, sessions, service accounts, domains, audit auth | servicios para autorización/capabilities | sesión: TTL idle 8 h/absoluto 30 d; invitación 7 d; audit 2 a; membresía mientras contrato + 2 a |
| T1 Content | sites, pages, publications, navigation/theme, media, public event projections | público/CDN | versiones 2 a; media retirada 30 d; caché según headers |
| T2 Configuration | events, venues, speakers consentidos, programs, sessions, form definitions/versions/bindings, releases | T1/T3/T4 vía release | evento + 5 a; borradores abandonados 180 d; audit 2 a |
| T3 Participation | attendee identity, answers, consents, registrations, tickets, ventures, memberships, applications, files | titular, roles autorizados; proyecciones mínimas a T1/T4 | no seleccionado: 12 m tras cierre; participante/certificación: 5 a; archivos rechazados 12 m; consent record 5 a |
| T4 Onsite | devices, shifts, attendance facts, revocation projections | Operations y auditoría | asistencia 5 a; telemetría dispositivo 90 d; audit 2 a |
| T4 Operations | templates, message delivery, report jobs/artifacts, certificate/rule/template, HukID delivery local | usuario autorizado/verificación | mensajes 90 d; report artifact 24 h; certificado/metadatos 5 a; payload temporal HukID hasta terminal + 30 d |
| T5 HukID | tenants/issuers/definitions/clients, encrypted issuance claims, offers, credentials/status, audit | wallet/sistema fuente según grants | conforme a contrato canónico HukID; claims se crypto-shred según propósito/estado |

## Clasificación y controles

| Clase | Ejemplos | Control mínimo |
|---|---|---|
| Pública | landing, agenda publicada, speaker consentido | CDN, integridad de release, no cookies privadas |
| Interna | IDs opacos, estados, métricas agregadas | auth de servicio, tenant scope, cifrado en tránsito |
| Confidencial | email, teléfono, respuestas, venture docs | cifrado en reposo, RLS, field policy, redacción de logs |
| Restringida | documentos de identidad, datos financieros/premios, claims de credencial | consentimiento/propósito explícito, MFA para export, envelope encryption/KMS, acceso auditado |

## Reglas de transferencia

- El tenant se deriva de claims validados; nunca de un header o body libre.
- Content no recibe respuestas de formularios ni listas de participantes.
- Onsite recibe ticket/registro opacos y datos mínimos de búsqueda, no el expediente.
- Operations obtiene sujetos de certificado mediante referencia/envelope cifrado con audience, purpose y `retention_until`.
- HukID recibe por HTTPS sólo los claims necesarios para la credential definition y consentimiento; Events guarda el ID externo, no copia la credencial.
- Exportaciones sensibles requieren scope, MFA reciente, filtro explícito, watermark/audit y URL de un uso.

## Derechos y purga

Cada owner implementa búsqueda por `data_subject_id` opaco, exportación autorizada, corrección donde no rompa evidencia, anonimización/borrado y tombstone para evitar reingesta. Los jobs de purga emiten métricas de completitud y propagan comandos a proyecciones/cachés; auditoría conserva sólo lo legalmente necesario y no contiene payload sensible.
