# Reglas de negocio e invariantes

## Events

| Regla | Consecuencia |
| --- | --- |
| BR-E01 — Un escritor por dominio | Participation confirma cupos y emite/revoca tickets; Onsite registra asistencia; Configuration publica reglas. |
| BR-E02 — Cupo atómico | Confirmaciones no superan capacidad y una cancelación libera/promueve una sola vez. |
| BR-E03 — Publicación completa | Agenda, formulario y policy se activan por publication_id; una release incompleta no es visible. |
| BR-E04 — Evidencia histórica | Releases, formularios publicados y revisiones enviadas no se mutan. |
| BR-E05 — Asistencia append-only | Una corrección añade un void compensatorio; no borra el hecho original. |
| BR-E06 — Certificado elegible | Regla, template, datos y watermark quedan ligados a la emisión PDF. |
| BR-E07 — Transferencia autorizada | Operations recibe proyección mínima cifrada; HukID sólo los claims y evidencia necesarios con consentimiento. |
| BR-E08 — Integración opcional | El fallo de HukID no bloquea inscripción, check-in ni generación PDF. |

## HukID

| Regla | Consecuencia |
| --- | --- |
| BR-H01 — Identidades separadas | Tenant, issuer, integration client, subject y holder no son intercambiables. |
| BR-H02 — Definition publicada | Sólo se emite desde una versión publicada e inmutable y un grant válido. |
| BR-H03 — Idempotencia y origen | Misma key/hash reproduce resultado; otro hash falla. Origen se identifica por issuer + source.system + source.reference. |
| BR-H04 — Oferta de un uso | Canje atómico; expiración/lockout/cancelación no se eluden por reintentos. |
| BR-H05 — Entrega según riesgo | QR abierto sólo para tipos aprobados de bajo riesgo; documentos nominativos necesitan policy adicional de autenticación/tx_code. |
| BR-H06 — Binding independiente | La prueba de clave y cnf.jkt vinculan wallet; no prueban por sí solos identidad del subject. |
| BR-H07 — Firma durable | Reservar payload, key version y status slots; entregar sólo el artefacto confirmado. Los reintentos no publican una segunda credencial. |
| BR-H08 — Status efectivo | Revocación terminal; suspensión reversible; no anunciar efectividad pública antes de publicar la lista. |
| BR-H09 — Custodia local | El backend no custodia clave holder, PIN ni inventario completo de wallet. Borrar copia local no revoca issuer. |
| BR-H10 — Reemisión | Local-only por defecto; issuer-reauth autoriza nueva emisión a nueva clave. No backup de clave privada en claro. |
| BR-H11 — Verificación y confianza | Firma válida, issuer reconocido y aceptación de negocio se evalúan por separado. |
| BR-H12 — No selective disclosure v0 | Presentar application/vc+jwt revela la VC completa y debe explicarse antes de consentir. |

Fuentes normativas: [estados Events](../03-design/contracts/events-state-machines.md), [perfil HukID](../03-design/hukid-profile.md), [datos HukID](../03-design/hukid-data-model.md), [flujos](../03-design/hukid-ux-flows.md).
