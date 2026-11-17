# FEAT-005 — Operación administrativa del issuer

- Producto: HukID Platform / Team 5.
- Estado: **incremento técnico parcial en la rama `feat/credential-issuance-mvp`; pendiente aprobación del owner, asignación de capabilities y cierre del gate**.
- Owners por límites existentes: Team 5 para backend Go/consola; Team 4 para el adaptador Events→HukID; Team 5 mantiene la wallet Flutter. El owner de producto debe aprobar permisos administrativos y el payload POS.
- Depende de: [perfil HukID v0.1-draft](../../03-design/hukid-profile.md), [ADR-0002](../../decisions/ADR-0002.md), [ADR-0031](../../decisions/ADR-0031.md), [contrato de emisión](../../03-design/api-contracts.md) y los límites de integración descritos en [roadmap](../../05-delivery/hukid-roadmap.md).
- Plan y tareas: [plan](plan.md) · [tasks](tasks.md).

## Objetivo

Dar a operadores autorizados una vista segura del ciclo del issuer: emisores, definiciones, clientes de integración, solicitudes y credenciales. Completar la autoridad administrativa solo cuando exista una política explícita distinta de las credenciales de integración. Esta feature es una descomposición de consola y operación; no reemplaza ni renumera HK-010–056.

## Alcance de este incremento

- Vistas y operaciones ya conectadas para emisores/keys, credential definitions y clientes de integración (detalladas en [administración del issuer](../../03-design/console-issuance-management.md)).
- Endpoints privados de listado de solicitudes/credenciales con tenant, paginación `limit`/`offset` y resúmenes con campos allowlisted.
- Solo el permiso explícito `issuance:read` habilita esas nuevas lecturas. El capability sigue reservado y sin otorgar a roles conforme a [contrato del dashboard](../../03-design/console-dashboard-contract.md); por eso la UI y los endpoints quedan preparados, pero inaccesibles para los perfiles actuales hasta aprobar política/ADR.
- Listados jamás devuelven claims, hashes/digests de credencial, source reference ni URI/código de oferta.

Fuera del alcance autorizado por los artefactos vigentes:

- Suspender/reactivar/revocar mediante identidad de operador. `status:write` actual es OAuth de cliente de integración y no se reutiliza como capability del operador.
- Definir o publicar una credential definition canónica POS: ADR-0031 mantiene abierto el payload, semántica SUNAT, mapping y consentimiento.
- Consumir Events o compartir su DB. Team 4 posee el adaptador; la reconciliación v0 usa polling.
- Crear una wallet Flutter nueva o cambiar sus límites; Team 5 mantiene su ownership y el recorrido depende de esa integración.

## Requisitos y aceptación

| ID | Comportamiento | Criterio de aceptación |
| --- | --- | --- |
| ISS-FR01 | Consultar solicitudes desde la consola con autoridad de operador. | AC01: GET de Management exige tenant activo y `issuance:read`; issuer operators quedan limitados a issuer asignado. Sin permiso se falla antes de revelar disponibilidad. |
| ISS-FR02 | Paginar solicitudes y credenciales. | AC02: `limit` 1–100 (default 50), `offset` 0–1,000,000; orden estable descendente por timestamp y referencia. Parámetros duplicados/desconocidos se rechazan. |
| ISS-FR03 | Minimizar datos de solicitud. | AC03: solo referencia, issuer/client, definición/configuration, estados y timestamps; sin claims, source reference, offer URI/código ni campos cifrados. |
| ISS-FR04 | Minimizar datos de credencial. | AC04: solo credential/request/issuer/client IDs, desired/published status, versión de status e issuedAt; sin claims, digest ni credential JWT. |
| ISS-FR05 | Mantener la frontera entre operador e integración. | AC05: endpoints OID4VCI/status existentes conservan su autorización de cliente; los listados nuevos no usan tokens de integración. |
| ISS-FR06 | Ejecutar cambios de status como operador. | AC06: pendiente. Requiere decisión del owner sobre capability, MFA reciente, auditoría, reason codes y clave de idempotencia atribuida al operador antes de habilitar comandos. |
| ISS-FR07 | Definir el producto POS. | AC07: pendiente de decisión de producto sobre payload/claims, significado del comprobante, mapping, consentimiento y vínculo con el origen. No se genera una definición canónica por inferencia. |
| ISS-FR08 | Completar el recorrido de emisión. | AC08: fuente→offer→wallet→credencial verificable y reconciliación polling con contrato/eventos acordados con Team 4; pendiente de integración y evidencia end-to-end. |

## Seguridad y límites operativos

La lectura de operator listings usa identidad operator y scope tenant; los permisos se vuelven a comprobar en Management tras el BFF. Las respuestas llevan `no-store`. La paginación es por offset y puede cambiar entre consultas cuando hay nuevas emisiones; un cursor de snapshot requiere acuerdo si el volumen/consistencia del piloto lo necesita. La aplicación no debe mostrar ni conservar el bearer token en el browser.

La validación de estos listados no demuestra conformance del perfil draft, disponibilidad productiva, wallet interoperable ni integración POS. Persistencia modificada requiere `npm run test:postgres` más los gates comunes.

## Trazabilidad

HK-001–005, HK-010–013, HK-020–025, HK-030–036 y HK-050–056 del [backlog Team 5](../../02-requirements/backlogs/team-5-hukid.md); decisiones abiertas en [ADR-0031](../../decisions/ADR-0031.md); autoridad actual y capability reservado en [contrato del dashboard](../../03-design/console-dashboard-contract.md); límites de equipos y estado consolidado en [roadmap HukID](../../05-delivery/hukid-roadmap.md).
