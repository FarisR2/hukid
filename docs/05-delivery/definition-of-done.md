# Definition of Done

## Historia o cambio

- Actor, owner, alcance y criterios de aceptación identificados.
- Contrato de API/evento actualizado y versionado antes de integrar; ejemplos y errores validados.
- Reglas de estado, autorización y aislamiento cubiertas con pruebas negativas.
- Idempotencia y concurrencia demostradas para efectos reintentables; consumidores con inbox/replay cuando aplique.
- Migraciones propias forward-only compatibles, constraints/RLS y prueba desde versión previa.
- Métricas/trazas/auditoría útiles, sin PII/tokens/claims sensibles.
- Journey y estados alternativos verificados, incluida accesibilidad cuando haya UI.
- Runbook, dashboard y cambios documentales correspondientes.
- Evidencia de checks ejecutados y limitaciones; un documento de estrategia no acredita tests aprobados.

## Tipo de credencial HukID

- Purpose, amenaza y issuer/subject/holder definidos.
- Claims con tipo, sensibilidad y propósito; mapping y ejemplos positivos/negativos.
- Definition/schema/context/configuration versionados e inmutables al publicar.
- Formato, algoritmo, holder binding, status purposes y freshness explícitos.
- Display, consentimiento y accesibilidad; revelar VC completa explicado en v0.
- Retención/evidencia y recovery/reissue definidos para ese tipo.
- Trust policy y caso de uso del verifier.
- Tests de emisión, errores y presentación cuando esté en alcance; métricas/runbook.

## Integración Events→HukID

- Certificado elegible y consentimiento comprobados server-side.
- Adaptador Team 4 con OAuth/grants, mapping de datos y source reference autorizados.
- Reintentos y concurrencia no duplican request/credencial.
- Oferta entregada al destinatario bajo policy; no confundir enlace con credencial.
- Wallet verifica antes de persistir; errores/expiración/cancelación visibles.
- Estado local reconciliado por polling v0; secretos/payloads excluidos de logs.
- Reglas de revocación/reemplazo entre productos acordadas y probadas si entran en el piloto.

## Release y producción

Restauración y continuidad ensayadas; SLO/carga medidos; rotación y secretos revisados; alertas/runbooks/on-call disponibles; políticas de retención ratificadas. El perfil HukID sólo cambia de draft a publicado tras vectores/suites y evidencia de interoperabilidad. Pérdida regional de KMS requiere ADR y ejercicio DR separado antes de prometer cobertura.

Fuentes: [DoD común Events](events-team-plan.md), [credential type HukID](hukid-roadmap.md), [seguridad/operación](../04-engineering/hukid-security-and-operations.md), [conformance gate](../03-design/hukid-profile.md#12-conformance-gate).
