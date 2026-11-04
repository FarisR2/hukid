# Requisitos no funcionales

## Objetivos medibles

Son objetivos de diseño documentados, no SLA contractual ni resultados medidos. Los perfiles de carga deben fijarse con el piloto.

| Ámbito | Objetivo | Fuente |
| --- | --- | --- |
| Events público | p95 < 500 ms en región objetivo; Content Read API 99.9% mensual. | Arquitectura Events |
| Events registro | p95 creación < 1.5 s; cero sobrecupo. | Arquitectura Events |
| Events check-in | p95 online < 700 ms; una entrada efectiva por ticket/evento/scope. | Arquitectura Events, OO-010/011 |
| Events carga | Probar registro/check-in a 3× el pico esperado. | Architecture Spine AD-10 |
| HukID Integration API | 99.9% mensual; creación de oferta p95 < 500 ms sin dependencia externa. | Seguridad HukID §9 |
| HukID Credential Endpoint | p95 < 1 s para emisión inmediata, excluyendo UX/red. | Seguridad HukID §9 |
| HukID metadata/status | Disponibilidad objetivo 99.95% con CDN. | Seguridad HukID §9 |
| HukID recuperación | RPO PostgreSQL ≤ 5 min; RTO ≤ 60 min. No incluye pérdida regional irrecuperable del KMS sin diseño DR adicional. | Seguridad HukID §9 |
| HukID revocación | Objetivo base propagación ≤ 5 min; freshness/policy se fija por tipo. | Seguridad HukID §9 |

## Atributos transversales

- Seguridad: aislamiento de instituciones, permisos mínimos y autorización negativa por recurso.
- Privacidad: datos mínimos, cifrado, no tokens/claims sensibles en logs y retención por propósito.
- Confiabilidad: comandos idempotentes, concurrencia controlada, reintentos y reconciliación durable.
- Consistencia: publicaciones y definiciones inmutables; status deseado separado del publicado.
- Accesibilidad: Events exige WCAG AA en journeys críticos y QA móvil/escritorio; wallet exige consentimiento comprensible y estados accesibles.
- Mantenibilidad: ownership de módulos/datos, contratos versionados y migraciones compatibles.
- Observabilidad: métricas, trazas y auditoría sin payload sensible; alertas de colas, KMS y status.
- Interoperabilidad: demostrar compatibilidad con el perfil HukID; no anunciar soporte universal ni conformidad por usar nombres de estándares.

No confundir freshness de revocación de ticket Events (<15 s online) con propagación de status de credencial HukID. Son mecanismos y objetivos diferentes.

Fuentes: [arquitectura Events](../03-design/events-architecture.md), [spine](../03-design/events-architecture-spine.md), [seguridad HukID](../04-engineering/hukid-security-and-operations.md), [perfil](../03-design/hukid-profile.md). Validación: [estrategia de pruebas](../04-engineering/testing-strategy.md).
