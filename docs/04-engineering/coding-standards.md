# Estándares de implementación

Estas reglas consolidan restricciones de las fuentes. Las versiones y comandos elegidos para el bootstrap AUTH-T01 se registran en [desarrollo local](local-development.md); Flutter y librerías de autenticación/persistencia siguen pendientes de selección.

## Límites y dependencias

- Cada owner mantiene módulos, datos, migraciones y contratos de su producto.
- HukID usa adaptadores de entrada, aplicación, dominio y puertos de salida; las dependencias apuntan hacia el dominio.
- DTO OpenID, modelos PostgreSQL y APIs KMS no entran al dominio.
- El núcleo HukID no tiene condicionales por POS, SIS o Events: diferencias mediante definition, mapping declarativo y policy.
- No ejecutar código arbitrario de clientes ni permitir key/schema/context libres que eludan configuración publicada.
- API y worker se despliegan con compatibilidad adyacente; extraer microservicios sólo con justificación.

## Contratos y datos

- Implementar contratos validados antes de conectar productores/consumidores.
- Mantener convenciones propias de cada API; traducir explícitamente en el adaptador Events→HukID.
- Inyectar reloj/entropía y puertos de infraestructura para probar expiración, reintentos y fallos.
- Efectos reintentables usan idempotencia; edición concurrente usa ETag/CAS según contrato.
- Persistir cambio, auditoría y outbox transaccionalmente donde corresponda.
- Aplicar migraciones forward-only y expand/contract; no reescribir snapshots publicados.
- Preservar artefacto de emisión confirmado ante reintentos; nunca reconstruir una segunda credencial como si fuera la primera.

## Organización propuesta por las fuentes

Backend Go: cmd/api, cmd/worker e internal por tenancy, issuers, integrations, definitions, issuance, credentials, status y audit, con adaptadores separados.

Wallet Flutter: app, identity, issuance, credentials, verification, presentation, recovery, security y shared. La ubicación final bajo src se definirá al iniciar implementación; todavía no existen esos módulos.

## Calidad de cambios

Cambios de comportamiento actualizan historia/contrato y pruebas relevantes. Cambios incompatibles crean versión nueva con convivencia. Feature flags por tenant tienen owner, expiración y default seguro. No registrar payload sensible ni crear ejemplos con secretos reales.

Elegir toolchain, dependencias y librerías en la fase 0 y registrar el resultado en ADR. Documentar comandos reales cuando existan manifiestos, sin presentar propuestas como checks ejecutados.

Fuentes: [arquitectura HukID](../03-design/hukid-architecture.md), [módulos Go/Flutter](../03-design/hukid-wallet-backend.md), [roadmap](../05-delivery/hukid-roadmap.md), [migraciones](../03-design/contracts/events-database-boundaries.md).
