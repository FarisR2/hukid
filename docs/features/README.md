# Features de la consola HukID

Ámbito confirmado: consola administrativa del Team 5. Estos paquetes preparan implementación; no representan funcionalidades ya construidas. No cambian el login de Events ni el bloqueo local de la wallet.

| Feature | Resultado | Documentos |
| --- | --- | --- |
| FEAT-001-authentication | Operador autenticado con OIDC/MFA, sesión segura y contexto tenant autorizado. | [Spec](FEAT-001-authentication/spec.md) · [Plan](FEAT-001-authentication/plan.md) · [Tareas](FEAT-001-authentication/tasks.md) |
| FEAT-002-user-management | Administrar miembros, invitaciones, roles y acceso dentro de un tenant. | [Spec](FEAT-002-user-management/spec.md) · [Plan](FEAT-002-user-management/plan.md) · [Tareas](FEAT-002-user-management/tasks.md) |
| FEAT-003-dashboard | Resumen operativo autorizado con datos reales y disponibilidad explícita. | [Spec](FEAT-003-dashboard/spec.md) · [Plan](FEAT-003-dashboard/plan.md) · [Tareas](FEAT-003-dashboard/tasks.md) |

## Secuencia y primer incremento

1. AUTH-T01/T02 entregan entorno y baseline contractual de laboratorio con IdP sintético; ver [contrato y límites](../03-design/console-auth-contract.md). El siguiente trabajo es AUTH-T03 (migraciones mínimas).
2. AUTH-T03–T08 permiten iniciar sesión con un operador/tenant sintéticos provisionados para desarrollo.
3. USR-T01–T08 reemplazan el fixture por administración real de miembros; no habilitar autoalta de tenants.
4. DASH-T01–T04 entregan el shell y resumen del tenant. DASH-T05 conecta métricas de otros módulos cuando existan.
5. Ejecutar los gates de cada paquete antes de declarar entrega.

La autenticación usa un registro mínimo de identidad/membership desde FEAT-001. FEAT-002 amplía ese registro; no existe una dependencia circular que obligue a construir un CRUD de usuarios antes del login.

## Reglas de lectura

- spec.md establece comportamiento, límites, requisitos y aceptación.
- plan.md propone componentes, contratos, migraciones, hitos y verificación.
- tasks.md contiene trabajo pendiente con dependencias, artefactos y comprobaciones. Las casillas se marcan sólo con implementación y evidencia.
- El [ADR-0002](../decisions/ADR-0002.md) registra propuestas nuevas de consola y decisiones técnicas por validar. Los endpoints propuestos no son contratos ejecutables existentes.
- Las referencias originales HK-001/005 y la fase 1 fundamentan estas features. Invitaciones detalladas, sesión BFF y dashboard son descomposición/diseño nuevo; no se presentan como historias originales ya especificadas.
- Rigen la [DoD](../05-delivery/definition-of-done.md), el [perfil HukID](../03-design/hukid-profile.md) y los [pendientes de artefactos](../05-delivery/documentation-gaps.md).

## Dependencias y alcance

Backend Go y PostgreSQL para Platform. AUTH-T01 materializa bootstrap Go y entry point React/TypeScript con Vite en `src/platform` y `src/console`, estructura acordada con el owner; ver [desarrollo local](../04-engineering/local-development.md). AUTH-T02 materializa contratos/políticas y fixture IdP de laboratorio, con handlers BFF/Management aún pendientes. No hay login ni pantalla funcional todavía.

No se requiere KMS de emisión, OID4VCI, una wallet instalada ni datos Events para el primer login y gestión de miembros. Sí se requiere IdP de pruebas, contratos de operador, persistencia tenant-scoped y auditoría. No bloquear estos paquetes esperando todos los artefactos del producto completo.

Fuera de estos paquetes: clientes de integración/grants de emisión, keys issuer, definitions, emisión VC, presentación y gestión global cross-tenant. El dashboard puede leer sus proyecciones cuando estén implementadas, sin construir esos dominios aquí.
