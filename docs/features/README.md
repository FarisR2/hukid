# Features de la consola HukID

Ámbito confirmado: consola administrativa del Team 5. AUTH-T01–T10 están implementadas y probadas para laboratorio. USR-T01 materializa [contrato/políticas](../03-design/console-members-contract.md) y reglas puras; USR-T02 añade [persistencia ampliada/RLS/transacciones](../03-design/console-members-persistence.md). USR-T03 añade [lecturas API/BFF autorizadas](../03-design/console-members-directory.md); USR-T04 añade [invitaciones/entrega sintética](../03-design/console-invitation-delivery.md); USR-T05 añade [aceptación/reingreso](../03-design/console-invitation-acceptance.md); USR-T06 añade [cambios de membresías con ETag](../03-design/console-members-lifecycle.md); USR-T07 conecta [revalidación/reconciliación de contexto](../03-design/console-authorization-revalidation.md); USR-T08 conecta [UI administrativa y aceptación](../03-design/console-members-interface.md); [gate USR-T09](../05-delivery/members-gate.md) completado en laboratorio. No cambian el login de Events ni el bloqueo local de la wallet.

Consola significa **panel web de administración**, con pantallas en el navegador. No significa ejecutar la operación del usuario final en una terminal. La [ruta global vigente](../05-delivery/implementation-plan.md) distingue estas features del [roadmap de emisión/verificación HukID](../05-delivery/hukid-roadmap.md). AUTH-T10 cierra autenticación de laboratorio; no entrega por sí sola miembros, dashboard ni verificación de documentos.

| Feature | Resultado | Documentos |
| --- | --- | --- |
| FEAT-001-authentication | Operador autenticado con OIDC/MFA, sesión segura y contexto tenant autorizado. | [Spec](FEAT-001-authentication/spec.md) · [Plan](FEAT-001-authentication/plan.md) · [Tareas](FEAT-001-authentication/tasks.md) |
| FEAT-002-user-management | Administrar miembros, invitaciones, roles y acceso dentro de un tenant. | [Spec](FEAT-002-user-management/spec.md) · [Plan](FEAT-002-user-management/plan.md) · [Tareas](FEAT-002-user-management/tasks.md) |
| FEAT-003-dashboard | Resumen operativo autorizado con datos reales y disponibilidad explícita. | [Spec](FEAT-003-dashboard/spec.md) · [Plan](FEAT-003-dashboard/plan.md) · [Tareas](FEAT-003-dashboard/tasks.md) |

## Secuencia y primer incremento

1. AUTH-T01–T05 entregan entorno, contratos, [PostgreSQL](../03-design/console-persistence.md), [login/callback](../03-design/console-oidc-login.md) y [middleware operator y /me](../03-design/console-operator-context.md) de laboratorio. AUTH-T06 añade [ciclo de sesión, refresh/logout y purga](../03-design/console-session-lifecycle.md). AUTH-T07 añade [MFA/step-up y cambio de tenant](../03-design/console-reauthentication.md). AUTH-T08 conecta [interfaz y navegador](../03-design/console-auth-interface.md). AUTH-T09 añade [auditoría/redacción integrada](../03-design/console-auth-audit.md). AUTH-T10 aporta [runbook y gate de laboratorio](../05-delivery/authentication-gate.md). USR-T01 concreta contratos y USR-T02 la persistencia de miembros; USR-T03 añade lecturas y USR-T04 invitaciones/entrega; USR-T05 añade aceptación/reingreso; USR-T06 añade PATCH de membresías; USR-T07 añade revalidación de contexto; USR-T08 añade UI; USR-T09 cierra el gate U4 de laboratorio; DASH-T01 entrega [contrato/reglas/fixtures](../03-design/console-dashboard-contract.md); siguiente DASH-T02.
2. AUTH-T03–T08 permiten iniciar sesión con un operador/tenant sintéticos provisionados para desarrollo.
3. USR-T01–T08 reemplazan el fixture por administración real de miembros; no habilitar autoalta de tenants.
4. DASH-T01–T04 entregan el shell y resumen del tenant. DASH-T05 conecta métricas de otros módulos cuando existan.
5. Ejecutar los gates de cada paquete antes de declarar entrega.

AUTH-T10 cierra el gate de laboratorio de FEAT-001; USR-T01 fija contratos y políticas según [ADR-0011](../decisions/ADR-0011.md) y USR-T02 añade persistencia según [ADR-0012](../decisions/ADR-0012.md). USR-T03 añade lectura según [ADR-0013](../decisions/ADR-0013.md). USR-T04 añade invitaciones/entrega según [ADR-0014](../decisions/ADR-0014.md). USR-T05 añade aceptación/reingreso según [ADR-0015](../decisions/ADR-0015.md). USR-T06 añade [PATCH de membresías](../03-design/console-members-lifecycle.md) según [ADR-0016](../decisions/ADR-0016.md). USR-T07 añade revalidación de contexto según [ADR-0017](../decisions/ADR-0017.md). USR-T08 añade UI según [ADR-0018](../decisions/ADR-0018.md). USR-T09 cierra el [gate U4 de laboratorio](../05-delivery/members-gate.md). DASH-T01 entrega contrato/reglas/fixtures según [ADR-0019](../decisions/ADR-0019.md); el siguiente incremento es DASH-T02. La ruta de entrega del panel conserva AUTH→USR→DASH y las dependencias específicas de cada tasks.md. El posible adelanto de un flujo de negocio HK es una propuesta de priorización que requiere alcance acordado; esta actualización no modifica el orden vigente.

La autenticación usa un registro mínimo de identidad/membership desde FEAT-001. FEAT-002 amplía ese registro; no existe una dependencia circular que obligue a construir un CRUD de usuarios antes del login.

## Reglas de lectura

- spec.md establece comportamiento, límites, requisitos y aceptación.
- plan.md propone componentes, contratos, migraciones, hitos y verificación.
- tasks.md contiene trabajo pendiente con dependencias, artefactos y comprobaciones. Las casillas se marcan sólo con implementación y evidencia.
- El [ADR-0002](../decisions/ADR-0002.md) registra propuestas nuevas de consola y decisiones técnicas por validar. Los endpoints propuestos no son contratos ejecutables existentes.
- Las referencias originales HK-001/005 y la fase 1 fundamentan estas features. Invitaciones detalladas, sesión BFF y dashboard son descomposición/diseño nuevo; no se presentan como historias originales ya especificadas.
- Rigen la [DoD](../05-delivery/definition-of-done.md), el [perfil HukID](../03-design/hukid-profile.md) y los [pendientes de artefactos](../05-delivery/documentation-gaps.md).

## Dependencias y alcance

Backend Go y PostgreSQL para Platform. AUTH-T01 materializa bootstrap Go y entry point React/TypeScript con Vite en `src/platform` y `src/console`, estructura acordada con el owner; ver [desarrollo local](../04-engineering/local-development.md). AUTH-T02 materializa contratos/políticas y fixture IdP; AUTH-T03–T05 conectan DB, login/callback y lecturas BFF/Management de laboratorio. AUTH-T08 conecta las pantallas de autenticación y USR-T08 las de miembros; USR-T09 completa su gate de laboratorio. Dashboard tiene baseline contractual DASH-T01; lecturas, API/BFF e interfaz siguen pendientes.

No se requiere KMS de emisión, OID4VCI, una wallet instalada ni datos Events para el primer login y gestión de miembros. Sí se requiere IdP de pruebas, contratos de operador, persistencia tenant-scoped y auditoría. No bloquear estos paquetes esperando todos los artefactos del producto completo.

Fuera de estos paquetes: clientes de integración/grants de emisión, keys issuer, definitions, emisión VC, presentación y gestión global cross-tenant. El dashboard puede leer sus proyecciones cuando estén implementadas, sin construir esos dominios aquí.
