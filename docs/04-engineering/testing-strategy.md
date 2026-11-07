# Estrategia de pruebas

Estado al 2026-11-05: AUTH-T01–T10 tienen comprobaciones ejecutables de autenticación en laboratorio; el alcance y la evidencia por incremento están en [tareas FEAT-001](../features/FEAT-001-authentication/tasks.md). AUTH-T09 prueba [auditoría/redacción integrada](../03-design/console-auth-audit.md); AUTH-T10 añade [runbook, reversión ensayada y gate de laboratorio](../05-delivery/authentication-gate.md). Las pruebas de credenciales, wallet, status y verifier que se describen más abajo son requisitos pendientes, no suites ya construidas.

La autenticación tiene pruebas de contratos/ejemplos y matriz, JWT y políticas, PostgreSQL/RLS/migraciones, login/callback HTTP, middleware operator, sesión/refresh/logout, step-up/contexto y navegador React. La evidencia MFA sigue siendo sintética y no selecciona proveedor ni demuestra factores reales. Alcance y matriz en el [contrato de consola](../03-design/console-auth-contract.md#pruebas-y-cobertura-actual).

USR-T01 añade [contrato de miembros](../03-design/console-members-contract.md): OpenAPI con doce operaciones contract-only, schemas/ejemplos positivos y negativos en test:auth y unitarias Go de política/email/grants/revisión/último administrador en check:platform. Ese incremento no prueba endpoints, canje email real ni concurrencia DB de esas mutaciones; las tareas posteriores los incorporan progresivamente. El contrato no cambia la matriz de AUTH ni reemplaza su gate.

USR-T02 añade seis escenarios Go de [persistencia de miembros](../03-design/console-members-persistence.md) en test:postgres: upgrade 0006→0007 con datos preservados, RLS/credenciales/constraints/pool reuse, rollback de invitación ante fallo de evidencia, archivo y fingerprints/retención, carrera de últimos administradores bajo lock, UUID canónico/cancelación de waiter. Son pruebas de almacenamiento y protocolo de transacción; las mutaciones USR todavía no están implementadas. USR-T03 añade [lecturas autorizadas](../03-design/console-members-directory.md): unitarias de filtros/matriz/cursor, dos escenarios PostgreSQL de aislamiento/permisos/expiración efectiva y pruebas HTTP Management/BFF dentro del escenario AUTH real. La suite AUTH completa se conserva.

USR-T04 añade [invitaciones y entrega](../03-design/console-invitation-delivery.md): seis escenarios PostgreSQL de comandos/replay, autorización viva, locks/concurrencia, rollback de evidencia/reemplazo, migración 0007→0008/RLS de recibos, fallos/reintentos/caída/purga y expiración del MFA durante la escritura. La suite HTTP real añade creación/revocación en Management/BFF, input estricto, CSRF/Origin, ETag y replay entre superficies; las unitarias OIDC/configuración cubren deadlines y separación de claves. El proveedor sólo simula aceptación con recibos duraderos, sin correo real, canje ni UI.

| Comando existente | Qué comprueba | Límite |
| --- | --- | --- |
| `npm run check` | Formato/vet/pruebas Go, TypeScript, contratos/IdP y documentación. | No incluye PostgreSQL ni navegador. |
| `npm run test:postgres` | Suite Go con PostgreSQL 18.6 propio: foundation, migraciones, RLS/roles, HTTP con API/IdP y ciclo de sesión/comandos. | Bases descartables; no carga ni restore. |
| `npm run build` | Compilación de Platform y distribución React. | Compilar no prueba una interacción. |
| `npm run smoke` | Liveness y auth deshabilitada/configuración rechazada, HTML y JS compilados. | Requiere build; es HTTP, no prueba visual. |
| `npm run test:browser` | Chromium→Vite→Go→OIDC/PostgreSQL de laboratorio; login, selector, /me, refresh, step-up, logout, fallos y contexto entre pestañas/historial. | Requiere build, Python/Playwright y Chromium; no MFA real ni conformance de credenciales. |

Instrucciones y condiciones en [desarrollo local](local-development.md) y [AUTH-T08](../03-design/console-auth-interface.md). Una ejecución de documentación no vuelve a acreditar estas suites: registrar siempre cuáles se ejecutaron para el cambio concreto.

## Matriz objetivo del producto

| Capa / riesgo | Pruebas necesarias |
| --- | --- |
| Dominio | Estados permitidos/prohibidos, eligibility/versiones, expiración, grant/policy y definición inmutable. |
| Contratos | OpenAPI/AsyncAPI/JSON Schema validables, ejemplos, compatibilidad y tests productor-consumidor. |
| Datos | Migración vacía/previa, constraints, RLS con dos tenants, pool reuse, legal hold y purga. |
| Concurrencia | Cupo/waitlist, ticket/check-in, canje de oferta, request duplicado y firma con CAS/lease. |
| Fallos | Timeout después de commit, caída entre DB/KMS/object store, replay/outbox, deferred y reconciliación. |
| Identidad | Roles/scopes, recursos ajenos, clases operator/integration/oid4vci y audiencias incorrectas. |
| Criptografía HukID | Payload VCDM directo, header/alg/kid, firma alterada, proof/nonce y binding cnf.jkt. |
| Status | Suspender/reactivar/revocar, purpose/índice/firma/freshness, desired vs published y rotación. |
| Wallet | Dispositivos Flutter, key storage, QR/deep link, consentimiento, error/expiración y persistencia cifrada. |
| Presentación | Request autenticado, respuesta cifrada, audience/state/nonce/replay y verifier externo compatible. |
| UX/accesibilidad | Teclado/foco/lector, cámara/conectividad, móvil/escritorio y estados loading/empty/error/forbidden. |
| Rendimiento | Perfiles del piloto, límites DB/KMS/colas, p95 y ausencia de duplicados/sobrecupo bajo carga. |
| Continuidad | Restore DB+objetos+status+metadata, reconciliación y ofertas expiradas que no reviven. |
| Privacidad | Redacción de logs/trazas/DLQ, consentimiento y ausencia de claims/tokens en telemetría. |

## Flujos de aceptación

1. Publicar evento y materializar la misma release en consumidores.
2. Registrar concurrentemente, confirmar/waitlist, emitir QR y rechazar revocado en check-in.
3. Generar PDF elegible, solicitar HukID con consentimiento y reintentar sin duplicado.
4. Abrir oferta, autorizar destinatario según policy, emitir/guardar wallet y reconciliar mediante polling v0.
5. Cuando entre en alcance: presentar a verifier compatible, comprobar status y rechazar replay/otra clave holder.

## Gate HukID

Mantener v0.1-draft hasta publicar vectores exactos positivos/negativos y automatizar el [conformance gate](../03-design/hukid-profile.md#12-conformance-gate). No afirmar interoperabilidad universal por usar OpenID/VCDM. Probar primero wallet/verifier de referencia y documentar implementaciones externas efectivamente verificadas.

## Criterio de evidencia

Registrar escenario, versión, ambiente, carga, resultados y limitaciones. Medir los [objetivos no funcionales](../02-requirements/non-functional-requirements.md); no convertirlos en SLA sin pruebas. Aplicar la [Definition of Done](../05-delivery/definition-of-done.md).

En documentación, verificar enlaces/anclas locales, bloques y estructura con `npm run check:docs` y revisión de diff. Declarar únicamente pruebas de componentes existentes y efectivamente ejecutadas.

## Gate acumulado de autenticación

npm run test:auth:gate ejecuta secuencialmente los cinco comandos de la tabla, con build previo al smoke/navegador, y genera un informe de metadatos sin secretos. El ensayo AUTH-T10 dentro de test:postgres prueba retirada/invalidez/reactivación con recursos propios. [Matriz A4 y límites](../05-delivery/authentication-gate.md). El workflow versionado usa ese mismo comando; CI remoto no se declara aprobado por validación local.

## Interfaz DASH-T04

Chromium añade dashboard sobre BFF/DB reales: conteos, roles propios, teclado, reflujo 320–1440 px/200%, modo oscuro, rango UTC, cambio de tenant y permisos, 401/403, reintento y descarte de respuestas tardías. Degradación de secciones y paginación/cursor inválido de UI usan respuestas interceptadas explícitas; el cursor autenticado real conserva pruebas DASH-T03. La [interfaz](../03-design/console-dashboard-interface.md) y las [tareas](../features/FEAT-003-dashboard/tasks.md) distinguen esta evidencia del trabajo DASH-T07/T08 pendiente.

## Matriz base DASH-T06

La [matriz negativa](../features/FEAT-003-dashboard/tasks.md#matriz-negativa-dash-t06--base-de-laboratorio) reúne unitarias, contratos, PostgreSQL/HTTP y regresión Chromium. Amplía reautorización entre páginas, replay de cursor entre actores/tenants, TTL fijo 899/900 s, manipulación de nonce/ciphertext/tag, fallos SQL por ambas superficies y límites nanosegundo sobre la fuente microsegundo. Conserva la separación entre pruebas contractuales de fuentes futuras y adaptadores reales; desired/published sigue siendo un oráculo sintético hasta DASH-T05. DASH-T07 conserva medición de consultas y revisión de accesibilidad; DASH-T08 documenta operación/DoD.

## E2E y medición DASH-T07

El [informe DASH-T07](../05-delivery/reviews/dashboard-t07-laboratory.md) registra paginación Chromium con cursor autenticado real, revalidación tenant/rol, recorrido Tab y regresión de foco al desmontar Siguiente página. El canary email inválido y las claves efímeras se contrastan contra logs de aplicación/auditoría sin volcar estos destinos. test:postgres añade tracer pgx exclusivo de prueba con 2×10.000 eventos y 30 muestras seriales; los informes locales contienen sólo etiquetas y tiempos. No hay datos operativos, SLA nuevo ni carga concurrente del piloto. DASH-T08 conserva rollout/runbook y DoD base.
