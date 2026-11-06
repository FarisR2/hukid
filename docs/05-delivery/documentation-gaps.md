# Artefactos pendientes y diferencias documentales

Fecha: 2026-11-03. Inventario del paquete recibido; no significa que los artefactos no existan en otro repositorio. Los diez Markdown HukID incorporados sustituyen referencias personales para arquitectura, perfil y modelo conceptual, pero no adjuntan los archivos ejecutables citados.

Estado de ejecución actualizado al 2026-11-06: AUTH-T01–T10 implementadas en laboratorio; USR-T01 materializa [contrato/política de miembros](../03-design/console-members-contract.md) y reglas puras; USR-T02 añade [persistencia ampliada/RLS/locks/evidencia](../03-design/console-members-persistence.md), USR-T03 añade lecturas autorizadas y USR-T04 [invitaciones con entrega sintética](../03-design/console-invitation-delivery.md). USR-T05–T08 añaden aceptación, cambios de acceso, reconciliación y [UI administrativa](../03-design/console-members-interface.md). La [ruta vigente](implementation-plan.md) continúa con DASH-T04, tras contrato DASH-T01, lectura DASH-T02 y API/BFF DASH-T03 y el [gate U4 de laboratorio](members-gate.md) y distingue el panel web del negocio de credenciales. Este inventario conserva procedencia y evidencia histórica; un artefacto nuevo de consola no sustituye al artefacto histórico ausente de emisión/wallet/verificación.

## Archivos referenciados que no se adjuntaron

| Artefacto de origen | Referencias conservadas | Acción necesaria |
| --- | --- | --- |
| `/Users/juancx/Documents/CX-Developments/SELF/hukid/docs/planting/api/openapi.yaml` | [team-5-hukid.md](../02-requirements/backlogs/team-5-hukid.md) | Incorporar la fuente original o materializar y validar el artefacto; no fabricar evidencia de ejecución. |
| `diagrams/hukid-platform.architecture.html` | [hukid-architecture.md](../03-design/hukid-architecture.md) | Incorporar la fuente original o materializar y validar el artefacto; no fabricar evidencia de ejecución. |
| `diagrams/credential-lifecycle.workflow.html` | [hukid-ux-flows.md](../03-design/hukid-ux-flows.md) | Incorporar la fuente original o materializar y validar el artefacto; no fabricar evidencia de ejecución. |
| `diagrams/pos-oid4vci.sequence.html` | [hukid-ux-flows.md](../03-design/hukid-ux-flows.md) | Incorporar la fuente original o materializar y validar el artefacto; no fabricar evidencia de ejecución. |
| `examples/cpe-credential.json` | [hukid-api-contracts.md](../03-design/hukid-api-contracts.md) | Incorporar la fuente original o materializar y validar el artefacto; no fabricar evidencia de ejecución. |
| `examples/oid4vp-request-payload.json` | [hukid-api-contracts.md](../03-design/hukid-api-contracts.md), [hukid-profile.md](../03-design/hukid-profile.md) | Incorporar la fuente original o materializar y validar el artefacto; no fabricar evidencia de ejecución. |
| `examples/vp-jwt-structure.json` | [hukid-api-contracts.md](../03-design/hukid-api-contracts.md) | Incorporar la fuente original o materializar y validar el artefacto; no fabricar evidencia de ejecución. |
| `database/001_initial.sql` | [hukid-data-model.md](../03-design/hukid-data-model.md) | Incorporar la fuente original o materializar y validar el artefacto; no fabricar evidencia de ejecución. |
| `database/002_integrity_rls_and_concurrency.sql` | [hukid-data-model.md](../03-design/hukid-data-model.md) | Incorporar la fuente original o materializar y validar el artefacto; no fabricar evidencia de ejecución. |

El gate histórico menciona un OpenAPI baseline de 30 paths que no está adjunto. Tampoco se incluyen schemas AsyncAPI/JSON Schema compilables, vectores criptográficos, suites ni resultados de pruebas. La estructura src no los sustituye.

La cabecera de procedencia del Architecture Spine conserva rutas a architecture/events-platform-2026-11-02 y briefs de su ubicación original; esos documentos externos tampoco están en este paquete. Son procedencia histórica, no enlaces activos ni dependencias que deban resolverse desde la nueva carpeta.

## Detalles ahora disponibles

USR-T04 conecta [invitaciones y entrega cifrada/idempotente](../03-design/console-invitation-delivery.md) según [ADR-0014](../decisions/ADR-0014.md). El worker explícito por tenant usa un proveedor falso con recibos duraderos sin payload (migración 0008), separación de claves, replay reautorizado y purga bajo lock. No envía correo real ni implementa aceptación/email verificado, scheduler/SLA, rotación multiversión, rate limiting específico, carga/restore o UI. La retención institucional de evidencia/recibos y operación productiva siguen pendientes; siguiente USR-T05.

USR-T03 añade [lecturas autorizadas de miembros e invitaciones](../03-design/console-members-directory.md), con cuatro GET Management/BFF, filtros/cursor y credencial separada. USR-T04 añade cuatro mutaciones de invitación y entrega sintética; cuatro mutaciones de aceptación/memberships, evidencia email y UI siguen pendientes. La máscara fija del destinatario no distingue correos y no se descifra PII; deben mantenerse explícitos ese límite y la falta de rate limiting propio, carga/restore y operación productiva. Ver [ADR-0013](../decisions/ADR-0013.md) y tareas FEAT-002.

- [Perfil](../03-design/hukid-profile.md): VC/VP-JWT, ES256, cnf.jkt, token classes, low-risk offer TTL ≤5 min, local-only/issuer-reauth y presentación directa.
- [APIs](../03-design/hukid-api-contracts.md): request/response ilustrativos, errores, status operations y candidatos webhook.
- [Modelo](../03-design/hukid-data-model.md): schemas lógicos, ownership, constraints, cifrado y reglas de migración; DDL sigue ausente.
- [Wallet/backend](../03-design/hukid-wallet-backend.md): autoridad Go/Flutter y polling obligatorio para reconciliación v0.
- [Operación](../04-engineering/hukid-security-and-operations.md): objetivos 99.9/99.95%, p95, RPO/RTO y limitación DR-KMS; son objetivos, no mediciones.

## Diferencias de alcance y precedencia

| Tema | Lectura para implementación |
| --- | --- |
| Microservicios vs backend modular | Events tiene límites por carga/equipo; HukID inicia API modular + worker. Ver ADR-0001. |
| Polling o webhook en fuentes Events | El documento específico wallet/backend fija polling v0; webhooks quedan posteriores. |
| Roadmap incluye OID4VP; MVP Events lo difiere | Distinguir contrato objetivo del perfil, roadmap independiente HukID y alcance del primer cliente Events. No anunciar compatibilidad no probada. |
| Recovery y sincronización como preguntas generales | El perfil v0 concreta local-only default e issuer-reauth; account-linked/sync fuera. Sigue abierto quién opera soporte y su assurance. |
| API Events snake_case y HukID camelCase | Preservar ambos contratos; traducción a cargo del adaptador. |
| organization_id global vs tenant_id HukID | Las guías Events no reemplazan el modelo canónico HukID; no renombrar tenant ni inferir equivalencia con issuer. |
| Secretos de oferta hasheados vs reintento que devuelve URI | El URI contiene referencia opaca y el diseño exige replay semántico. Verificar el OpenAPI/DDL original para materializar almacenamiento/reentrega sin persistir códigos recuperables. No resolverlo sólo copiando ejemplos. |
| Perfil v0.1-draft | Mantener draft hasta vectores y pruebas; fuentes que dicen v0 describen el mismo objetivo de perfil, no una publicación certificada. |
| Auditorías previas dicen cobertura completa | Son revisiones históricas de cobertura semántica, no garantía de que el paquete incluya OpenAPI/DDL ni código generado. |

## Pendientes concretos del piloto y ejecución

1. Recuperar OpenAPI, DDL y ejemplos originales y comprobar que coincidan con perfil/Markdown.
2. Definir credential definition de participación Events, claims mínimos, mapping, evidence/source refs y autorización del issuer.
3. Elegir canal de entrega, distribución/deep links de wallet y tratamiento de app no instalada; concretar autenticación del destinatario para tipos nominativos. El diseño exige protección, pero no documenta un flujo Events completo de identidad civil.
4. Especificar política y comandos del adaptador para revocar/reemplazar VC cuando cambie el certificado PDF. Hay operaciones en ambos productos; el enlace de negocio no está cerrado.
5. Fijar parámetros de polling/retry, freshness/status por tipo, retención/legal hold y alcance DR; ratificar la política institucional.
6. Elegir librerías/versiones, KMS/IdP/storage/hosting y perfiles de carga. El roadmap exige spikes y ADRs; no hay evidencia de selección final.
7. Confirmar trust framework, soporte/reemisión y caso de uso del verifier; probar compatibilidad de implementaciones externas antes de anunciarla.

Owners: Team 4 y Team 5 coordinan el contrato de integración; cada equipo materializa sus propios contratos/migraciones/pruebas. Producto y responsables institucionales ratifican alcance, confianza y retención.

## Foundation de consola documentada

Los paquetes [FEAT-001/002/003](../features/README.md) añaden especificación, plan y tareas para la consola HukID confirmada por el usuario. [ADR-0002](../decisions/ADR-0002.md) registra propuestas de BFF, operador, miembros y dashboard. AUTH-T01–T05 implementan bootstrap, contratos, PostgreSQL, login/callback y lecturas autorizadas /me de laboratorio; AUTH-T06/T07 añaden ciclo de sesión y step-up/contexto; AUTH-T08 conecta [UI y navegador](../03-design/console-auth-interface.md); miembros y dashboard siguen pendientes. Los apartados siguientes conservan evidencia por incremento, no sustituyen el estado actual de las tareas.

Para empezar AUTH-T01 no es necesario recuperar los ejemplos de emisión ni configurar KMS issuer. Para completar login integrado sí hacen falta IdP test compatible, políticas de sesión/MFA, contrato de operador y migraciones mínimas; miembros necesita policy de invitación/notificación. No marcar esos artefactos como disponibles por existir el plan.

Pendientes actuales del panel: implementación FEAT-002 miembros y FEAT-003 dashboard. AUTH-T10 cierra [operación/gate de laboratorio](authentication-gate.md), con límites productivos explícitos. Hay un harness E2E descartable y pantallas conectadas. El owner confirmó ingreso en un laboratorio manual temporal preparado fuera del código versionado; no es un entorno demo persistente reproducible desde checkout ni un despliegue productivo. No acredita emisión/verificación documental. Las secciones de incremento que siguen conservan el estado histórico de su fecha.

### Incremento USR-T02

[ADR-0012](../decisions/ADR-0012.md) y [modelo de persistencia](../03-design/console-members-persistence.md): migración 0007, lifecycle/archivo, invitaciones con hash/destinatario cifrado, envelope separado, deadlines/fingerprints y rol propio con RLS tenant. La primitiva de mutación comparte audit/outbox y lock tenant; seis escenarios de almacenamiento prueban upgrade, aislamiento/pool reuse/constraints, rollback, archivo/retención y carrera de último admin/cancelación. Los fixtures no son endpoints ni sustituyen reautorización de actor/MFA. El corte de revocación legacy usa la fecha de migración porque no había fecha histórica.

No se conecta credencial USR a la API ni hay lookup global del token, evidencia email, replay HTTP, entrega/worker, purga programada, fuente ownership issuer o UI. Los grants no vacíos continúan bloqueados sin fuente confiable; sólo se prepara su almacenamiento. Retención institucional, cargas, restore y producción mantienen sus gates. Siguiente USR-T03. El detalle USR-T01 que sigue conserva la evidencia previa a esta migración.

### Incremento USR-T01

[ADR-0011](../decisions/ADR-0011.md) adopta baseline OpenAPI/schemas y matriz existente, política email/TTL/reingreso y reglas Go puras. Todas las operaciones de miembros siguen contract-only; no hay DDL de invitaciones, worker ni UI. El perfil IdP actual aún no emite email verificado: T05 debe integrar esa evidencia con pruebas. T02 debe materializar lifecycle/historial, generación objetivo para reingreso, RLS/locks/idempotencia/retención/auditoría; T04 entrega sintética. No hay fuente de ownership issuer implementada por este incremento: los grants no vacíos requieren una fuente confiable y fallan cerrados sin ella. Retención institucional, proveedores/factores productivos, cargas y concurrencia real de mutaciones mantienen sus gates. Siguiente USR-T02.

### Incremento AUTH-T01

Se incorpora bootstrap local Go y entry point React/TypeScript con Vite, con estructura `src/platform` y `src/console` acordada con el owner. Versiones, instalación, comandos y límites están en [desarrollo local](../04-engineering/local-development.md). Sólo existe liveness; no hay pantalla, login, proxy BFF, Management, migraciones ni IdP ejecutable. La instalación de Go usada para validación es portable y local a `.cache`; otro checkout requiere instalar el toolchain indicado. Docker no está disponible en el entorno inspeccionado y no se requiere para este bootstrap; no se han ejecutado pruebas DB, OIDC, MFA, E2E ni conformidad. El fixture IdP aislado y las políticas quedan expresamente en AUTH-T02, sin reutilizar producción.

Fuentes: [gate histórico](reviews/correction-gate.md), [roadmap HukID](hukid-roadmap.md), [contratos](../03-design/api-contracts.md), [alcance](../01-product/scope.md).

### Incremento AUTH-T02

Existe un [contrato ejecutable nuevo de consola](../03-design/console-auth-contract.md), con OpenAPI, schemas, ejemplos, matriz, política test y fixture OIDC de biblioteca. Pruebas de contrato, tokens firmados y reglas temporales pasan en laboratorio. No recupera el OpenAPI histórico ni el DDL original; las referencias ausentes del inventario continúan ausentes.

La evidencia `pwd`/`otp`/ACR del fixture es sintética: no prueba factores reales, email verificado, selección de proveedor productivo ni interoperabilidad VC. El backend sólo añade validación de configuración; no implementa handlers de login, store, RLS, CSRF HTTP o validación Bearer Go. No se han ejecutado pruebas DB, cookies en navegador ni MFA real. El siguiente incremento AUTH-T03 debe crear migraciones nuevas y demostrar aislamiento con dos tenants; PostgreSQL/Docker siguen sin provisionar en el entorno inspeccionado. AUTH-T04 debe seleccionar y probar la librería OIDC del backend Go; no se deriva una implementación propia de JWT desde los tests Node.

Diferencia documentada: el resumen de seguridad decía «No almacenar códigos/tokens recuperables», mientras FEAT-001 exigía tokens y verifier cifrados recuperables por el BFF. La prohibición literal impediría PKCE y refresh. ADR-0003 precisa el alcance: nunca material en claro; hashes cuando basta verificar, y envelope cifrado/temporal cuando el protocolo exige recuperar. No se altera la política de ofertas ni se pretende recuperar secretos desde hashes.

### Incremento AUTH-T03

Existe [DDL nuevo de consola ejecutado y probado](../03-design/console-persistence.md) en PostgreSQL 18.6 portable/descartable, con pgx, migraciones forward-only/checksum, roles separados, RLS, contexto local transaccional y bootstrap sintético CLI. Se probó desde vacío y desde la primera migración con datos. Es una secuencia propia de consola: los DDL históricos ausentes del inventario no se consideran recuperados.

El harness no usa DB existente ni instala un servicio; crea y elimina únicamente sus bases/logins y detiene su servidor. Docker no se requiere. Hay una identidad sin membership para acceso pendiente; el alta de identidad tras autenticación verificada todavía debe conectarse en AUTH-T04. El driver/store no está conectado a rutas HTTP y no implementa todavía cifrado operativo de envelopes, callback, sesión/refresh BFF, CSRF ni middleware Bearer Go. Verificación productiva de factores, backup/restore, TLS, retención y cargas siguen pendientes. Los registros globales de identidad/sesión se protegen por roles/puertos; RLS de tenant no equivale a verificar un JWT. ADR-0004 registra la separación y sus límites.

### Incremento AUTH-T04

Existe [login/callback Go probado con IdP y PostgreSQL](../03-design/console-oidc-login.md), con librerías OIDC fijadas, consumo de transacción de un uso, PKCE/nonce/issuer/binding, tokens firmados, rate limiting local y cifrado AES-GCM. Una función restringida registra identidad por issuer/subject sin memberships, y la sesión inicial se guarda antes de emitir su cookie. [ADR-0005](../decisions/ADR-0005.md) documenta el límite entre creación inicial y AUTH-T06.

El estado posterior se registra en AUTH-T05 abajo. AUTH-T06 incorpora purga automática acotada; siguen pendientes rotación/recuperación de claves y rate limiting distribuido. Las claves/credenciales se suministran externamente; no se ha seleccionado gestión productiva de secretos. Los factores del fixture siguen siendo sintéticos y el perfil sigue draft.

### Incremento AUTH-T05

Existe [middleware operator y lectura /me](../03-design/console-operator-context.md) con verificación Bearer, roles/capacidades propios, revalidación viva de tenant/membership y composición BFF desde sesión cifrada. Se usan tres credenciales runtime separadas y las migraciones/grants existentes. [ADR-0006](../decisions/ADR-0006.md) adelanta sólo lectura de generación inicial desde AUTH-T06 para habilitar /me.

AUTH-T06 implementa actividad, refresh/logout y rotación. AUTH-T07 completa comandos restantes/CSRF/step-up. Pendientes: selector/UI/navegador (AUTH-T08), auditoría integrada (AUTH-T09) y operación/gate A4 (AUTH-T10). issuerIds vacío no acredita asignación ni autoridad sobre emisores. AUTH-T06 permite refresh explícito dentro de los límites originales; una familia incierta/revocada exige nuevo login. No se probaron MFA real, navegador, carga ni restore; el perfil conserva draft.

### Incremento AUTH-T06

Existe [ciclo de sesión](../03-design/console-session-lifecycle.md) con lease persistente, rotación cookie/CSRF/AAD, logout local primero y mantenimiento acotado. Se probaron pérdidas mediante inyección en puertos y desconexión HTTP; no se ensayó caída física de host ni restore. El mantenimiento no tiene SLA ni métricas/alertas de backlog; un fallo DB retrasa la eliminación física sin ampliar la validez de las credenciales. Rate limiting sigue local al proceso. AUTH-T07 completa comandos restantes. MFA real, navegador y operación productiva siguen pendientes.

### Incremento AUTH-T07

Existe [MFA/step-up y cambio de contexto](../03-design/console-reauthentication.md), con [ADR-0008](../decisions/ADR-0008.md) y migración 0005. Se prueban reautenticación de la misma identidad, binding de familia/generación, rotación atómica, Origin/CSRF/JSON, concurrencia/logout/lease/rollback y selector backend entre dos tenants. No se concede autoridad desde claims/body del navegador ni se amplía el límite absoluto.

Pendientes: IdP/factores productivos, interfaz/navegador y limpieza de estado visual (AUTH-T08), auditoría integrada (AUTH-T09), operación y gate A4 (AUTH-T10). El gate de freshness está implementado y probado para ser invocado por las futuras mutaciones privilegiadas de FEAT-002; no hay aún administración de miembros. No se probaron carga/restore ni se publicó o migró un entorno existente. El perfil sigue draft.

### Incremento AUTH-T08

Conecta las pantallas de autenticación con los endpoints reales y añade negociación de navegación compatible con 303, error de callback recuperable y origen explícito para proxy local. [Referencia](../03-design/console-auth-interface.md) y [ADR-0009](../decisions/ADR-0009.md) mantienen el detalle. E2E Chromium verifica UI, permisos vivos, expiración, aislamiento visual y ausencia de credenciales en storage/HTML. No amplía permisos de persistencia ni añade migraciones. AUTH-T09 conserva auditoría/redacción integrada; AUTH-T10 operación/gate A4. Siguen pendientes factores reales, proveedor productivo, carga/restore y conformidad del perfil.

### Incremento AUTH-T09

Existe [auditoría integrada](../03-design/console-auth-audit.md) con [ADR-0010](../decisions/ADR-0010.md), migración 0006, eventos/outbox atómicos y pruebas de redacción/permisos/rollback/concurrencia en laboratorio. Las denegaciones tienen registro acotado y alerta fija; no se garantiza conservarlas ante caída de DB/proceso. No se entrega retención institucional, WORM, worker/visor, SIEM ni redacción de proxies/infraestructura externos. AUTH-T10 conserva operación/gate A4; MFA real, carga/restore, proveedor y preparación productiva siguen pendientes.

### Incremento AUTH-T10

La primera ejecución CI reportada por el owner aprobó check/build y falló al iniciar PostgreSQL antes de las pruebas de integración. Se corrige el lanzamiento directo mediante `pg_ctl`, junto con permisos del runner sobre los clústeres descartables y diagnóstico de arranque. La validación local de esta corrección no acredita éxito remoto; queda pendiente repetir el workflow con la revisión corregida.

[Runbook](../04-engineering/console-auth-runbook.md), [matriz A4](authentication-gate.md), comando offline de invalidación y ensayo real de retirada/reactivación, gate local con reporte de metadatos y workflow Windows. No se entregan ni se acreditan ejecución CI remota, demo persistente, restore, drenado por señales, rollback a versión binaria anterior, factores reales, retención/publisher/visor ni observabilidad productiva. El escenario mantiene el esquema y no reactiva familias/callbacks anteriores. La invalidación local no revoca Bearer/grants del IdP. Las diferencias entre requisitos generales y alcance de laboratorio están expuestas en la matriz; producción permanece NO-GO. Continúa USR-T01.

### Incremento USR-T05

[ADR-0015](../decisions/ADR-0015.md) y [referencia de aceptación](../03-design/console-invitation-acceptance.md) añaden evidencia email de ID token validado Code/PKCE, custodia cifrada en sesión, localizador acotado de tenant por hash y canje/reingreso atómico. Migración 0009 compatible con sesiones anteriores sin inventar evidencia. Sólo dos PATCH de memberships siguen contract-only. Management depende también de una sesión server-side activa para evidencia; refresh la descarta.

Pendientes al corte USR-T05: cambios de miembros e invalidación completa USR-T06/T07, UI USR-T08, gate/operación USR-T09, fuente ownership issuer, proveedor/factores/correo reales, rate limiting específico de aceptación, carga/restore y producción. La evidencia permanece cifrada hasta la purga de secretos de sesión; su validez no se renueva al cambiar tenant. Los límites históricos anteriores describen sus respectivos incrementos.

### Incremento USR-T06

[ADR-0016](../decisions/ADR-0016.md) y [referencia de cambios de membresías](../03-design/console-members-lifecycle.md) conectan ambos PATCH Management/BFF. Las doce operaciones del contrato son implemented-test. Autorización/MFA viva, ETag, replay reautorizado y conteo de administradores bajo el mismo lock tenant protegen las escrituras. Revocación archiva el lifecycle; reingreso USR-T05 conserva identidad/membershipId e instala sólo grants nuevos. Mutación, roles, revisión, historial, idempotencia y audit/outbox revierten juntos ante fallo. No hay migración ni configuración nueva.

Los grants issuer no vacíos siguen fallando con 503 sin una fuente confiable de propiedad; no se ha implementado ese dominio. USR-T07 conserva invalidación/reconciliación completa de contexto, USR-T08 UI/confirmaciones/recuperación de edición y USR-T09 gate/operación. Sin factores/IdP/correo productivos, rate limiting específico, carga/restore, retención institucional ni producción. Este incremento no acredita emisión/verificación VC ni completa el roadmap HK.

### Incremento USR-T07

[ADR-0017](../decisions/ADR-0017.md) y [revalidación de contexto](../03-design/console-authorization-revalidation.md) conectan AUTH/USR: contexto vivo por petición, revisión reconciliada y selección retirada sin logout global. Migración 0010 limita la proyección de issuerIds a scopes propios mediante RLS, sin asignar ni verificar propiedad de issuers. La reconciliación de sesión es derivada y diferida hasta la lectura; la retirada efectiva depende de autorización viva y no del worker/outbox.

USR-T08 conserva UI de miembros/invitaciones y USR-T09 gate/operación. No hay ownership issuer, IdP/MFA/correo productivos, rate limiting específico, carga/restore, rollback binario ensayado, retención institucional ni producción. Las evidencias anteriores conservan su alcance histórico; el roadmap HK no cambia.

## Incremento USR-T09

El [gate U4](members-gate.md) reúne las AC/QR de miembros, regresión AUTH, PostgreSQL/HTTP y Chromium. Añade pruebas de rollback de expiración/redacción ante fallos de audit/outbox, límites de retención, aislamiento tenant y coherencia de evidencia. El [runbook](../04-engineering/console-members-runbook.md) documenta el lote explícito del worker, diagnóstico agregado y retirada. No hay migración, ruta ni permiso nuevo. La evidencia local no acredita CI remoto.

USR-T01–T09 quedan completas en laboratorio; siguiente DASH-T01. Permanecen pendientes ownership issuer, IdP/MFA/correo reales, HTTPS, rate limiting específico, scheduler/SLA de purga y retención institucional, publisher/visor/observabilidad, carga/SLO, rotación multiversión, rollback binario, backup/restore y DR. Purga no borra hashes, historial, audit/outbox, recibos ni copias externas. Producción sigue NO-GO y el perfil sigue draft.

## Incremento DASH-T01

[Contrato de dashboard](../03-design/console-dashboard-contract.md), OpenAPI de cuatro lecturas contract-only, schemas estrictos, catálogo de métricas/capacidades reservadas, política test, fixtures sintéticos y reglas Go de filtros UTC. No amplía grants AUTH/USR ni añade tablas, handlers, credenciales SQL, fuentes conectadas o UI. DASH-T02/03 deben implementar autorización viva, consultas, cursor autenticado y perímetro HTTP; DASH-T04 interfaz.

La auditoría actual no atribuye issuer y los eventos globales no son actividad tenant. No se inventa esa atribución. status:read queda reservada sin asignación a roles; los dominios futuros requieren ownership y política propios. Las pruebas de contrato no acreditan aislamiento DB/HTTP ni datos operativos. Perfil draft, roadmap HK y bloqueos productivos sin cambios.

## Incremento DASH-T02

[Lectura base autorizada](../03-design/console-dashboard-reads.md) y [ADR-0020](../decisions/ADR-0020.md): caso de uso, conteo tenancy, actividad audit mínima y migración aditiva 0011 con credencial separada/RLS. Revalida contexto y consulta en snapshot de sólo lectura; no usa fixtures operativos, no lee secretos ni genera audit/outbox al consultar.

DASH-T03 conserva handlers/BFF, configuración del pool, cursor autenticado, no-store/correlación y observación HTTP; DASH-T04 UI; DASH-T05 fuentes futuras. Ownership/atribución issuer ausentes: no se inventan y los selectores/conjuntos que requieren ownership fallan cerrados. La evidencia PostgreSQL no acredita HTTP dashboard, navegador nuevo, carga/SLO, CI remoto, producción ni cierre del roadmap HK.

## Incremento DASH-T03

[API/BFF del dashboard](../03-design/console-dashboard-http.md) y [ADR-0021](../decisions/ADR-0021.md) conectan las cuatro lecturas con configuración opcional dedicada, autorización viva, cursor AES-GCM ligado a revisión/scopes, TTL fijo, errores contractuales y no-store. Las respuestas HTTP reales se contrastan con el schema. Sin migración nueva ni cambios de grants.

DASH-T04 conserva UI; DASH-T05 fuentes futuras; DASH-T06–T08 matriz ampliada, navegador y operación. Con una sola fuente de conteo autorizada conectada, su fallo sigue siendo 503 global; parciales futuros se validan por fixtures y reglas, sin fingir adaptadores. No hay ownership/atribución issuer, rate limiter dashboard propio, carga/SLO, CI remoto, producción ni cierre del roadmap HK.
