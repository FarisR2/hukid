# Artefactos pendientes y diferencias documentales

Fecha: 2026-11-03. Inventario del paquete recibido; no significa que los artefactos no existan en otro repositorio. Los diez Markdown HukID incorporados sustituyen referencias personales para arquitectura, perfil y modelo conceptual, pero no adjuntan los archivos ejecutables citados.

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

Los paquetes [FEAT-001/002/003](../features/README.md) añaden especificación, plan y tareas para la consola HukID confirmada por el usuario. [ADR-0002](../decisions/ADR-0002.md) registra propuestas de BFF, operador, miembros y dashboard. AUTH-T01–T05 implementan bootstrap, contratos, PostgreSQL, login/callback y lecturas autorizadas /me de laboratorio; ciclo operativo de sesión, comandos, UI, miembros y dashboard siguen pendientes. Los apartados siguientes conservan evidencia por incremento, no sustituyen el estado actual de las tareas.

Para empezar AUTH-T01 no es necesario recuperar los ejemplos de emisión ni configurar KMS issuer. Para completar login integrado sí hacen falta IdP test compatible, políticas de sesión/MFA, contrato de operador y migraciones mínimas; miembros necesita policy de invitación/notificación. No marcar esos artefactos como disponibles por existir el plan.

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

El estado posterior se registra en AUTH-T05 abajo. No hay purga automática de transacciones abandonadas/sesiones expiradas, rotación/recuperación de claves ni rate limiting distribuido. Las claves/credenciales se suministran externamente; no se ha seleccionado gestión productiva de secretos. Los factores del fixture siguen siendo sintéticos y el perfil sigue draft.

### Incremento AUTH-T05

Existe [middleware operator y lectura /me](../03-design/console-operator-context.md) con verificación Bearer, roles/capacidades propios, revalidación viva de tenant/membership y composición BFF desde sesión cifrada. Se usan tres credenciales runtime separadas y las migraciones/grants existentes. [ADR-0006](../decisions/ADR-0006.md) adelanta sólo lectura de generación inicial desde AUTH-T06 para habilitar /me.

Pendientes: actualizar actividad, refresh/logout/rotación (AUTH-T06), comandos/CSRF/step-up (AUTH-T07), selector/UI/navegador (AUTH-T08), auditoría integrada (AUTH-T09) y operación/gate A4 (AUTH-T10). issuerIds vacío no acredita asignación ni autoridad sobre emisores. La sesión inicial no se renueva: access token vencido exige nuevo login. No se probaron MFA real, navegador, carga ni restore; el perfil conserva draft.
