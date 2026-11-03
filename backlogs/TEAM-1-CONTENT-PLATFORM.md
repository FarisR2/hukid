# Equipo 1 — Content & Platform Foundation

## Producto

Entrega Platform API, tenant directory, gateway/identity integration, CMS API, Public Read API, React Admin Shell, módulo React CMS, Astro commercial/demo/client sites y foundation de despliegue.

## Épica PF-A — Organizaciones, identidad y acceso

| ID | Historia | Criterios de aceptación esenciales |
|---|---|---|
| PF-001 | Como administrador inicial, quiero crear una organización y su primer owner. | Alta idempotente; slug único; owner activo; auditoría; rollback si falla provisioning. |
| PF-002 | Como owner, quiero invitar un miembro con roles definidos. | Invitación expirable y de un uso; no duplica membresía; correo por evento; roles validados. |
| PF-003 | Como invitado, quiero aceptar o rechazar la invitación. | Requiere identidad OIDC verificada; token hasheado; estados pending/accepted/declined/expired; replay rechazado. |
| PF-004 | Como usuario, quiero iniciar sesión mediante OIDC con PKCE. | `state`/`nonce`/PKCE/issuer/audience validados; cookie segura; redirección original allowlisted; auditoría. |
| PF-005 | Como usuario, quiero mantener y cerrar mi sesión de forma segura. | Refresh rotado; expiración idle/absolute; logout revoca sesión; reutilización revoca familia; tokens fuera de localStorage. |
| PF-006 | Como usuario bloqueado o sin membresía, quiero recibir una respuesta clara sin acceder a datos. | Estados 401/403/404 coherentes; UI forbidden; ninguna proyección privada cargada; auditoría. |
| PF-007 | Como usuario, quiero recuperar acceso o configurar MFA desde el proveedor de identidad. | Enlace al flujo IdP; retorno seguro; roles privilegiados bloqueados sin MFA; autenticación reciente para acciones críticas. |
| PF-008 | Como owner, quiero cambiar roles, suspender o revocar miembros. | ETag/If-Match; no se elimina último owner; sesiones revocadas al suspender; evento de membership actualizado. |
| PF-009 | Como miembro de varias organizaciones, quiero cambiar de contexto. | Sólo memberships activas; token/sesión reemitidos con tenant; cachés privadas separadas; URL refleja organización. |
| PF-010 | Como security admin, quiero consultar y revocar sesiones activas. | Lista dispositivo/IP pseudonimizada/último uso; revocación inmediata; no expone tokens. |
| PF-011 | Como equipo técnico, quiero crear service accounts con scopes mínimos. | Secret mostrado una vez o private-key JWT; hash/ref KMS; expiración/rotación/revocación; audience exacta. |
| PF-012 | Como auditor, quiero consultar eventos de identidad y autorización. | Filtros/paginación/retención; append-only; export requiere scope y MFA; sin claims sensibles. |

## Épica PF-B — Tenant, dominios y gateway

| ID | Historia | Criterios de aceptación esenciales |
|---|---|---|
| PF-020 | Como owner, quiero configurar nombre, zona horaria, locale y estado institucional. | Validaciones; revisión optimista; suspensión bloquea operaciones privadas y preserva públicos según policy. |
| PF-021 | Como owner, quiero asociar y verificar un dominio. | Challenge DNS/HTTP; hostname único; TLS automatizado; takeover prevenido; renovación/alerta. |
| PF-022 | Como visitante, quiero que host/slug resuelva el sitio correcto sin fuga cross-tenant. | Resolver privilegiado mínimo; slug/host canonizados; resultado sólo IDs opacos; pruebas negativas. |
| PF-023 | Como plataforma, quiero enrutar APIs con autenticación, cuotas y request IDs comunes. | Gateway valida JWT/audience; WAF/rate limit/CORS; propaga trace; tamaños/timeouts; problem details. |
| PF-024 | Como servicio, quiero usar una librería común de tenant/RBAC. | Extrae sólo claims validados; establece RLS; helpers scope/event/site; pruebas contractuales por lenguaje. |
| PF-025 | Como operador, quiero bloquear una organización o client comprometido. | Kill switch auditable; revoca sesiones/clients; caché de decisión con TTL corto; runbook. |

## Épica PF-C — CMS y medios

| ID | Historia | Criterios de aceptación esenciales |
|---|---|---|
| PF-030 | Como editor, quiero crear y configurar un sitio. | Tipo product/demo/client; tema, locale y navegación; sólo su organización; draft inicial. |
| PF-031 | Como editor, quiero crear, editar y ordenar páginas con bloques tipados. | JSON Schema por bloque; sanitización; ETag; autosave controlado; errores por pointer. |
| PF-032 | Como editor, quiero subir imágenes/documentos. | Upload firmado; límite/MIME/hash; malware scan; estados pending/ready/quarantined; alt text requerido en imagen pública. |
| PF-033 | Como editor, quiero previsualizar sin publicar. | Token preview corto y de un uso/usuario; `no-store`; borrador no indexable ni accesible públicamente. |
| PF-034 | Como editor, quiero publicar una versión inmutable. | Snapshot/hash/version; publicación idempotente; evento; invalidación CDN; borrador posterior separado. |
| PF-035 | Como editor, quiero restaurar una versión previa creando una nueva publicación. | Historial; comparación; nunca muta snapshot antiguo; auditoría. |
| PF-036 | Como editor, quiero configurar SEO y compartir en redes. | title/description/canonical/OG/image/sitemap/robots; preview; defaults accesibles. |
| PF-037 | Como editor, quiero insertar catálogo, evento destacado y agenda sin duplicar eventos. | Bloque almacena filtro/ID + publication; Content proyecta sólo releases activas; empty/error state. |
| PF-038 | Como owner, quiero versionar tema y navegación. | Tokens allowlisted; contraste validado; navegación sin links inseguros; preview/publicación/rollback. |

## Épica PF-D — Frontends públicos y Admin Shell

| ID | Historia | Criterios de aceptación esenciales |
|---|---|---|
| PF-040 | Como prospecto, quiero entender el producto y solicitar demo. | Landing Astro rápida/accesible; lead anti-spam; consentimiento; confirmación y evento interno. |
| PF-041 | Como prospecto, quiero recorrer una demo reproducible. | Seed sin PII; evento simple y convocatoria; reset versionado; banner que identifica demo. |
| PF-042 | Como visitante, quiero consultar sitio, catálogo, detalle y programas. | SSR/static edge; publicación coherente; 404/cancelled; locale/timezone; SEO; sin llamada transaccional en cache hit. |
| PF-043 | Como visitante, quiero iniciar registro desde la página del evento. | Slot estable para isla React de Participation; CSP; design tokens; analytics consentido; fallback de error. |
| PF-044 | Como usuario interno, quiero un shell administrativo consistente. | Login callback, organización activa, navegación por permiso, breadcrumbs, loading/empty/error/forbidden, logout. |
| PF-045 | Como usuario, quiero interfaces accesibles y responsive. | WCAG AA en journeys críticos; teclado/focus/screen reader; pruebas desktop/móvil y reduced motion. |
| PF-046 | Como visitante, quiero contenido actualizado sin cruces de caché. | Cache key host/site/locale/slug/publication; ETag/surrogate key; no cachea cookies/preview; purge versionado. |

## Épica PF-E — Plataforma operable

| ID | Historia | Criterios de aceptación esenciales |
|---|---|---|
| PF-050 | Como equipo, quiero templates de repositorio y pipelines. | Lint/test/SBOM/scan/build/sign/deploy; ambientes aislados; promoción y rollback; ownership CODEOWNERS. |
| PF-051 | Como servicio, quiero secretos y configuración seguros. | Secret manager; rotación; no secretos en logs/build; startup falla cerrado; configuración tipada. |
| PF-052 | Como operador, quiero métricas, logs y trazas comunes. | OTel; request/trace/org IDs; redacción PII; dashboards/alertas/SLO; correlación cross-service. |
| PF-053 | Como operador, quiero broker, schema registry, retry y DLQ base. | ACL por topic; compatibilidad; retención; replay controlado; DLQ con acceso restringido y sin PII. |
| PF-054 | Como responsable, quiero backups y recuperación del tenant/CMS. | PITR; cifrado; restore drill; RPO/RTO medidos; runbook y evidencia trimestral. |
| PF-055 | Como soporte, quiero health/readiness y diagnóstico seguro. | Dependencias diferenciadas; no secretos; drain shutdown; status interno autenticado. |

## Contratos que posee

`/platform/v1/organizations`, `/memberships`, `/invitations`, `/roles`, `/sessions`, `/service-accounts`, `/domains`; `/cms/v1/sites`, `/pages`, `/media`, `/publications`; `/public/v1/sites/**`. Produce eventos platform/content y consume `configuration.event.release_published.v1` y `participation.availability.changed.v1`.
