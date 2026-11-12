# Brief de despliegue HukID en Dokploy (borrador)

Estado: borrador de consulta, no es una decisión. Producción y despliegue siguen sin decidir en `documentation-gaps.md`; si se adopta, debe quedar en un ADR. Todo lo de abajo sale del código del repo (commit `bc4e614`) salvo lo marcado **[no verificado]**.

## 1. Hallazgo bloqueante: el backend NO acepta producción

> Actualización 2026-11-09: el commit siguiente añade el entorno `staging` ([ADR-0028](../decisions/ADR-0028.md), propuesta): `HUKID_ENV=staging`, issuer y consola `https` públicos, cookie `__Host-hukid_session` `Secure`, base `hukid_staging` con TLS (o alias de red privada de un solo segmento). Plantilla: `src/platform/config/auth.staging.example.json`. Sigue faltando alta del primer administrador y herramienta de migración para staging. Lo que sigue describe el estado previo y por qué hizo falta.

`src/platform/internal/authentication/policy.go` solo admite `HUKID_ENV=test` o `local`, y `Policy.Validate` impone, para ambos:

- `issuer` y `consoleOrigin` **loopback** (`127.0.0.1`/`::1`) y con esquema **`http`**.
- `cookieSecure` **debe ser `false`**, `cookieSameSite` = `Lax`.
- `clientId` fijo `hukid-console`, cookie `hukid_local_session`, `audience` `https://api.hukid.pe/operator`.
- `redirectUri` = `consoleOrigin + /console/auth/callback`; `issuer` y `consoleOrigin` con orígenes distintos.

Además: `memberconfig/secrets.go` solo permite `HUKID_ENV` `test`/`local`; `cmd/api/{auth,dashboard,directory}.go` y `cmd/worker/main.go` llaman a `SupportedEnvironment`; `localdb` y `bootstrap_local.go` exigen `HUKID_ENV=local` y una base `hukid_local` en loopback.

**Consecuencia:** subir la API tal cual al VPS no arranca. Hace falta código nuevo: un entorno (p. ej. `staging`/`production`) que acepte issuer `https` público, `consoleOrigin` `https`, `cookieSecure=true`, y que siga rechazando configuraciones inseguras. Eso es trabajo de backend con tests y ADR, no solo configuración.

Lo que sí se puede subir hoy, de forma independiente: **Keycloak**.

## 2. Arquitectura objetivo

```
Internet -> Cloudflare -> Traefik (Dokploy)
   id.<dominio>   -> Keycloak (solo /realms/* y /resources/*)
   app.<dominio>  -> consola estática + API (mismo origen)
API -> Keycloak (issuer público HTTPS), API -> PostgreSQL HukID
Keycloak -> PostgreSQL propia (otra base/instancia)
```

- La API es el único cliente OIDC y el único que usa la base de HukID. La consola nunca habla con Keycloak: el login lo muestra Keycloak (no hay landing propia, ver `prototype-brief.md:17`).
- Consola y API deben compartir origen: la sesión es una cookie de la API (patrón BFF). En local Vite hace de proxy (`HUKID_CONSOLE_API_TARGET`); en producción hay que servir el build estático y enrutar `/console/*` (y la API de consola) a la API bajo el mismo dominio **[no verificado el listado exacto de rutas; revisar `cmd/api/main.go`]**.

## 3. Keycloak

- Versión usada: **26.8.2**. Hoy corre con `start-dev`, `--hostname-strict=false`, `sslRequired: none`. Nada de eso sirve en producción.
- Producción: `kc.sh start` (optimizado), `KC_HOSTNAME=https://id.<dominio>`, `KC_PROXY_HEADERS=xforwarded`, `KC_HTTP_ENABLED=true` (TLS termina en Traefik/Cloudflare), `KC_DB=postgres` con su propia base, `KC_HEALTH_ENABLED=true`. **[no verificado: nombres exactos de variables en 26.8; contrastar con la doc oficial]**.
- **No exponer** `/admin`, ni el realm `master`. En Traefik publicar solo `/realms/hukid/*` y `/resources/*`; la administración por túnel o VPN.
- Credenciales de bootstrap: `KC_BOOTSTRAP_ADMIN_USERNAME`/`KC_BOOTSTRAP_ADMIN_PASSWORD`; rotarlas y retirar el admin temporal tras el primer arranque.
- Cloudflare: no cachear `/realms/*`; respetar cabeceras `X-Forwarded-*`; si se usa Cloudflare Tunnel, el origen apunta a Traefik.

### Realm y cliente (lo reconcilia `scripts/local-keycloak.mjs`, `reconcileKeycloak`)

- Realm `hukid`; `bruteForceProtected: true`, `registrationAllowed: false`. En producción `sslRequired` debe ser `external` o `all` (el script hoy fija `none`).
- Cliente `hukid-console`: confidencial (`client-secret`), solo Authorization Code + PKCE S256; sin implicit, sin direct grants, sin service accounts; `fullScopeAllowed=false`; `consentRequired: true`.
- `redirectUris` = `[https://app.<dominio>/console/auth/callback]`, `webOrigins` = `[https://app.<dominio>]` (hoy se derivan de `origin` local).
- Tokens firmados **ES256** (proveedor `ecdsa-generated` P-256, `hukid-es256-signing`), `at+jwt` (RFC 9068), acr `2`.
- Flujo de autenticación propio `hukid-console-mfa-v1`: usuario/contraseña + OTP obligatorio, LoA 2.
- Scopes por defecto: `email`, `acr`, `basic`, `operator:read`; opcional solo `offline_access`.
- Mappers: `amr`, audiencia `https://api.hukid.pe/operator`, y claims fijos `client_id`, `hukid_token_class=operator`, `hukid_grant=authorization_code`.
- Tiempos (de `auth.local.json`): access token 300 s, idle 1800 s, absoluto 28800 s, refresh 28800 s, step-up 300 s, rate limit de login 10/60 s; refresh token con revocación y `refreshTokenMaxReuse=0`.
- El script depende de `src/platform/config/auth.local.json` para esos tiempos; para producción hay que **parametrizarlo** (issuer, origen, usuario operador, contraseña de cliente) y no reutilizar `operador.local`.
- Verificación: `verifyKeycloak` falla si el perfil no coincide (así falló `start` hoy hasta correr `keycloak-init`).

## 4. API (binario Go) y worker

- Toolchain: **Go 1.27.3** exacta (`GOTOOLCHAIN=local`); build: `go build -o hukid-api ./cmd/api` desde `src/platform`. Existe `cmd/worker` (argumentos: dos UUID de tenant/ejecución según la doc).
- **No hay Dockerfile ni compose** en el repo: hay que crearlos (multi-stage Go → imagen mínima no-root; otra imagen o contenedor nginx/caddy para la consola, o servir el build desde la API).
- Salud: `GET /healthz`. Escucha en `HUKID_LISTEN_ADDR` (hoy `127.0.0.1:8080`; en contenedor debe ser `0.0.0.0:8080`, lo que hoy la política no permite para el origen/issuer **[comprobar si `HUKID_LISTEN_ADDR` también está restringido]**).
- Variables que lee la API (nombres reales del código; **los valores son secretos, nunca al repo**):
  - Entorno/política: `HUKID_ENV`, `HUKID_AUTH_POLICY` (ruta al JSON), `HUKID_LISTEN_ADDR`, `HUKID_CONSOLE_PROXY_ORIGIN`.
  - Bases (una URL por rol runtime, ver §5): `HUKID_SESSION_DATABASE_URL`, `HUKID_CONTEXT_DATABASE_URL`, `HUKID_TENANT_DATABASE_URL`, `HUKID_MEMBERS_DATABASE_URL`, `HUKID_DASHBOARD_DATABASE_URL`.
  - Secretos: `HUKID_OIDC_CLIENT_SECRET`, `HUKID_AUTH_KEY` + `HUKID_AUTH_KEY_VERSION`, `HUKID_INVITATION_KEY` + `HUKID_INVITATION_HMAC_KEY` + `HUKID_INVITATION_KEY_VERSION`, `HUKID_MEMBERS_CURSOR_KEY`, `HUKID_DASHBOARD_CURSOR_KEY` (claves base64 de 32 bytes, generadas con `randomBytes(32)` en local).
  - Políticas JSON: `HUKID_MEMBERS_POLICY` y `HUKID_DASHBOARD_POLICY`; hoy apuntan a `user-management.test.json` y `dashboard.test.json` (**archivos de test**). Para producción hay que crear versiones reales y revisar su contenido.
- Migración/aprovisionamiento: hoy `cmd/localdb migrate` (solo local). Las migraciones son SQL en `src/platform/internal/adapters/postgres/migrations/` (0001…0005+). Falta una herramienta de migración para producción **[no verificado si existe otra]**.

## 5. PostgreSQL de HukID

- Roles de runtime separados (el script los crea como `hukid_local_<rol>`; cada uno recibe el rol `hukid_<rol>_runtime`): `session`, `context`, `tenant`, `members`, `dashboard`. Todos `NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS`. El diseño usa RLS: **no usar superusuario en runtime**.
- Una administración aparte aplica migraciones. Backups y retención no están definidos en el repo.
- Tras migrar, vincular el primer administrador: hoy `localdb bootstrap <issuer> <subject> <tenant>` (solo local, con superusuario). En producción hay que diseñar el alta del primer `tenant_admin` (es el mismo problema de "primer usuario" del §1).

## 6. Consola (React/Vite)

- Node **24.22.1** (rango `>=24.22.1 <25`), npm `>=11.19.1 <12`.
- Build: `node node_modules/vite/bin/vite.js build src/console --outDir <dir>`; el script local lo ejecuta con `HUKID_CONSOLE_API_TARGET`.
- Sin variables de entorno de runtime propias en el navegador (usa rutas relativas al mismo origen).

## 7. Qué NO está verificado (honestidad)

- La consola autenticada contra el backend real **nunca se ejecutó** de punta a punta; solo se probó con un mock. `go test ./cmd/api` está bloqueado por Application Control en la máquina de desarrollo.
- Nada de lo de producción (Traefik, Cloudflare, Dokploy, HTTPS) se probó. El diseño de arriba es una propuesta.

## 8. Orden sugerido

1. **ADR de despliegue** y decidir dominios (`id.` para Keycloak, `app.` para consola+API) y si es staging o producción.
2. **Keycloak primero** (independiente): contenedor + su Postgres + Traefik + realm reconciliado con el script parametrizado. Validar el discovery `https://id.<dominio>/realms/hukid/.well-known/openid-configuration`.
3. **Backend**: nuevo entorno `staging`/`production` en la política (con tests), políticas JSON reales, migraciones y alta del primer administrador.
4. Dockerfiles/compose, secretos en Dokploy, health checks.
5. Ejecutar la verificación contra el backend real (412, último administrador, idempotencia, invitaciones, sesión) antes de abrir al público.

## 9. Decisiones que debes tomar

- Dominios y si Cloudflare va con proxy naranja o Tunnel.
- Staging o producción real (cambia backups, MFA y rate limits).
- Un solo VPS con todo (Keycloak, Postgres x2, API, consola) o separar la base de datos.
- Idioma/tema del login de Keycloak (hoy en inglés, tema por defecto).
