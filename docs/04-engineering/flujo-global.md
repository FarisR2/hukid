# Flujo global de HukID (entorno local)

Vista paso a paso de qué piezas existen, cómo arrancan y qué llama a qué durante el login. Los diagramas están en [Mermaid](https://mermaid.js.org/), que GitHub dibuja directamente.

Alcance: sólo el entorno local de `scripts/local-env.mjs`. No describe producción ni despliegue (sin decidir; ver [pendientes](../05-delivery/documentation-gaps.md)). Cada paso se contrastó con el código citado; lo no comprobado de extremo a extremo se marca como tal.

## 1. Piezas y conexiones (contenedores)

```mermaid
flowchart LR
  B[Navegador]
  subgraph Local["Máquina local (127.0.0.1)"]
    C["Consola<br/>vite preview :5173<br/>(bundle de .cache/local/console-dist)"]
    A["API Go<br/>:8080"]
    K["Keycloak 26.8.2<br/>:8081<br/>realm hukid"]
    P[("PostgreSQL<br/>:54329<br/>hukid_local")]
  end
  B -->|"HTTP"| C
  C -->|"proxy /console/*<br/>(vite.config.ts)"| A
  B -->|"redirección de login"| K
  A -->|"OIDC: discovery, token, JWKS"| K
  A -->|"sesiones, contexto, tenants<br/>(3 roles runtime)"| P
```

- El navegador sólo habla con la consola (`:5173`) y, durante el login, con Keycloak (`:8081`).
- Todo `/console/*` pasa por el proxy de Vite hacia la API sin reescribir `Origin`, para conservar cookies y CSRF (`src/console/vite.config.ts`).
- La API es el único cliente OIDC y el único que usa PostgreSQL.

## 2. Arranque: `node scripts/local-env.mjs start`

```mermaid
sequenceDiagram
  autonumber
  participant S as local-env.mjs start
  participant P as PostgreSQL :54329
  participant K as Keycloak :8081
  participant A as API :8080
  participant C as Consola :5173
  S->>S: comprueba que 8080 y 5173 están libres
  S->>P: pg_ctl start (si no corre)
  S->>K: arranca si 8081 está libre
  S->>K: espera /.well-known/openid-configuration
  S->>S: go build → .cache/build/hukid-api.exe
  S->>S: vite build → .cache/local/console-dist
  S->>A: lanza con política auth.local.json y roles de BD
  S->>C: lanza vite preview sobre console-dist
  S->>A: espera /healthz
  S->>C: espera respuesta HTTP
  S-->>S: imprime LISTO y la URL
```

Fuente: `scripts/local-env.mjs` (función `start`). `init` y `keycloak-init` crean o actualizan el entorno; `bootstrap` requiere Keycloak activo y puede ejecutarse tras `start`, en otra terminal. El [perfil Keycloak](../03-design/console-local-keycloak.md) incluye verificación previa y configuración de miembros/dashboard.

## 3. Login: abrir la raíz sin sesión

```mermaid
sequenceDiagram
  autonumber
  actor U as Usuario
  participant B as Navegador (consola React)
  participant A as API Go
  participant K as Keycloak
  participant P as PostgreSQL
  U->>B: abre http://127.0.0.1:5173/
  Note over B: AuthConsole en estado "loading"<br/>(pantalla en blanco, opacity-0)
  B->>A: GET /console/api/me
  A-->>B: 401 invalid_session
  B->>A: GET /console/auth/login?returnTo=/
  A->>P: guarda la transacción (state, nonce, PKCE)
  A-->>B: cookie de transacción + URL de autorización
  B->>K: redirección (PKCE S256, prompt="login consent")
  K-->>U: formulario de Keycloak (usuario, contraseña, TOTP)
  U->>K: credenciales
  K-->>B: redirección a /console/auth/callback?code&state&iss
  B->>A: GET /console/auth/callback
  A->>K: intercambia el code por tokens y valida el ID token (ES256)
  A->>P: crea la sesión
  A-->>B: 303 a "/" + cookie de sesión HttpOnly
  B->>A: GET /console/api/me
  A-->>B: 200 identidad, organizaciones, csrfToken
  Note over B: vista autenticada
```

Fuentes:

- Cliente: `src/console/src/authentication/AuthConsole.tsx` (`run('read')`, `claimAutoLogin`, `run('login')`) y `client.ts` (`/console/api/me`, `navigate`).
- API: `src/platform/internal/adapters/console/login.go` (`start`, `complete`, cookie de transacción con `Path=/console/auth`, `303` al terminar).
- OIDC: `src/platform/internal/adapters/oidc/client.go` (PKCE `S256`, `prompt=login consent`, firma ES256).
- Callback registrado: `src/platform/config/auth.local.json` (`redirectUri` a `:5173/console/auth/callback`).

### Reglas del arranque automático

- Si el primer `GET /console/api/me` devuelve 401, la consola inicia el login sola; no existe pantalla de acceso ([ADR-0025](../decisions/ADR-0025.md)).
- Un segundo intento automático en menos de 60 s no se hace: se muestra la vista "Acceso no completado" con el botón "Iniciar sesión de nuevo" (evita un bucle si el proveedor falla).
- Al cerrar sesión se repite el mismo ciclo y vuelve a pedirse usuario y contraseña, porque el login siempre fuerza credenciales.
- Configurar TOTP por primera vez no sustituye ejecutar el autenticador OTP: si el primer callback se rechaza, volver a HukID e iniciar sesión de nuevo con contraseña y OTP. No se crea sesión sin la evidencia requerida.

## 4. Evidencia y límites

- `npm run test:keycloak` comprueba el perfil real en recursos aislados; las [tareas AUTH](../features/FEAT-001-authentication/tasks.md) registran el resultado vigente y las limitaciones. La [auditoría inicial](../05-delivery/reviews/local-flow-2026-11-09.md) conserva las incompatibilidades originales.
- El orden exacto de las escrituras en PostgreSQL durante `start` y `complete`: el diagrama indica el efecto, no cada consulta.
- Producción: HTTPS, dominio, base de datos persistente y copias de seguridad de Keycloak.

Para contrastar el orden real de llamadas, revise `.cache/local/api.log` (API) y `.cache/local/console.log` (consola) mientras abre la raíz.
