# scripts/

## Keycloak: local y staging

`local-keycloak.mjs` contiene la lógica del realm `hukid` (cliente `hukid-console`, flujo MFA, firma ES256, mappers). Tiene dos modos, elegidos con `HUKID_KEYCLOAK_MODE`:

| Modo | Cómo se usa | Diferencias |
| --- | --- | --- |
| `local` (por defecto) | `node scripts/local-env.mjs keycloak-init` | Sin cambios: loopback `http`, `sslRequired: none` al crear el realm, usuario `operador.local`. |
| `staging` | `node scripts/staging-keycloak.mjs reconcile` | `sslRequired: external` (también en un realm existente), `redirectUris` y `webOrigins` del origen HTTPS indicado, y usuario operador propio. |

En ambos modos `verifyKeycloak` valida el perfil; en `staging` además exige `sslRequired=external`. Los tiempos de sesión salen de `src/platform/config/auth.local.json` o `auth.staging.example.json`; los orígenes y secretos nunca salen de archivos del repo.

### Uso en staging

Keycloak solo publica `/realms` y `/resources`; la administración va por túnel SSH:

```sh
ssh -L 8081:127.0.0.1:8081 usuario@vps     # otra terminal; deja el túnel abierto
```

Define estas variables (todas obligatorias; el script falla nombrando las que falten y no hay valores por defecto). Hazlo en tu shell, sin guardarlas en archivos del repo:

| Variable | Contenido |
| --- | --- |
| `HUKID_KC_ADMIN_URL` | URL de administración, p. ej. `http://127.0.0.1:8081` (`http` solo en loopback; otro host exige `https`). |
| `HUKID_KC_ADMIN_USER` / `HUKID_KC_ADMIN_PASSWORD` | Administrador de Keycloak. |
| `HUKID_KC_CLIENT_SECRET` | Secreto del cliente `hukid-console` (mínimo 32 caracteres). Debe ser el mismo `HUKID_OIDC_CLIENT_SECRET` de la API. |
| `HUKID_KC_OPERATOR_USER` | Usuario operador de staging. No puede ser `operador.local` ni `admin`. |
| `HUKID_KC_OPERATOR_EMAIL` | Correo del operador (se solicita el scope `email`). |
| `HUKID_KC_OPERATOR_PASSWORD` | Contraseña inicial (mínimo 16 caracteres, distinta de las demás). Es temporal. |
| `HUKID_KC_CONSOLE_ORIGIN` | Origen público de consola y API, p. ej. `https://hukid.zentrycore.com`: https, en minúsculas, sin puerto ni ruta. |

```sh
node scripts/staging-keycloak.mjs verify      # solo lectura
node scripts/staging-keycloak.mjs reconcile   # crea o actualiza realm y cliente, crea el operador si falta, y verifica
```

- `reconcile` es idempotente. Un usuario operador existente no se modifica: no se restablecen contraseña ni factor OTP.
- El operador nuevo recibe contraseña temporal y las acciones `CONFIGURE_TOTP` y `UPDATE_PASSWORD`: define TOTP y cambia la contraseña en el primer login.
- La salida nunca imprime secretos; los errores solo nombran variables.
- El script no toca el backend. La API necesita `HUKID_ENV=staging` y su política (ver [ADR-0028](../docs/decisions/ADR-0028.md)).

| `HUKID_KC_PUBLIC_ORIGIN` | Opcional. Origen público de Keycloak, p. ej. `https://hukid-id.zentrycore.com`. Si se define, `reconcile` fija los redirect URIs y web origins del cliente integrado `account-console` a ese origen (detrás del proxy Keycloak los resolvía contra la base equivocada y el endpoint de tokens respondía 403 "Invalid origin"). |

### Cómo se creó el realm en staging

El realm `hukid`, el cliente `hukid-console` y el operador de staging se crearon el 2026-11-09 con este orden, sobre el Keycloak ya desplegado ([compose](../deploy/keycloak/docker-compose.yml)):

1. Túnel SSH hacia la consola de administración, que solo escucha en `127.0.0.1:8081` del VPS: `ssh -L 18081:127.0.0.1:8081 usuario@vps` (el puerto local 18081 evita chocar con el Keycloak local, que usa 8081). Con ese túnel, `HUKID_KC_ADMIN_URL=http://127.0.0.1:18081`.
2. `node scripts/staging-keycloak.mjs reconcile` creó el realm con `sslRequired: external`, el cliente confidencial `hukid-console` (PKCE S256, firma ES256, MFA con `acr` 2, mappers mínimos) y el operador con contraseña temporal más `CONFIGURE_TOTP` y `UPDATE_PASSWORD`.
3. `node scripts/staging-keycloak.mjs verify` y un segundo `reconcile` dieron OK, lo que confirma que es idempotente.

La administración nunca se publica: Traefik solo enruta `/realms` y `/resources` (ver [restricción del realm master](../docs/05-delivery/keycloak-master-realm.md)).

### Rotar el secreto del cliente sin mostrarlo

El secreto debe ser el mismo en Keycloak y en la API: `HUKID_KC_CLIENT_SECRET` y `HUKID_OIDC_CLIENT_SECRET`. `reconcile` aplica `HUKID_KC_CLIENT_SECRET` al cliente, así que rotar es cambiar el valor en los dos archivos y reconciliar. Ningún paso necesita imprimirlo:

```sh
node scripts/staging-rotate-client-secret.mjs    # escribe un valor nuevo en .env.staging y .env.staging.compose; imprime solo nombres
node --env-file=.env.staging scripts/staging-keycloak.mjs reconcile   # con el túnel abierto: Keycloak adopta el valor nuevo
```

Después, pasa el nuevo `HUKID_OIDC_CLIENT_SECRET` a Dokploy sin verlo en pantalla y redespliega la API:

```powershell
(Get-Content .env.staging.compose | Where-Object { $_ -like 'HUKID_OIDC_CLIENT_SECRET=*' }) -replace '^[^=]*=' | Set-Clipboard
# Dokploy > hukid-api > Environment: reemplaza el valor pegando el portapapeles; guarda y redespliega.
```

Entre el `reconcile` y el redespliegue, los inicios de sesión nuevos fallan (la API todavía presenta el secreto viejo). Hazlo en una ventana corta y sin usuarios. La renovación de sesión también llama al endpoint de tokens con el secreto del cliente, así que las sesiones abiertas pueden fallar al renovar hasta que la API se redespliegue (no verificado: depende de cuándo refresque cada sesión). Si algo sale mal, repetir el redespliegue con el valor actual de `.env.staging.compose` lo deja consistente. El valor anterior no se conserva: si necesitas poder volver atrás, guarda tú una copia antes de rotar.

Garantías que cubren los tests y esta revisión: `staging-keycloak.mjs`, `staging-secrets.mjs` y `staging-rotate-client-secret.mjs` imprimen solo nombres de variables, orígenes y estados; los errores de Keycloak muestran método, ruta y código HTTP, nunca el cuerpo. `staging-rotate-client-secret.test.mjs` comprueba que el valor no aparece en la salida.

### Tests

```sh
node --test scripts/staging-keycloak.test.mjs scripts/staging-secrets.test.mjs scripts/staging-rotate-client-secret.test.mjs
```

Son tests sin red ni Keycloak: usan un cliente administrativo falso en memoria y directorios temporales.
