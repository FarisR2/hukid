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

### Tests

```sh
node --test scripts/staging-keycloak.test.mjs
```

Son tests sin red ni Keycloak: usan un cliente administrativo falso en memoria.
