# Restringir el realm `master` de Keycloak en staging

Estado: propuesta; no aplicada. Cualquier cambio se muestra como diff antes de tocar Dokploy.

## Qué está expuesto hoy

Verificado el 2026-11-10 con GET públicos a `https://hukid-id.zentrycore.com`:

| Ruta | Respuesta | Comentario |
| --- | --- | --- |
| `/realms/hukid/.well-known/openid-configuration` | 200 | Necesaria: la API y el navegador la usan. |
| `/realms/master/.well-known/openid-configuration` | **200** | Innecesaria y expuesta. |
| `/realms/master/protocol/openid-connect/certs` | **200** | Idem. |
| `/admin/master/console/` | 404 | Correcto: `/admin` no se enruta. |

La causa es la regla del router en [`deploy/keycloak/docker-compose.yml`](../../deploy/keycloak/docker-compose.yml): ``PathPrefix(`/realms`)`` cubre todos los realms. La consola de administración sí queda fuera (solo `127.0.0.1:8081`), pero el endpoint de autenticación del realm `master` (`/realms/master/protocol/openid-connect/auth` y `/token`) es alcanzable. Es el blanco natural de ataques de credenciales contra el administrador, que en staging es la cuenta temporal `KC_BOOTSTRAP_ADMIN_USERNAME`.

## Propuesta principal: estrechar la regla de Traefik

Cambiar una línea de la etiqueta del router `hukid-kc`:

```diff
-      - traefik.http.routers.hukid-kc.rule=Host(`hukid-id.zentrycore.com`) && (PathPrefix(`/realms`) || PathPrefix(`/resources`))
+      - traefik.http.routers.hukid-kc.rule=Host(`hukid-id.zentrycore.com`) && (PathPrefix(`/realms/hukid/`) || PathPrefix(`/resources/`))
```

- La barra final importa: `/realms/hukid/` no casa con un futuro realm `hukid-otro`.
- Lo que no casa con ningún router lo responde Traefik con 404, sin llegar a Keycloak.
- `/resources/` es genérico de Keycloak (JS y CSS de las pantallas de login) y no se puede filtrar por realm. No expone datos.
- El realm `master` sigue funcionando para administrar: la consola se abre por el túnel SSH en `127.0.0.1:8081`, que no pasa por Traefik. Con `KC_HOSTNAME_ADMIN=http://127.0.0.1:8081` las redirecciones de administración apuntan a ese origen.

## Defensa en profundidad (opcional)

1. **Cloudflare:** una regla WAF que bloquee `http.request.uri.path starts_with "/realms/master"` sobre el host `hukid-id.zentrycore.com`. Es independiente de Traefik y sobrevive a un error en las etiquetas.
2. **Keycloak:** activar la protección contra fuerza bruta en el realm `master` y sustituir la cuenta `bootstrap` por un administrador permanente con TOTP. Se hace desde la consola por el túnel; no está automatizado en `scripts/`.

## Cómo comprobarlo tras aplicarlo

Debe cumplirse todo, en este orden:

```sh
curl -s -o /dev/null -w '%{http_code}\n' https://hukid-id.zentrycore.com/realms/hukid/.well-known/openid-configuration   # 200
curl -s -o /dev/null -w '%{http_code}\n' https://hukid-id.zentrycore.com/realms/hukid/protocol/openid-connect/certs     # 200
curl -s -o /dev/null -w '%{http_code}\n' https://hukid-id.zentrycore.com/realms/master/.well-known/openid-configuration  # 404
curl -s -o /dev/null -w '%{http_code}\n' https://hukid-id.zentrycore.com/realms/master/protocol/openid-connect/auth      # 404
curl -s -o /dev/null -w '%{http_code}\n' https://hukid-id.zentrycore.com/admin/master/console/                          # 404
```

Después, un login completo en `https://hukid.zentrycore.com` (contraseña, TOTP, consola) y la consola de administración por el túnel. Si el login falla, revertir la etiqueta: el cambio no toca datos.

## No verificado

- Que Dokploy aplique la etiqueta con un redeploy sin recrear el volumen de la base de Keycloak. Debería, porque el volumen es independiente, pero no se ha ensayado.
- Que Keycloak no necesite `/realms/master/...` desde el navegador durante el login del realm `hukid` (no debería; cada realm usa sus propias rutas).
