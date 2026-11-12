# Operación de staging: aprovisionamiento, membresía huérfana y reinicios

Aplica a `deploy/staging/compose.yaml` en Dokploy ([ADR-0029](../decisions/ADR-0029.md)). Ningún paso de este documento guarda ni muestra secretos.

## Orden de aprovisionamiento

Una sola vez, tras el primer despliegue, con `docker compose --profile tools run --rm tools ...`:

1. `migrate`: aplica las migraciones SQL con la cuenta propietaria (`hukid_admin`).
2. `runtime-logins`: crea los cinco logins de ejecución `hukid_staging_<rol>` (`session`, `context`, `tenant`, `members`, `dashboard`), `NOSUPERUSER`, solo con la pertenencia a su rol.
3. `bootstrap <issuer> <subject> "<nombre del tenant>"`: crea un tenant y liga una identidad real como `tenant_admin`.

El `subject` es el identificador `sub` del usuario en Keycloak (un UUID). No se puede deducir: hay que leerlo del usuario real.

## Membresía huérfana por un `bootstrap` con subject inventado

### Qué quedó, según el código

`bootstrapIdentity` (`internal/adapters/postgres/bootstrap_local.go`) no reutiliza tenants: **cada ejecución con un subject nuevo crea un tenant nuevo** con ese nombre. Solo es idempotente por identidad: si `(issuer, subject)` ya existe, no hace nada. Por tanto, dos ejecuciones con dos subjects distintos dejaron, en una sola transacción cada una:

| | Primer `bootstrap` (subject inventado) | Segundo `bootstrap` (subject real) |
| --- | --- | --- |
| `tenancy.tenants` | "Zentry Core" (huérfano) | "Zentry Core" (en uso) |
| `tenancy.operator_identities` | identidad con el subject inventado | identidad real |
| `tenancy.memberships` + `membership_roles` | `active` + `tenant_admin` | `active` + `tenant_admin` |
| `platform.audit_events` + `outbox_events` | `staging.bootstrap.completed` | `staging.bootstrap.completed` |

Estado **inferido, no consultado**: no hay acceso a la base desde la máquina de desarrollo (no publica puerto y el usuario SSH no tiene permiso de Docker). El paso 1 de abajo lo confirma.

El huérfano es inofensivo hoy: nadie puede autenticarse con ese subject (Keycloak asigna sus propios UUID), y como la consola solo lista tenants `active` con membresía `active` del operador actual, nadie lo ve. Pero hay dos tenants con el mismo nombre y una identidad administradora sin dueño.

### Por qué no se borra ni se revoca desde la aplicación

- **Regla del último administrador:** la aplica el código bajo el bloqueo del tenant (`ErrLastAdmin` en `internal/tenancy/membership_rules.go`), no una restricción de la base. Revocar esa membresía por la API es imposible, porque nadie puede iniciar sesión como esa identidad, y además la propia regla lo rechazaría, porque es el único administrador del tenant.
- **Borrar filas:** `audit_events` y `outbox_events` referencian el tenant y la identidad por clave foránea. Borrarlos obliga a borrar evidencia de auditoría como superusuario. No se recomienda.
- **Sin superusuario en runtime:** los logins `hukid_staging_*` solo tienen `SELECT` sobre `tenancy.tenants` y sus tablas hermanas (migración `0002`). Quien corrige esto es el propietario, a mano, una vez; la aplicación no gana ningún permiso.

### Procedimiento seguro: suspender el tenant huérfano

`tenancy.tenants.state` admite `suspended`. Un tenant suspendido desaparece de la consola (`console_auth.operator_tenants()` exige `t.state = 'active'`) y sus membresías dejan de resolverse, sin tocar auditoría, identidades ni membresías. La regla del último administrador no se viola: no se quita ningún administrador.

Se ejecuta con `psql` como `hukid_admin` en el servicio de base de datos de Dokploy (su terminal), no desde la aplicación.

**1. Solo lectura: confirmar qué existe.**

```sql
SELECT t.tenant_id, t.display_name, t.state, t.created_at,
       i.subject, m.membership_id, m.state AS membership_state
FROM tenancy.tenants t
JOIN tenancy.memberships m ON m.tenant_id = t.tenant_id
JOIN tenancy.operator_identities i ON i.operator_identity_id = m.operator_identity_id
ORDER BY t.created_at;
```

Se esperan dos filas "Zentry Core". Anota el `tenant_id` de la fila cuyo `subject` es `1b2c3d4e-5f60-7182-93a4-b5c6d7e8f901`. **No continúes si ves otro resultado** (más filas, otros subjects, o el subject real en esa fila).

**2. Suspender, con guardas, en una transacción.** Sustituye `<TENANT_ID_HUERFANO>` por el valor anotado.

```sql
BEGIN;
SELECT pg_advisory_xact_lock(6721587303);  -- el mismo bloqueo que usa bootstrap
UPDATE tenancy.tenants t
SET state = 'suspended',
    display_name = 'Zentry Core (descartado: bootstrap con subject erróneo)'
WHERE t.tenant_id = '<TENANT_ID_HUERFANO>'
  AND NOT EXISTS (                       -- guarda: ninguna identidad que no sea la inventada
        SELECT 1 FROM tenancy.memberships m
        JOIN tenancy.operator_identities i USING (operator_identity_id)
        WHERE m.tenant_id = t.tenant_id
          AND i.subject <> '1b2c3d4e-5f60-7182-93a4-b5c6d7e8f901');
-- Debe decir UPDATE 1. Con UPDATE 0, ejecuta ROLLBACK; y revisa el paso 1.
COMMIT;
```

**3. Comprobar.** Repite la consulta del paso 1 (ahora debe mostrar `suspended` y el nombre nuevo para el huérfano y `active` para el real) y entra en la consola: debe aparecer una sola organización.

Verificado por lectura: ninguna de las migraciones 0001-0011 define triggers, y los cinco roles de ejecución solo tienen `SELECT` sobre `tenancy.tenants`, así que el `UPDATE` solo lo puede hacer el propietario. No verificado: el `UPDATE` en sí, que no se ha ejecutado contra la base de staging. Si fallara, la transacción se revierte y no queda nada a medias.

### ¿Debe `bootstrap` rechazar subjects que no existen en Keycloak?

Sí, conviene, pero **no comprobando contra Keycloak**: el contenedor `tools` vive en `dokploy-network` y la administración de Keycloak solo escucha en loopback del VPS, así que no puede consultarla, y dotarla de credenciales de administrador sería peor que el problema.

La opción adecuada es exigir que la identidad **ya exista por un login real**. El primer login registra `(issuer, subject)` en `tenancy.operator_identities` sin membresías (`console_auth.register_operator`) y deja al usuario en "Acceso pendiente". Si `bootstrap` solo acepta una identidad ya registrada y sin membresías, un subject inventado se rechaza por construcción: nunca pasó por Keycloak. Encaja con el flujo ya existente: el operador entra una vez, ve "Acceso pendiente", se ejecuta `bootstrap` con el subject que figura en la base, y "Comprobar acceso" lo deja pasar.

Además, una guarda barata y complementaria: rechazar la creación si ya existe un tenant con el mismo `display_name`. Habría detectado exactamente este error.

Requiere cambiar `bootstrapIdentity` (hoy hace no-op si la identidad existe), un test de integración y una nota en ADR-0029. No está implementado: queda a decisión del owner.

## `web` comparte la red de `api`

`web` usa `network_mode: service:api`, es decir, el espacio de red de la instancia concreta del contenedor `api`. Con el healthcheck y `depends_on: condition: service_healthy`, `docker compose up` ya no arranca `web` antes de que `api` responda.

Límite que se mantiene: si Docker **recrea** `api` después (cambio de imagen o de entorno), `web` queda unido a un espacio de red que ya no existe. `restart: unless-stopped` no lo arregla, porque `web` no termina. Recrear `api` implica reiniciar `web`: en Dokploy basta un redespliegue de la aplicación completa, no solo de un servicio. Si eso resulta incómodo, las salidas son fundir ambos procesos en una imagen o añadir un supervisor de contenedores no saludables. Ninguna se ha implementado.

## Observación de seguridad del servidor

Los `.env` que Dokploy escribe junto a cada compose (`/etc/dokploy/compose/*/code/.env`) tienen modo `644`: cualquier usuario local del VPS puede leerlos. Contienen las contraseñas de base de datos y de Keycloak. Restringirlos a `600` es un cambio en el servidor; se propone, no se aplicó.
