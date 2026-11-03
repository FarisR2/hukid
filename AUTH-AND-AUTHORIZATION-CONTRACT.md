# Contrato de autenticación y autorización

## Ownership

El Equipo 1 integra un proveedor OIDC. La plataforma no almacena contraseñas. Platform Foundation posee tenant directory, organizaciones, membresías, roles, invitaciones, sesiones de aplicación, service accounts, gateway y librerías de autorización. Cada servicio sigue siendo responsable de autorizar sus recursos.

## Flujos humanos

1. React/Astro inicia Authorization Code + PKCE.
2. Callback valida `state`, `nonce`, issuer, audience y PKCE.
3. El backend crea sesión segura mediante cookie `HttpOnly`, `Secure`, `SameSite=Lax`; no guarda access tokens en `localStorage`.
4. Refresh rota identificador; reutilización revoca la familia de sesión.
5. Logout revoca sesión local y ejecuta RP-initiated logout cuando el IdP lo soporte.
6. Recuperación de contraseña/cuenta y MFA se ejecutan en el IdP; la plataforma conserva sólo estado de verificación y auditoría.
7. Roles privilegiados (`org_owner`, `security_admin`) exigen MFA y autenticación reciente para cambios de miembros, dominios, claves o exports sensibles.

### Política de sesión MVP

- TTL inactivo: 8 horas; TTL absoluto: 30 días; autenticación reciente privilegiada: máximo 10 minutos.
- La cookie contiene sólo un identificador opaco; la sesión y refresh family se almacenan server-side con hash.
- Refresh rotation es transaccional. Reutilizar un refresh ya rotado revoca toda la familia en menos de 60 segundos.
- Suspender usuario, membresía u organización invalida autorización y sesiones afectadas en menos de 60 segundos.
- `POST /auth/logout` siempre termina la sesión local aunque falle el logout federado; logout global revoca todas las familias.
- Redirects pertenecen a una allowlist exacta. Callback, recuperación o MFA nunca aceptan un destino arbitrario.

### Participante no administrativo

El participante no recibe roles de backoffice. Consulta, edición permitida, ticket y cancelación usan una sesión de participante o enlace firmado de propósito único ligado a `registration_id`, action, audience y TTL máximo de 30 minutos. El token es one-use para mutaciones, no permite enumeración y una respuesta neutral protege la existencia de emails/registros.

### Endpoints BFF normativos

| Operación | Semántica |
|---|---|
| `GET /auth/login?return_to=` | crea state/nonce/PKCE server-side y redirige al IdP; `return_to` allowlisted |
| `GET /auth/callback` | valida state/nonce/code/issuer; vincula `(issuer,sub)`; crea cookie y redirige |
| `POST /auth/refresh` | exige cookie + CSRF; rota familia; devuelve cookie nueva, `204` |
| `POST /auth/logout` | exige CSRF; revoca sesión; limpia cookie; idempotente |
| `POST /auth/logout-all` | sesión + MFA reciente; revoca todas las familias del usuario |
| `GET /platform/v1/me` | identidad proyectada, organización activa, roles, capabilities, `auth_time` |
| `GET /platform/v1/me/sessions` | sesiones enmascaradas; nunca refresh/token |
| `DELETE /platform/v1/me/sessions/{id}` | revoca sesión propia o con scope administrativo |

Todos los endpoints auth responden `Cache-Control: no-store`, no registran códigos/tokens y usan `application/problem+json` para errores.

## Claims internos

```json
{
  "sub": "oidc-subject",
  "sid": "session-id",
  "organization_id": "uuidv7",
  "membership_id": "uuidv7",
  "roles": ["event_manager"],
  "scopes": ["events:write"],
  "aud": "event-configuration-api",
  "amr": ["pwd", "mfa"],
  "iat": 0,
  "exp": 0
}
```

`organization_id`, roles y scopes se derivan de membresía activa; nunca del body o header proporcionado por el navegador.

## Roles iniciales

| Rol | Capacidades principales |
|---|---|
| `org_owner` | configuración institucional, miembros, dominios y toda capacidad operativa |
| `security_admin` | miembros, sesiones, auditoría y service accounts; no edita contenido por defecto |
| `site_editor` | sitios, CMS, medios y publicación de páginas |
| `event_manager` | eventos, agenda, forms, participantes y comunicaciones |
| `application_reviewer` | admisibilidad/postulaciones asignadas; no ve exports globales |
| `checkin_staff` | check-in/out en eventos/sedes asignados |
| `checkin_supervisor` | además registra void y gestiona dispositivos |
| `report_viewer` | dashboards y reportes autorizados |

Los permisos son unión de roles menos restricciones por evento/sede. Denegación es el valor por defecto.

## Service-to-service

- OAuth client credentials o workload identity + mTLS.
- Token con `sub=service:<name>`, audience exacta, scopes mínimos y organización cuando el trabajo sea tenant-scoped.
- Ningún servicio reenvía tokens humanos a otro servicio como identidad propia.
- Consumers de eventos validan productor/topic/schema y comparan `organization_id` con la partición/proyección destino.

## Matriz de scopes

| Scope | Servicios/rutas |
|---|---|
| `organizations:admin` | organizaciones, miembros, invitaciones, roles y dominios |
| `sites:write`, `sites:publish` | CMS, medios, preview y publicación |
| `events:write`, `events:publish` | eventos, agenda, forms y releases |
| `participation:read`, `participation:manage` | registros, equipos, postulaciones y admisibilidad |
| `registration:self` | consulta/cancelación del registro propio |
| `onsite:checkin`, `onsite:void` | check-in/out y compensación por evento/sede |
| `communications:send` | campañas transaccionales y plantillas |
| `reports:read`, `reports:export_sensitive` | dashboards y exports; el segundo exige MFA reciente |
| `certificates:issue`, `certificates:revoke` | certificados y request HukID |

## Respuestas de seguridad

- `401`: token/sesión ausente, vencida o inválida.
- `403`: identidad válida sin permiso; no se revela PII.
- `404`: recurso tenant-scoped ajeno o inexistente para evitar enumeración.
- `409`: invitación, dominio, membership o estado en conflicto.
- Toda denegación sensible crea auditoría con actor, organización, acción, target opaco y request ID; nunca token ni claims personales.
