# Administración del issuer en la consola

Estado: incremento técnico parcial en `feat/credential-issuance-mvp`; aún no es un gate de producto ni completa el piloto. El contrato privado de Management está en [issuance-v1.openapi.json](../../src/platform/contracts/issuance-v1.openapi.json). El alcance y tareas están en [FEAT-005](../features/FEAT-005-issuer-operations/spec.md); Management administrativo se mantiene separado del contrato de emisión para clientes de integración.

## Acceso desde el navegador

La consola llama `GET /console/api/tenants/{tenantId}/{managementPath}` para lecturas y usa la misma ruta con `POST`, `PUT` u otros métodos explícitos del Management API para comandos. El BFF resuelve la sesión server-side, verifica de nuevo el operador y su contexto, exige que `tenantId` coincida con el tenant activo y conserva el token operator fuera del navegador. Para comandos valida `Origin` y `X-CSRF-Token`; Management vuelve a evaluar capability, asignación de issuer, MFA reciente e idempotencia según el contrato de cada operación. El BFF monta sólo el mux privado de administración de issuer; no funciona como proxy general.

Las pantallas conectadas cubren emisores y claves, versiones de credential definition, clientes de integración, solicitudes y credenciales. Los nuevos listados usan `limit`/`offset` (1–100, default 50), orden estable y resúmenes allowlisted. El secreto de un cliente se muestra una vez. La consola no presenta claims, secretos almacenados, digest de credencial ni URI/códigos de oferta.

## Límites del incremento

- Los endpoints administrativos de listado existen y exigen `issuance:read`; esa capability está reservada y no se concede a roles actuales según el [contrato DASH](console-dashboard-contract.md). Las vistas no están habilitadas a perfiles actuales hasta aprobar la política y actualizar su ADR/matriz. La consulta del cliente de integración sigue separada.
- No hay acciones de operador para suspender, reactivar o revocar credenciales. El status actual autoriza al cliente de integración con `status:write`; no se adapta con una identidad sintética de cliente.
- El editor de definitions no establece los claims de un producto. Para POS, ADR-0031 prioriza el comprobante, pero deja la semántica SUNAT y el payload abiertos.
- No se implementan una wallet Flutter ni el adaptador Events→HukID de Team 4. La reconciliación v0 sigue siendo polling; HukID no consume el bus Events ni comparte su base de datos.

El Management API aplica permisos de operador y tenant al recibir la petición reenviada por el BFF. El contrato aditivo define listados metadata-only y `issuance:read`; su grant sigue pendiente. Cualquier acción de status para operador necesita política, MFA reciente, auditoría e idempotencia propias. POS payload, wallet/adaptador y recorrido autenticado quedan fuera del gate actual.
