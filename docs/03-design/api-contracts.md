# Contratos de APIs y protocolos

## Catálogo de referencia

| Ámbito | Documento de detalle |
| --- | --- |
| Events HTTP | [Catálogo de APIs](contracts/events-api-contracts.md) |
| Events eventos internos | [Envelope, topics, ordering y replay](contracts/events-event-contracts.md) |
| Events estados | [Máquinas de estado](contracts/events-state-machines.md) |
| Events dependencias | [Contratos de integración](contracts/events-integration.md) |
| HukID HTTP privado y ejemplos OpenID | [APIs HukID](hukid-api-contracts.md) |
| HukID reglas de interoperabilidad | [Perfil v0.1-draft](hukid-profile.md) |
| HukID consola — autenticación ejecutable de laboratorio | [Contrato y política](console-auth-contract.md), [OpenAPI propio](../../src/platform/contracts/console-auth.openapi.json); sus nueve operaciones están implementadas, con [interfaz AUTH-T08](console-auth-interface.md). |
| HukID consola — miembros USR-T01 y lecturas USR-T03 | [Contrato/políticas](console-members-contract.md), [OpenAPI propio](../../src/platform/contracts/console-members.openapi.json); [cuatro lecturas](console-members-directory.md) y [cuatro mutaciones de invitación](console-invitation-delivery.md) implementadas; USR-T05 conecta [dos aceptaciones](console-invitation-acceptance.md); USR-T06 conecta [dos PATCH de membresías](console-members-lifecycle.md). |
| HukID consola — persistencia USR-T02 | [Modelo, RLS y protocolo transaccional](console-members-persistence.md); no habilita rutas HTTP. |
| HukID consola — contratos futuros | [Dashboard](../features/FEAT-003-dashboard/plan.md) |

## Frontera Events→HukID

Events expone una solicitud de entrega sobre su certificado; el catálogo la identifica como POST /certificates/{id}/hukid-deliveries, con scope certificates:issue. Su entrada mínima es certificate_id, issuer_id, credential_definition_id y consent_id; el servidor prepara los claims permitidos.

El adaptador Team 4 traduce esa entrada al contrato HukID POST /v1/issuance-requests. HukID usa issuerId, credentialDefinition, claims, delivery y source; responde con ID, offerState, issuanceState, credentialConfigurationId, credentialOfferUri y fechas. Los ejemplos fiscales son ilustrativos de ese contrato; no constituyen la definition de participación Events.

En v0, el adaptador consulta GET /v1/issuance-requests/{id}. La documentación de wallet/backend fija polling como reconciliación final; los candidatos de webhook del catálogo HukID se mantienen como evolución posterior.

## Convenciones distintas

| Aspecto | Events | HukID |
| --- | --- | --- |
| JSON privado | snake_case | camelCase en ejemplos/API |
| Tenant interno | organization_id | tenant_id; issuer y client separados |
| Correlación HTTP | X-Request-Id y traceparent | X-Correlation-Id |
| Tokens | Audiences/scopes por servicio Events | Clases operator, integration, oid4vci y audiencias exactas del perfil |
| Errores | Problem Details y catálogo Events | Problem Details privado; errores OAuth/OpenID en endpoints estándar |

No normalizar silenciosamente ambos contratos. El adaptador hace traducción y correlación sin reenviar tokens humanos como identidad del sistema.

Las rutas /console/auth, /console/api y /v1/operator tienen baseline OpenAPI validada en AUTH-T02 según [ADR-0003](../decisions/ADR-0003.md). AUTH-T04 implementa login/callback y AUTH-T05 [lecturas /me/context](console-operator-context.md) de laboratorio; AUTH-T06 añade [refresh/logout y sesión](console-session-lifecycle.md); AUTH-T07 implementa [step-up y tenant-context](console-reauthentication.md). AUTH-T08 conecta [pantallas y navegador](console-auth-interface.md), navegación JSON opcional de login/step-up y error HTML fijo del callback, conservando el 303 y Problem Details para sus consumidores originales. El BFF usa cookies para navegador; Management mantiene Bearer operator, clase y audience del perfil. El nuevo claim de procedencia humana y las restricciones del laboratorio se documentan en el contrato de consola; no reinterpretan auth Events ni OID4VCI.

## Estado de los artefactos

Los Markdown y ejemplos HTTP/JSON están incluidos. AUTH-T02 añade OpenAPI y JSON Schemas nuevos de consola, validados en laboratorio. El OpenAPI YAML original, AsyncAPI/JSON Schema de Events/otras superficies, vectores y archivos de ejemplo externos no están adjuntos. Esos contratos narrativos requieren sus propios artefactos y validación antes de integrarse. Ver [registro de pendientes](../05-delivery/documentation-gaps.md).
