# Arquitectura del servicio de verificación de credenciales

Estado: diagramas del servicio de verificación de HukID (FEAT-004) tal como está en `develop` el **2026-11-17** (`e4fcf51`). Describen relaciones y estado de implementación; no son contrato normativo. Los detalles normativos están en el [contrato del núcleo](credential-verification-contract.md), el [perfil HukID](hukid-profile.md) §9–§10, [ADR-0030](../decisions/ADR-0030.md), [ADR-0031](../decisions/ADR-0031.md), [ADR-0033](../decisions/ADR-0033.md) y el [contrato OpenAPI de sesiones](../../src/platform/contracts/verification-sessions.openapi.json). El estado por tarea vive en [tasks.md](../features/FEAT-004-credential-verification/tasks.md); si difiere de este documento, manda `tasks.md`.

Leyenda de color: verde, hecho y probado; amarillo, hecho sin conectar; rojo, falta; gris, actor externo al servicio.

## 1. Arquitectura

El servicio es un módulo del binario `cmd/api` ([ADR-0031](../decisions/ADR-0031.md) #1). Los endpoints del wallet son públicos; los del tenant exigen token de operador con MFA reciente.

```mermaid
flowchart LR
  subgraph TEN["Tenant: comercio que contrata el servicio"]
    OP["Operador<br/>token + MFA reciente"]
    CON["Consola React<br/>sin pantalla de verificación"]
  end
  subgraph WAL["Wallet: HukID u otra compatible"]
    APP["App del usuario<br/>guarda la credencial<br/>firma la presentación"]
  end
  subgraph PLAT["Binario único src/platform/cmd/api"]
    direction TB
    H1["privateapi.VerificationHandler<br/>POST verification-sessions"]
    H2["GET verification-sessions/id<br/>solo en el contrato"]
    W1["oid4vphttp<br/>GET /oid4vp/request/state"]
    W2["oid4vphttp<br/>POST /oid4vp/response"]
    OID["internal/oid4vp<br/>sesión, request object, JWE"]
    CORE["internal/verification<br/>núcleo puro"]
    RES["Results de producción<br/>complete_session"]
    JW["jwksresolver<br/>clave del emisor"]
  end
  subgraph DB["PostgreSQL"]
    S["verification.sessions<br/>RLS por tenant"]
    C["verification.verifier_configs<br/>client_id y response_uri"]
    R["replay persistente<br/>solo hash"]
  end
  LAB["Montaje de laboratorio<br/>cmd/api/oid4vplab.go"]

  OP -- "1 POST start" --> H1
  CON -. "T11-e diferida" .-> H2
  OP -- "9 GET resultado" --> H2
  H1 --> C
  H1 --> S
  H1 -- "2 launchUri" --> OP
  OP -. "3 QR o enlace" .-> APP
  APP -- "4 GET request object" --> W1
  APP -- "6 POST respuesta cifrada" --> W2
  W1 --> OID
  W2 --> OID
  OID --> CORE
  CORE -.-> JW
  CORE --> R
  OID --> RES
  RES --> S
  H2 --> S
  LAB -. "único lugar donde hoy están montados" .-> W1
  LAB -.-> W2

  classDef done fill:#d7efdd,stroke:#2f8f55,color:#17502b
  classDef wired fill:#fdf0cf,stroke:#b8860b,color:#6a4b00
  classDef todo fill:#f9dcdc,stroke:#b84545,color:#7a1f1f
  classDef ext fill:#e5e9f0,stroke:#7b879b,color:#243044
  class CORE,OID,W1,W2,S,C,R,LAB done
  class H1,JW wired
  class H2,RES todo
  class OP,CON,APP ext
```

## 2. Flujo completo con el wallet

Los pasos 8 y 9 (completar la sesión y consultar el resultado) y la resolución real de la clave del emisor son los que hoy no están conectados.

```mermaid
sequenceDiagram
  autonumber
  actor Op as Operador del tenant
  participant API as Plataforma cmd/api
  participant DB as PostgreSQL
  actor W as Wallet
  participant EM as Emisor

  Op->>API: POST /v1/operator/tenants/t/verification-sessions
  Note over API: Bearer válido, MFA reciente,<br/>capacidad verification:start,<br/>cuerpo estricto
  API->>DB: lee verifier_configs e inserta sesión pending
  API-->>Op: 201 sessionId, launchUri, expiresAt
  Op-->>W: QR o enlace openid4vp fuera de HukID
  W->>API: GET /oid4vp/request/state
  API-->>W: request object ES256<br/>nonce, state, response_uri, DCQL, JWK de cifrado
  Note over W: comprueba al verifier,<br/>pide consentimiento,<br/>firma la VP con la clave de cnf.jkt
  W->>API: POST /oid4vp/response con JWE
  API->>EM: resuelve la clave pública del emisor
  Note over API,EM: jwksresolver existe pero no está integrado
  API->>API: descifra, verifica VC y VP, consume anti-replay
  API->>DB: complete_session con códigos y digest
  Op->>API: GET .../verification-sessions/id
  API-->>Op: pass o fail, códigos, digest, fechas
```

## 3. Capas y regla de imports

[ADR-0030](../decisions/ADR-0030.md): el módulo del wallet no puede importar `internal/authentication`. Solo el adaptador autenticado entrega al módulo el cliente, la URI de respuesta y el tenant ya autorizado.

```mermaid
flowchart TB
  subgraph AUTH["Con autenticación de operador"]
    PA["privateapi<br/>VerificationHandler"]
    AU["internal/authentication<br/>y tenancy"]
    PS["postgres<br/>VerificationStartStore"]
  end
  subgraph MOD["Módulo sin autenticación de operador"]
    HT["adapters/oid4vphttp"]
    OV["internal/oid4vp"]
  end
  subgraph LIB["Librería pura sin red ni base de datos"]
    VE["internal/verification"]
  end
  subgraph INF["Infraestructura"]
    PR["postgres.ReplayStore"]
    JR["adapters/jwksresolver"]
    MIG["migraciones 0012 y 0013"]
  end

  PA --> AU
  PA --> PS
  PA -- "ClientID, ResponseURI, TTL" --> OV
  HT --> OV
  OV --> VE
  VE -. "puerto ReplayStore" .-> PR
  VE -. "puerto IssuerKeyResolver" .-> JR
  PS --> MIG
  PR --> MIG
  OV -. "NO importa" .- AU
  HT -. "NO importa" .- AU

  classDef done fill:#d7efdd,stroke:#2f8f55,color:#17502b
  classDef wired fill:#fdf0cf,stroke:#b8860b,color:#6a4b00
  class OV,HT,VE,PR,MIG,AU done
  class PA,PS,JR wired
```

## 4. Estados de una sesión

La base solo guarda `pending` y `completed`. `expired` se deriva de `expires_at` al leer. Una sesión se completa una sola vez y solo si sigue vigente.

```mermaid
stateDiagram-v2
  [*] --> pending: POST start, vence en 60 a 900 s
  pending --> completed: complete_session una sola vez y vigente
  pending --> expired: pasa expires_at, derivado al leer
  completed --> [*]: purga acotada por retención
  expired --> [*]: purga acotada por retención
  note right of completed
    Guarda resultado pass o fail,
    códigos cerrados y digest.
    Nunca JWS, claims, nonce ni state.
  end note
```

## Estado por componente (2026-11-17)

| Componente | Estado | Detalle |
| --- | --- | --- |
| `internal/verification` | Hecho | Seis checks técnicos y 21 códigos cerrados. `status` y `schema` salen como `skipped` (VER-T09 y VER-T13). |
| `internal/oid4vp` y `oid4vphttp` | Hecho | Montados solo en el laboratorio. Una clave de firma por proceso. |
| Migraciones 0012 y 0013 | Hecho | Replay persistente y sesiones con RLS por tenant. Sin columnas de clave. |
| Capacidades `verification:*` | Hecho | Para `tenant_admin` y `security_admin`; el inicio exige MFA. |
| `VerificationHandler` (inicio) | Hecho, sin conectar | Probado con Postgres real; `cmd/api` no lo referencia. |
| `jwksresolver` | Hecho, sin conectar | Probado con un servidor TLS local; no integrado ni probado contra un JWKS real. |
| `Results` de producción y mapa `state` a `session_id` | Falta | El laboratorio solo imprime el reporte en la terminal. |
| Lectura (`GET`) y replay por tenant | Falta | La lectura solo existe en el contrato. |
| Clave de firma por tenant | Falta | Custodia abierta ([ADR-0033](../decisions/ADR-0033.md) #7). Bloquea el montaje en producción. |
| Pantalla en la consola | Falta | [ADR-0031](../decisions/ADR-0031.md) #2: la primera será de solo lectura (VER-T11-e). |

Las credenciales y los vectores son sintéticos: no hay interoperabilidad probada con un wallet, emisor o verifier externo. Completar este servicio no cierra el conformance gate del [perfil](hukid-profile.md) §12.
