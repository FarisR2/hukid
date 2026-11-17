# Events y HukID: del certificado a la credencial

Estado: diagramas de lectura, fechados el **2026-11-17**. Resumen visual de lo que ya documentan [api-contracts](api-contracts.md) (frontera Events→HukID), [ux-flows](ux-flows.md), [arquitectura](architecture.md), [events-integration](contracts/events-integration.md) y [events-architecture-spine](events-architecture-spine.md) (AD-11). No es contrato normativo ni prueba que el adaptador o la emisión estén implementados: el código de Events no está en este repositorio y la emisión HukID tampoco. Si difieren, mandan los documentos enlazados. Events y HukID siguen siendo productos independientes.

Para el resumen en una página de qué hace cada actor y cuáles son los dos momentos (recibir y demostrar), ver [Qué construimos](credential-verification-architecture.md#qué-construimos-en-una-página).

Leyenda de color: azul, Events; violeta, HukID; gris, actor externo.

## 1. Tres QR distintos

Cada QR nace en un sistema, usa otro protocolo y cumple otro propósito. Solo el segundo y el tercero pertenecen a HukID. La documentación no relaciona el ticket de Events con los otros dos.

```mermaid
flowchart LR
  subgraph EV["Events"]
    T["Ticket QR<br/>JWS asimétrico, aud=onsite"]
    CK["Onsite<br/>check-in y asistencia"]
  end
  subgraph HK["HukID"]
    O["QR de oferta<br/>OID4VCI, credentialOfferUri"]
    V["QR o enlace de verificación<br/>OID4VP, launchUri"]
    W["Wallet"]
    VS["Servicio de verificación<br/>por tenant"]
  end
  P["Participante"]
  X["Verifier: comercio o tercero"]

  P -- "muestra" --> T
  T -- "valida firma, evento, revocación" --> CK
  O -- "la wallet lo escanea y recibe la credencial" --> W
  W -- "presenta la credencial" --> V
  V --> VS
  X -- "inicia la sesión" --> VS
  T -. "sin relación documentada" .- O
  T -. "sin relación documentada" .- V

  classDef ev fill:#d9ecf7,stroke:#2b7aa8,color:#11425e
  classDef hk fill:#e3dcf5,stroke:#6a54b8,color:#3a2a78
  classDef ext fill:#e5e9f0,stroke:#7b879b,color:#243044
  class T,CK ev
  class O,V,W,VS hk
  class P,X ext
```

## 2. Del certificado a la credencial

El adaptador del Equipo 4 traduce entre los dos contratos. HukID no consume el bus de Events ni comparte su base de datos. La reconciliación v0 es por polling; los webhooks son evolución posterior.

```mermaid
sequenceDiagram
  autonumber
  actor U as Usuario u organización
  participant EV as Events (Onsite y Operations)
  participant AD as Adaptador Team 4
  participant HK as HukID Platform
  participant W as Wallet

  EV->>EV: certificado PDF elegible y consentimiento
  U->>EV: solicita la credencial
  EV->>AD: POST /certificates/{id}/hukid-deliveries<br/>certificate_id, issuer_id, credential_definition_id, consent_id
  Note over EV,AD: el servidor de Events prepara los claims permitidos
  AD->>HK: POST /v1/issuance-requests + Idempotency-Key<br/>issuerId, credentialDefinition, claims, delivery, source
  HK-->>AD: id, offerState, issuanceState, credentialOfferUri, fechas
  AD-->>EV: registra referencia y estado
  EV-->>U: presenta o entrega la oferta (QR o enlace)<br/>canal por definir en el piloto
  U->>W: abre el enlace o escanea el QR de la oferta
  Note over W: valida URI, issuer y compatibilidad.<br/>Puede exigir autenticación o tx_code por otro canal
  W->>HK: OID4VCI con proof del holder
  HK-->>W: credencial vc+jwt, inmediata o diferida
  Note over W: verifica firma, binding, schema, tiempo y status.<br/>La guarda cifrada
  loop reconciliación por polling
    AD->>HK: GET /v1/issuance-requests/{id}
    HK-->>AD: estado actual
  end
```

## 3. Qué contiene el ticket QR de Events

Es un JWS firmado con una clave asimétrica. No lleva datos personales y su audiencia es solo el servicio de check-in ([events-integration](contracts/events-integration.md), sección Ticket y caché).

```mermaid
flowchart TB
  subgraph TK["Ticket QR de Events: JWS asimétrico"]
    direction TB
    H["Header: kid rotable"]
    C1["jti opaco, único por ticket"]
    C2["aud = onsite"]
    C3["organización y evento"]
    C4["scope"]
    C5["iat y exp: vigencia"]
    C6["versión"]
    N["Sin datos personales"]
  end
  PA["Participation<br/>único emisor y revocador"]
  ON["Onsite"]
  RV["Lista de revocación firmada<br/>máximo 15 s de antigüedad en línea"]
  UN["Un único check-in efectivo<br/>por ticket, evento y scope"]

  PA -- "emite" --> TK
  TK -- "se presenta en la entrada" --> ON
  RV --> ON
  ON -- "verifica firma, audience, evento, versión y revocación" --> UN

  classDef ev fill:#d9ecf7,stroke:#2b7aa8,color:#11425e
  class H,C1,C2,C3,C4,C5,C6,N,PA,ON,RV,UN ev
```

## Qué es de cada lado y qué falta

| Tema | Dueño | Estado |
| --- | --- | --- |
| Certificado PDF y consentimiento | Events | Operativo en su producto. |
| Adaptador Events a HukID | Events, Team 4 | Documentado como contrato; no está en este repo. |
| Solicitud de emisión y QR de oferta | HukID, Team 5 | Documentado; la emisión no está implementada en este repo. |
| Wallet | HukID, Team 5 | Flutter; no forma parte de este repo. |
| Servicio de verificación | HukID | Implementado en laboratorio; sin montar en producción. Ver la [arquitectura](credential-verification-architecture.md). |
| Credential definition de participación y claims mínimos | Por definir | Pendiente en [documentation-gaps](../05-delivery/documentation-gaps.md). Los ejemplos fiscales son ilustrativos. |
| Canal de entrega de la oferta y app no instalada | Por definir | Se decide en el piloto. |
| Autenticación del destinatario | Por definir | Necesaria para credenciales nominativas: escanear un QR no prueba identidad ([seguridad](../04-engineering/security.md)). |
| Uso del ticket QR como entrada del verifier | No documentado | Sería una decisión nueva: el ticket no es una presentación OpenID4VP. |

`organization_id` de Events y `tenant_id` de HukID no son equivalentes. El adaptador resuelve el vínculo autorizado entre ambos ([data-model](data-model.md)).
