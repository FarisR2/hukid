# HukID — Documento de Entrega Técnica (Handover) y Plan de Continuidad

**Repositorio del Fork:** [github.com/juanrmos/hukid](https://github.com/juanrmos/hukid)  
**Rama Activa de Desarrollo:** `feat/credential-issuance-mvp`  
**Repositorio Upstream (Base):** [github.com/paultarazona/hukid](https://github.com/paultarazona/hukid) (`develop`)  
**Fecha de corte:** Noviembre 2026  
**Estado:** Backend de Emisión y Verificación MVP (Fases 0 a 4) 100% implementado y verificado.

---

## 1. Visión General del Proyecto

**HukID** es una plataforma de identidad digital soberana y credenciales verificables basada en estándares abiertos:
- **OID4VCI (OpenID for Verifiable Credential Issuance):** Protocolo de emisión de credenciales hacia billeteras digitales de usuarios.
- **OID4VP (OpenID for Verifiable Presentations):** Protocolo de presentación y verificación descentralizada de credenciales.
- **W3C VC-JWT:** Formato de credenciales verificables con firma criptográfica ES256 (`ecdsa-p256`).
- **W3C Bitstring Status List v1:** Mecanismo de privacidad y alta escala para suspensión y revocación de credenciales sin revelar la identidad del titular.

---

## 2. Estado de la Implementación (Qué está hecho)

Todo el trabajo actual reside en la rama `feat/credential-issuance-mvp` en `github.com/juanrmos/hukid` con 5 commits verificados:

| Hash | Módulo / Componente | Descripción |
| :--- | :--- | :--- |
| `f7a73b2` | `internal/verification` (`VER-T13`) | Validador JSON Schema formal para credenciales y resolver HTTP/HTTPS de esquemas externos. |
| `bebbb83` | `internal/issuance` (Etapa A) | Cancelación de solicitudes (`DELETE /v1/issuance-requests/{id}`), emisión diferida (`deferred_credential`), hosting público de esquemas/contextos (`/{slug}/schemas/...`) y reporte de compromiso de llaves (`HK-052`). Migración `0016`. |
| `c7a7afd` | `internal/adapters/vaultkms` | Adaptador KMS para HashiCorp Vault Transit: aprovisionamiento no exportable `ecdsa-p256`, firma remota delegada y cifrado envelope (KEK) para llaves de respaldo. |
| `c47904f` | `privateapi` & `postgres` (Etapa B) | APIs administrativas completas (issuers, rotación de llaves, definiciones de credenciales, clientes de integración y auditoría) con aislamiento multi-tenant RLS, MFA step-up y validación ETag (`If-Match`). |
| `3292874` | `cmd/api` & `contracts/` | Montaje productivo en el servidor HTTP principal, validación estricta de TLS en staging/producción, contrato OpenAPI unificado `issuance-v1.openapi.json` y tests de conformidad contractual. |

### Estado de Calidad y Pruebas
- **Go Tests:** 19/19 paquetes pasando (`cmd/api`, `postgres`, `vaultkms`, `privateapi`, `oid4vcihttp`, `issuance`, `verification`, etc.).
- **PostgreSQL 18.6:** Tests de integración con aislamiento estricto y Row-Level Security (`FORCE RLS`) 100% pasando.
- **Formateo y Tipado:** `gofmt -l .` limpio, `go vet ./...` limpio, `tsc --noEmit` de la consola limpio.
- **Documentación:** 146 archivos Markdown y 1378 enlaces locales validados (`npm run check:docs`).

---

## 3. Instrucciones de Onboarding para el Nuevo Colaborador

### 3.1. Requisitos Previos
- **Git** configurado con nombre y correo de GitHub.
- **Go 1.22+** (o versión recomendada en `go.mod`).
- **Node.js 20+** y `npm`.
- **Docker** o **PostgreSQL 16+** para pruebas de integración con RLS (opcional si solo trabaja en frontend o pruebas unitarias de Go).

### 3.2. Clonar y Configurar el Repositorio
```bash
# 1. Clonar el fork personal
git clone https://github.com/juanrmos/hukid.git
cd hukid

# 2. Configurar el upstream para mantenerse al día con el repo base del docente
git remote add upstream https://github.com/paultarazona/hukid.git
git fetch upstream

# 3. Moverse a la rama de trabajo donde está todo el desarrollo
git checkout feat/credential-issuance-mvp

# 4. Instalar dependencias de pruebas y consola
npm install
cd src/console && npm install && cd ../..
```

### 3.3. Cómo Ejecutar las Pruebas de Verificación
```bash
# Pruebas unitarias de Go en memoria (rápidas, no requieren base de datos)
go test -count=1 ./src/platform/...

# Verificación de contratos OpenAPI y capacidades
npm run test:auth

# Verificación de TypeScript en la consola web
npm run check:console

# Verificación de consistencia de documentación Markdown
npm run check:docs

# Pruebas de integración completas contra PostgreSQL (si Docker/PostgreSQL está disponible)
npm run test:postgres
```

---

## 4. Mapa de la Arquitectura y Código Fuente

```
hukid/
├── HANDOVER.md                       # Guía de entrega y tareas pendientes
├── src/
│   ├── console/                      # Consola Web (React 18 + TypeScript + Vite)
│   │   ├── src/
│   │   │   ├── navigation.ts         # Menús laterales (rutas con soon: true a implementar)
│   │   │   ├── views/                # Pantallas actuales (overview, audit, tenants)
│   │   │   └── api/                  # Clientes fetch hacia el backend
│   └── platform/                     # Backend Principal (Go)
│       ├── cmd/api/                  # Punto de entrada HTTP y montaje de servicios
│       │   ├── runtime_services.go   # Ensamblado de emisores, verificadores y KMS
│       │   └── auth.go               # Middlewares de tenancy, bearer token y MFA step-up
│       ├── contracts/                # Contratos y especificaciones OpenAPI
│       │   ├── capabilities.json     # Matriz de permisos (roles.tenant_admin: issuers/definitions/clients:manage)
│       │   ├── issuance-v1.openapi.json # Contrato OpenAPI formal de emisión v1
│       │   └── console-auth.openapi.json
│       ├── internal/
│       │   ├── issuance/             # Núcleo de dominio de emisión (RFC 0033 / OID4VCI)
│       │   ├── verification/         # Verificador OID4VP y JSON Schema (VER-T13)
│       │   └── adapters/             # Adaptadores de infraestructura
│       │       ├── postgres/         # Stores SQL transaccionales con RLS
│       │       │   └── migrations/   # Scripts SQL 0001..0016
│       │       ├── privateapi/       # Endpoints HTTP administrativos para la consola
│       │       ├── oid4vcihttp/      # Endpoints públicos OID4VCI (well-known, credential, offer)
│       │       └── vaultkms/         # Cliente HTTP HashiCorp Vault Transit
```

---

## 5. Lista Priorizada de Tareas Pendientes (Roadmap de Trabajo)

El colaborador puede seleccionar cualquiera de las siguientes tareas según su perfil y especialidad:

### 1. UI de Emisión en la Consola Web (Frontend React/TS)
* **Perfil:** Frontend / Full-stack Developer.
* **Archivos Clave:** `src/console/src/navigation.ts`, `src/console/src/views/`, `src/console/src/api/`.
* **Objetivo:**
  * Actualmente en `navigation.ts`, las secciones de **Emisión** (`emisores`, `definiciones`, `solicitudes`, `credenciales`) y **Ajustes** están deshabilitadas con `soon: true`.
  * Diseñar y programar las pantallas en React + TypeScript que consuman los endpoints ya creados y testeados en `src/platform/internal/adapters/privateapi/issuance_admin.go`:
    1. **Vista de Emisores (`/issuers`):** Listar emisores del tenant, crear nuevo emisor (slug, display_name), botón de "Rotar Llave KMS", botón de "Reportar Llave Comprometida".
    2. **Vista de Definiciones de Credencial (`/definitions`):** Listar plantillas, crear borrador, editar esquema JSON y publicar versión inmutable.
    3. **Vista de Clientes de Integración (`/clients`):** Registrar clientes que pueden solicitar emisiones (como la Plataforma de Eventos de la UNAS), generar tokens y rotar credenciales.
    4. **Vista de Credenciales y Solicitudes (`/issuance-requests`):** Ver el estado de emisiones pendientes, emitidas, revocadas o suspendidas, con opción de revocar credencial en Bitstring Status List.

### 2. Definición Canónica del Certificado Académico / Eventos (Fase 5)
* **Perfil:** Backend / Arquitecto de Datos.
* **Archivos Clave:** `src/platform/internal/adapters/postgres/seeds/` o migración `0017`.
* **Objetivo:**
  * Crear la definición formal inmutable de la credencial universitaria `pe.edu.certificate.vc-jwt.v1` / `unas-certificate`.
  * Esquema JSON Schema estricto: datos del participante (`recipient_name`, `recipient_id`), del evento (`event_name`, `event_date`, `academic_hours`, `participation_role`) y hash criptográfico (`pdf_sha256`) del certificado digital en PDF emitido por el Equipo 4.
  * Validar que se aloje automáticamente en `/{slug}/schemas/pe.edu.certificate.vc-jwt.v1/1.0.0.json`.

### 3. Conectar Métricas Reales en el Overview del Dashboard (Fase 6)
* **Perfil:** Backend Go / SQL Developer.
* **Archivos Clave:** `src/platform/internal/adapters/postgres/dashboard_store.go`, `src/platform/internal/dashboard/`.
* **Objetivo:**
  * Hoy las métricas `activeIssuers`, `publishedDefinitionVersions`, `createdRequests`, `issuedCredentials` y `pendingStatusChanges` devuelven el estado `source_not_connected`.
  * Implementar las queries SQL directas sobre las tablas `definition.credential_definitions`, `issuance.issuance_requests`, `status.status_lists` y `status.issued_credentials` para retornar números reales agregados por tenant.

### 4. Billetera Móvil (Wallet Flutter / HK-D)
* **Perfil:** Flutter / Mobile Developer.
* **Objetivo:**
  * Desarrollar la aplicación móvil para el estudiante/asistente:
    1. Escanear el QR de *Credential Offer* generado por la Plataforma de Eventos o HukID.
    2. Generar un par de claves en el hardware seguro del teléfono (Keystore/Secure Enclave).
    3. Solicitar la credencial a HukID enviando el DPoP / `cnf.jkt` (Proof-of-Possession).
    4. Guardar la credencial VC-JWT localmente.
    5. Presentar la credencial vía OID4VP ante el verificador escaneando una solicitud QR.

---

## 6. Consideración Crítica para el Merge a Upstream (`develop`)

En el repositorio central del docente (`paultarazona/hukid`, rama `develop`), se incorporó el commit `5fbc13e` con la migración `0013_verification_sessions.sql`.  
En nuestra rama usamos provisionalmente los prefijos `0013` a `0016`.  
**Antes de enviar el Pull Request a `upstream/develop`**, es necesario renombrar:
- `0013_issuer_foundation.sql` → `0014_issuer_foundation.sql`
- `0014_issuance_core.sql` → `0015_issuance_core.sql`
- `0015_status_lists.sql` → `0016_status_lists.sql`
- `0016_etapa_a_lifecycle_and_schemas.sql` → `0017_etapa_a_lifecycle_and_schemas.sql`  
Y actualizar las referencias numéricas en los tests de migraciones correspondientes.
