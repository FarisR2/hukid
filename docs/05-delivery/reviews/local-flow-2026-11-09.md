# Validación del flujo local — 2026-11-09

## Dictamen

**Flujo local completo: NO APROBADO.** La regresión automatizada con OIDC sintético pasa, pero el ingreso con Keycloak real no crea una sesión. Los recorridos autenticados del perfil local quedan bloqueados por ese fallo.

Esta revisión ejecuta el plan de arranque, login, sesión, permisos, módulos y recuperación. No modifica la política ni la configuración de Keycloak para convertir resultados negativos en positivos.

## Revisión y entorno

- Base Git: `2f9825880820c9782e2b8460c871ac005f0c16a8`, con cambios locales previos.
- Gate iniciado: `2026-11-09T06:05:25.363Z`; finalizado: `2026-11-09T06:07:34.084Z`.
- Digest de fuentes del gate: `f07a37e3848279911b2a359e41499d3a4ba76824fc0b08d099ce79050531955e`.
- Windows x64; Node 24.22.1, npm 11.19.1, Go 1.27.3, PostgreSQL 18.6, Java Temurin 25.0.5 y Keycloak 26.8.2.
- Chromium headless mediante Python 3.15.2/Playwright.
- Perfil real: `local`, PostgreSQL persistente y Keycloak en loopback, según [ADR-0025](../../decisions/ADR-0025.md).

El gate identifica el árbol anterior a añadir este informe y su enlace en pendientes. No se alteró código de aplicación durante la validación. Los scripts auxiliares y los informes JSON permanecen en `.cache`, ignorada por Git.

## 1. Regresión automatizada

Se ejecutó `npm run test:dashboard:gate` con resultado `passed` y digest estable.

| Etapa | Resultado | Duración del runner |
| --- | --- | --- |
| check | Aprobado | 8,305 s |
| build | Aprobado | 3,704 s |
| test:postgres | Aprobado | 42,881 s |
| smoke | Aprobado | 0,843 s |
| test:browser | Aprobado | 72,513 s |

La primera invocación fue interrumpida por el límite de tiempo de la herramienta durante navegador, tras aprobar las cuatro primeras etapas. Se relanzó el gate completo con salida a archivos y se obtuvo el resultado anterior. No se tomó la ejecución interrumpida como aprobada.

El build emitió advertencias de bundling sobre directivas `use client`; terminó con código cero. No hubo suites omitidas en el gate final.

Alcance: contratos, Go/TypeScript, PostgreSQL/RLS/HTTP, regresión AUTH/USR/DASH y Chromium con OIDC/MFA sintéticos. Se conservan los límites del [gate D4](../dashboard-gate.md) y de la [estrategia de pruebas](../../04-engineering/testing-strategy.md).

## 2. Arranque y bootstrap reales

| Caso ejecutado | Resultado |
| --- | --- |
| start con API/consola ya activas | Rechazo por puerto ocupado |
| stop del entorno local | API y consola dejan de responder |
| start tras detener servicios | health 204 y consola 200 |
| Reinicio con datos existentes | Conteos de tenants, identidades, membresías y roles conservados |
| bootstrap con sesión kcadm caducada | Fallo: `Session has expired. Login again` |
| Autenticar kcadm y ejecutar bootstrap | Aprobado; vinculación inicial del operador local |
| Repetir bootstrap dos veces | Aprobado; mismos conteos en las cuatro tablas, sin duplicados |

Se repitió el ciclo stop/start después del bootstrap; persistencia y repetición idempotente volvieron a pasar. El entorno queda arrancado, como estaba al comenzar. No se reinicializó el clúster ni se regeneraron sus secretos.

**Fallo operativo:** `bootstrap` invoca `kcadm get users` usando una sesión administrativa persistida, sin autenticarla ni renovarla. Puede fallar aunque Keycloak esté activo y los secretos sean correctos. Actualizar explícitamente la sesión permitió continuar; esto no corrige la dependencia del script.

## 3. Login con Keycloak y TOTP reales

Se crearon identidades temporales exclusivas de validación, con contraseña aleatoria y acción CONFIGURE_TOTP. Se eliminaron mediante la API administrativa al terminar cada intento. No se usó ni se cambió la contraseña o el factor del operador existente. Los primeros intentos ajustaron selectores del harness; sólo los recorridos completos sustentan el resultado funcional siguiente.

| Caso ejecutado | Resultado |
| --- | --- |
| Abrir raíz sin sesión | Redirección automática a Keycloak |
| Contraseña incorrecta | Rechazada, sin cookie de sesión HukID |
| Contraseña válida y alta TOTP | Completadas en Keycloak |
| Retorno al callback BFF | Pantalla «No se pudo completar el acceso» |
| GET /console/api/me después del retorno | 401; sin cookie hukid_local_session |
| Respuesta privada | Cache-Control contiene no-store |
| Volver a HukID tras el error | «Acceso no completado», sin bucle automático inmediato |
| OTP incorrecto en ingreso posterior | Rechazado |
| OTP válido en intervalo posterior | Permite completar autorización del proveedor |
| Código OIDC con PKCE S256 | Canjeado correctamente en diagnóstico independiente |
| Reutilizar código ya canjeado | Keycloak devuelve 400 |
| Eliminar identidad temporal | Aprobado |

El diagnóstico independiente utiliza el mismo cliente, redirect registrado, scopes, `resource` y `acr_values=2`. Intercepta la redirección antes del BFF y canjea el código con su propio verifier PKCE; no fabrica sesiones ni sustituye la validación JWT del backend. Se inspeccionan header/payload en memoria para comparar configuración; esa inspección no es una prueba criptográfica independiente ni concede autoridad. No se guardan tokens, códigos, contraseñas ni secretos TOTP en los informes.

### Incompatibilidades observadas

| Propiedad | Exigencia vigente | Observado |
| --- | --- | --- |
| Firma de ID/access token | ES256 | RS256 en ambos |
| Métodos MFA | pwd y otp | amr vacío en ambos |
| Nivel de autenticación | acr 2 | acr 1 en ambos |
| Tipo del access token | at+jwt | JWT |
| Clase del access token | hukid_token_class=operator | Ausente |
| Grant del access token | hukid_grant=authorization_code | Ausente |

Fuentes de exigencias: [política local](../../../src/platform/config/auth.local.json) y [adaptador OIDC](../../../src/platform/internal/adapters/oidc/client.go). El backend rechaza algoritmos/tipos incompatibles antes de aceptar la evidencia MFA. Por tanto, el fallo del callback no se atribuye exclusivamente a acr/amr: existen varias incompatibilidades independientes.

Que Keycloak haya solicitado TOTP no demuestra que sus tokens expresen la evidencia que exige HukID. No se relajó ninguna validación ni se añadieron claims estáticos para simular factores.

## 4. Sesiones, permisos, módulos y recuperación

| Área | Evidencia ejecutada | Estado del perfil local real |
| --- | --- | --- |
| Refresh, logout, expiración y step-up | Gate HTTP/PostgreSQL/Chromium sintético | Bloqueado por falta de sesión local válida |
| Aislamiento entre tenants, roles y suspensión | Gate de regresión AUTH/USR/DASH | Bloqueado tras login real |
| Concurrencia, replay, CSRF, auditoría | Gate PostgreSQL/HTTP y contratos | No se acredita equivalente autenticado local |
| Miembros/invitaciones | Regresión USR acumulada | start no configura HUKID_MEMBERS_* ni entrega |
| Dashboard | Regresión DASH base acumulada | start no configura HUKID_DASHBOARD_* |
| Dependencias/errores/red/respuestas tardías | Suites existentes, con fallos reales o interceptados según cada escenario | No se ejecutó matriz completa de caídas con sesión Keycloak |
| Recuperación del proceso y datos | stop/start y consultas agregadas reales | Aprobado en alcance descrito |

El arranque local proporciona explícitamente las tres credenciales AUTH; no equivale a habilitar todos los módulos implementados. Los errores visuales interceptados de las suites no se presentan como caídas físicas de dependencias del perfil local.

## Evidencia y siguientes pasos

Artefactos locales ignorados:

- `.cache/dashboard-gate/latest.json`: gate acumulado aprobado.
- `.cache/validation-gate.stdout.log` y `.cache/validation-gate.stderr.log`: salida del gate completo.
- `.cache/local-runtime-validation.json`: último ciclo de arranque/persistencia/bootstrap aprobado con sesión administrativa vigente. El fallo previo de caducidad queda descrito arriba.
- `.cache/local-flow-validation.json`: login real fallido y propiedades diagnósticas observadas.
- `.cache/validate-local-runtime.py` y `.cache/validate-local-flow.py`: harnesses auxiliares locales. No forman parte de CI ni de una suite versionada.

Prioridad de resolución:

1. Acordar/configurar el perfil Keycloak compatible con el contrato operator: firma, tipo, clase, grant y evidencia real de MFA/LoA. Cambiar el contrato requeriría su decisión documental correspondiente.
2. Hacer reproducible la autenticación administrativa de bootstrap.
3. Repetir login real; después probar refresh/logout/step-up, permisos y recuperación con sesión válida.
4. Habilitar miembros/dashboard con sus roles y configuración explícitos y repetir la matriz local de ambos módulos.

No se declara validado el flujo local completo, CI remoto ni producción. Los casos bloqueados requieren una ejecución posterior; el gate sintético aprobado no los sustituye.
