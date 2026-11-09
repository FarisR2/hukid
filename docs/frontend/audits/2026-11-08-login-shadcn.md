# Adaptación del acceso a shadcn/Base UI

Fecha: 2026-11-08. Owner autoriza adaptar flujo y estilos con la nueva biblioteca. Este incremento continúa la infraestructura local sin commit/push; conserva la [especificación AUTH](../../03-design/console-auth-interface.md), contratos y lógica de sesión/autorización/navegación. No implementa un IdP productivo ni formulario local de credenciales.

## Implementación

El panel de acceso y sus estados reutilizan Button, Field y Native Select de `base-nova`; Label y Separator llegan como dependencias de Field. Generados con CLI shadcn 4.23.0 después de `--dry-run` y `--view`. Se verifican APIs con skill global, MCP y documentación oficial Base UI; el MCP genérico sigue devolviendo Radix, por lo que se contrasta con la resolución local Base UI.

Button/Native Select/Label se adaptan a los tokens, controles de 48 px y foco existentes; FieldGroup conserva el espaciado del sistema. Sin Preflight ni cambios en los selectores de USR/DASH. La ayuda explica proveedor → organización → espacio autorizado, con el mismo orden en móvil. Sin nueva máquina de estados, requests, reintentos o almacenamiento.

Dependencias nuevas de este incremento: `class-variance-authority` 0.7.1 (Button/Field) y `lucide-react` 1.70.0 (flecha de Native Select). La CLI no las instaló al informar solo cn: se añadieron tras verificar los imports reales, en el workspace y lock raíz. Npm informa 0 vulnerabilidades. No se añade Data Table ni TanStack.

## Verificaciones

Revisión estática y visual contra la especificación AUTH y el design system del proyecto, usando la estructura documental existente. Rama `feature/shadcn-infrastructure`, HEAD base `2f98258`; cambios locales sin commit. No falta documentación esencial para el alcance de presentación revisado.

| Comprobación | Resultado |
| --- | --- |
| `npm run check:console` | Aprobado. |
| `npm run build:console` | Aprobado. CSS 28,62 kB / gzip 6,11 kB; JS 306,59 kB / gzip 98,35 kB. Advertencias de directivas de dependencias, sin error de compilación. |
| `npm run test:browser` | Ejecución final aprobada en 63,716 s. Login/callback, selección nativa por teclado, rotación, caducidad, revalidación entre pestañas, permisos, miembros y dashboard. |
| Foco y componentes | Prueba específica verifica Button real, Tab al login, outline solid de 3 px, altura ≥48 px, Native Select y error vinculado al selector. Sin campo password local. |
| Rendimiento sintético | LCP 316 ms, CLS 0,088146875, interacción máxima medida 48 ms. Dentro de los umbrales existentes; no es INP de campo. |
| Contraste | 24 pares en claro/oscuro aprobados. |
| Documentación y whitespace | `check:docs` y `git diff --check` aprobados. Advertencias LF/CRLF propias del checkout, sin errores. |
| Límites | Comparación de la máquina de estados, handlers y efectos antes/después idéntica. Clientes HTTP y navegación sin cambios; versiones previas del lock conservadas. |

La primera suite falló durante la caducidad de sesión forzada por el harness: una lectura pendiente podía desmontar Renovar sesión antes del clic. La repetición sin cambio de aplicación aprobó en 62,787 s. Se sincronizó únicamente esa prueba esperando networkidle antes de la mutación de laboratorio; la suite final pasó, sin relajar las aserciones de expiración. La revisión visual detectó también el borde nativo outset al omitir Preflight: se añadió border-style solid local a las primitivas antes de la ejecución final.

Capturas: 36 a 390 y 1280 px, claro/oscuro, incluyendo carga, acceso, selección inválida, acceso pendiente, contexto autenticado, errores y confirmación. Revisión visual de seis capturas finales: acceso en las cuatro combinaciones y selección en 390 claro/1280 oscuro. Sin regresiones observadas de composición, identidad, legibilidad o foco en esa muestra. Se comprobaron además reflow/objetivos táctiles de la suite existente en 320/360/768/1024/1440 y reflow equivalente al 200%.

- [Acceso móvil claro](2026-11-08-login-shadcn/screens/audit-login-390-light.png).
- [Acceso escritorio oscuro](2026-11-08-login-shadcn/screens/audit-login-1280-dark.png).
- [Selección móvil con error y foco](2026-11-08-login-shadcn/screens/audit-organization-selection-390-light.png).
- [Selección escritorio oscuro](2026-11-08-login-shadcn/screens/audit-organization-selection-1280-dark.png).

Capturas conservadas localmente y excluidas de Git, siguiendo la convención del repositorio. No se afirma cobertura visual manual de todos los estados de error HTTP.

## Veredicto: APROBADO para el alcance de laboratorio revisado

Sin hallazgos bloqueantes, altos, medios o bajos en el incremento evaluado. Las observaciones de toolchain, peso del bundle y cobertura no ejecutada permanecen explícitas; no se certifica WCAG ni preparación productiva. El JS gzip crece aproximadamente 17,69 kB respecto de infraestructura sola por el uso real de primitivas; no se añaden dependencias de datos, formularios o tablas.

## Matriz de trazabilidad

| Paso | Estado / componente | Acción documentada → implementada | Verificación |
| --- | --- | --- | --- |
| Comprobar sesión | loading / AuthConsole | Status y retiro de contexto privado → conservados | Suite, capturas y comparación de lógica. |
| Iniciar acceso delegado | anonymous / AuthConsole + Button | Iniciar sesión → mismo handler y redirección IdP | Login/callback real de laboratorio y teclado. |
| Elegir organización | authenticated sin tenant / Field + Native Select | Continuar → mismo submit, opciones y validación | Error asociado, foco, ArrowDown/Tab/Enter. |
| Acceso sin membresías | authenticated sin tenants | Comprobar acceso/cerrar → mismos handlers | Fixture de acceso pendiente y capturas. |
| Operar sesión | authenticated con tenant | Cambiar/verificar/renovar/cerrar → mismos callbacks | Rotación, cambio tenant, logout y revalidación. |
| Recuperar error | error / AuthConsole | Recuperación explícita → conservada | Fallos red/403, expiración y contexto anterior descartado. |

## Límites y reversión

La captura de credenciales/MFA sigue en el proveedor y el laboratorio mantiene identidad sintética. No se ha validado proveedor real, lector de pantalla, otros motores/dispositivos ni métricas de campo. El bundler avisa de directivas `use client` de dependencias dentro de una SPA; no se modifica node_modules ni se ocultan advertencias.

Para retirar este incremento conservando la infraestructura anterior: revisar y revertir solo el diff nuevo del render de AuthConsole, bases de componentes/ayuda CSS, pruebas y documentación; retirar las cinco primitivas si no tienen otros consumidores; retirar CVA/Lucide del workspace actualizando el lock raíz y repetir check/build/browser. No usar reset/clean global ni descartar los cambios previos de fases 1/2. Los snapshots previos están en `.cache/login-shadcn-before`.
