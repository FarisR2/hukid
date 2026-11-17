# HukID · Wallet de demostración

Prototipo aislado y móvil en HTML, CSS y JavaScript, con interfaz en español. Permite explorar la recepción, custodia en memoria y presentación consentida de credenciales **ficticias**. No modifica Platform ni Console. No implementa Flutter ni demuestra conformidad con protocolos de credenciales.

## Abrir la demo

Desde la raíz del repositorio, con Python 3 instalado:

```sh
python3 -m http.server 4173 --bind 127.0.0.1 --directory src/wallet-prototype
```

Abre <http://127.0.0.1:4173>. Detén el servidor con `Ctrl+C`. Los módulos necesitan HTTP: no abras `index.html` mediante `file://`. No hace falta instalar dependencias ni iniciar otros productos.

## Recorrido recomendado

1. Pulsa **Explorar mi wallet** y selecciona PIN o biometría simulados. No se pide un PIN ni una huella.
2. En la wallet vacía, pulsa **Recibir credencial**. El escáner demo no usa cámara: elige un escenario y pulsa **Simular lectura**. También puedes introducir uno de los códigos de la tabla en **Usar enlace**.
3. Revisa emisor, firma, estado y contenido. Solo **Aceptar y guardar** modifica la wallet.
4. Abre la credencial. **Presentar credencial** permite revisar una solicitud de Biblioteca demo o probar una solicitud inválida. Revisa el documento completo, marca el consentimiento y pulsa **Compartir en simulación**. No se envía nada.
5. Prueba **Eliminar copia local**. La confirmación explica que eliminar no revoca y que la oferta no puede reutilizarse.
6. Consulta **Actividad**. En **Ajustes**, carga ejemplos sin duplicarlos o reinicia la demo con confirmación.

Volver o cancelar no guarda, elimina ni comparte. Las cancelaciones tampoco añaden actividad. Una oferta consumida sigue consumida aunque elimines su copia; reinicia la demo para repetirla. La carga de ejemplos usa la misma aceptación que el flujo normal y no restaura copias eliminadas.

## Entradas de ejemplo

| Entrada de oferta | Resultado simulado |
| --- | --- |
| `demo:campus` | Identidad universitaria; guardado explícito |
| `demo:workshop` | Constancia de taller; guardado explícito |
| `demo:expired-offer` | Oferta vencida; sin cambios |
| `demo:used-offer` | Oferta ya usada; sin cambios |
| `demo:untrusted` | Emisor no confiable; bloqueada incluso con firma hipotéticamente válida |
| `demo:invalid` | Firma inválida; sin cambios |
| `demo:expired` | Credencial vencida; sin cambios |
| `demo:offline` | Se puede guardar, pero el estado es **desconocido**, sin última comprobación; no permite presentar |
| Cualquier otro texto o URL | Enlace inválido; sin cambios |

También se acepta exactamente `https://demo.hukid.invalid/offer/<escenario>`, reemplazando `<escenario>` por el sufijo del código de la tabla (por ejemplo, `campus`). No se visita esa URL. Se toleran espacios al principio y al final, no otros cambios.

Presentación: `demo:library` es la única solicitud admitida por el modelo. La interfaz ofrece además `demo:invalid-presentation` para observar el rechazo. Otros identificadores también se rechazan. No se interpreta un QR, enlace ni dominio arbitrario como fuente de confianza.

## Límites que forman parte del diseño

- Todos los nombres, campos y fechas son sintéticos. No introduzcas datos personales, credenciales reales, claves, PIN ni tokens.
- PIN y biometría son **opciones de representación**, no mecanismos de seguridad. No hay autenticación, almacenamiento seguro, cifrado ni criptografía.
- Los resultados de firma, confianza, vigencia y solicitudes son escenarios deterministas, no comprobaciones técnicas. La confianza en el emisor se distingue de la firma. El estado offline nunca se presenta como vigente o actual.
- La presentación revela el **documento completo**, sin selección de campos. Se revisan destinatario, propósito y contenido antes del consentimiento. Compartir solo añade una entrada local de simulación.
- Eliminar afecta únicamente la copia de esta sesión; no revoca ni afecta a emisores o terceros.
- Estado solo en memoria: recargar o cerrar la pestaña pierde todo. Sin `localStorage`, cookies, sincronización ni recuperación. La actividad es una secuencia local, no un registro de auditoría ni prueba de entrega.
- No hay peticiones a APIs ni assets remotos. La política CSP bloquea conexiones de red desde la aplicación. No se solicitan permisos de cámara, biometría o portapapeles.
- El navegador carga archivos estáticos del servidor local. El servidor de Python es solo para desarrollo, no para publicación productiva.

## Diseño y accesibilidad

Identidad violeta (`#5027bc`), tinta ciruela (`#24173d`), lavanda (`#f3effb`), papel blanco y verde reservado a resultados demo. Tipografía de sistema: Avenir Next si está disponible, luego Trebuchet MS/Arial. Las credenciales son el foco táctil; emisor, tipo y titular tienen posiciones consistentes, con navegación de apoyo discreta. En escritorio se presenta un teléfono con contexto; en móvil ocupa el ancho disponible.

Botones principales de al menos 48 px, foco visible, formularios etiquetados, estados con texto y no solo color, navegación semántica y respeto a movimiento reducido. Las confirmaciones son páginas, no modales: el foco pasa al título tras navegar. Esto es intención de implementación, **no certificación de accesibilidad**.

## Comprobar

Con Node.js disponible, desde la raíz:

```sh
node --test src/wallet-prototype/model.test.mjs
node --check src/wallet-prototype/model.mjs
node --check src/wallet-prototype/app.mjs
git diff --check
```

Las pruebas usan `node:test` y la API pública del modelo: inicialización, rechazo sin mutación (incluidos contadores/actividad), vista previa sin guardado, consentimiento estricto, cancelación, todas las ramas de error de la tabla, copia offline, duplicados, eliminación, carga y reinicio. No escriben archivos temporales ni leen historial git.

No hay runner de navegador instalado en este workspace al implementar esta demo; no se ejecutaron pruebas E2E ni inspección por captura. Quedan por verificar manualmente: recorrido completo, teclado, lector de pantalla, contraste, zoom al 200 %, anchuras 320/390 px y escritorio, scroll y navegación inferior. Las pruebas de modelo no prueban renderizado ni clics reales.

## Archivos

- `index.html`: documento, contexto de escritorio y política de recursos.
- `styles.css`: tokens, tarjetas, estados y adaptación móvil.
- `model.mjs`: fixtures y reglas de estado, sin DOM ni servicios.
- `app.mjs`: rutas locales, vistas y eventos del prototipo.
- `model.test.mjs`: pruebas deterministas del modelo público.
