# HukID Wallet — modelo de recepción de laboratorio

Primer incremento del paquete Flutter: modelo de vista previa y consentimiento.
La aplicación Android y sus pantallas se incorporan en la siguiente unidad.

## Alcance

- Una vista previa no solicita ni guarda una credencial.
- Solicitar requiere consentimiento explícito y sólo se ejecuta una vez por vista previa.
- Cancelar descarta el flujo e invalida respuestas tardías.
- El adaptador runtime no tiene emisor configurado ni confía en enlaces arbitrarios.
- No hay cámara, red, validación criptográfica, claves ni almacenamiento.
- Los adaptadores con datos ficticios existen sólo en pruebas.

## Comprobar

Desde la raíz con la imagen local existente y caché de paquetes preparada:

```sh
docker run --rm --network none --user 10001:1000 -e PUB_CACHE=/workspace/.pub-cache -v "$PWD/src/wallet:/workspace" hukid-wallet-dev:local bash -eu -c 'umask 002; flutter test --no-pub test/issuance_test.dart'
```

El paquete declara Flutter y `material_ui` 1.0.0 para la interfaz posterior;
`pubspec.lock` fija las dependencias. APK, builds y cachés están ignorados.
