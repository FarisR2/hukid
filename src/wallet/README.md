# HukID Wallet — Android de laboratorio

Base Flutter nativa, no versión HTML. Conserva la dirección violeta y española del
[prototipo](../wallet-prototype/README.md), que no se modifica.

No hay emisor configurado: cualquier enlace devuelve integración no disponible;
no se visita, no establece confianza y no se descarga ni guarda una credencial.
No ingreses datos personales ni códigos reales. La vista de preview/consentimiento
se comprueba exclusivamente con un adaptador en tests. No hay cámara, criptografía,
almacenamiento ni permisos adicionales.
La previsualización no acredita firma, estado ni confianza criptográfica.

Identidad Android de laboratorio: `dev.example.hukid_wallet`; no es identidad de
publicación. El scaffold usa Flutter 3.50.0 de `hukid-wallet-dev:local` existente.

La UI importa `material_ui` **1.0.0**, paquete oficial del publisher `flutter.dev`,
en lugar del import Material del SDK deprecado en Flutter 3.50. Se conserva la
misma dirección visual. La versión directa es exacta y `pubspec.lock` fija las
dependencias transitivas (incluido `cupertino_ui`, requerido por Material; no es
una dependencia directa ni una nueva interfaz Cupertino).

## Checks

Desde la raíz, montar **sólo** `src/wallet` en `/workspace`, con la imagen existente.
El cache generado `.pub-cache/` está ignorado y autorizado dentro de esta unidad;
la resolución inicial necesita red para paquetes oficiales y toolchain, no para
peticiones de la app. El usuario Docker UID10001/GID1000 y `umask 002` conservan
escritura por el grupo compartido; no ejecutar como root ni cambiar permisos:

```sh
docker run --rm --user 10001:1000 -e PUB_CACHE=/workspace/.pub-cache -v "$PWD/src/wallet:/workspace" hukid-wallet-dev:local bash -eu -c 'umask 002; flutter pub get'
docker run --rm --network none --user 10001:1000 -e PUB_CACHE=/workspace/.pub-cache -v "$PWD/src/wallet:/workspace" hukid-wallet-dev:local bash -eu -c 'umask 002; flutter test --no-pub test/issuance_test.dart'
docker run --rm --network none --user 10001:1000 -e PUB_CACHE=/workspace/.pub-cache -v "$PWD/src/wallet:/workspace" hukid-wallet-dev:local bash -eu -c 'umask 002; flutter test --no-pub test/widget_test.dart'
docker run --rm --network none --user 10001:1000 -e PUB_CACHE=/workspace/.pub-cache -v "$PWD/src/wallet:/workspace" hukid-wallet-dev:local bash -eu -c 'umask 002; flutter test --no-pub'
docker run --rm --network none --user 10001:1000 -e PUB_CACHE=/workspace/.pub-cache -v "$PWD/src/wallet:/workspace" hukid-wallet-dev:local bash -eu -c 'umask 002; flutter analyze --no-pub'
```

Cancelar o volver descarta el consentimiento sin solicitar recepción. Aceptar
solicita como máximo una vez por preview; el único resultado de este corte es
pendiente o no disponible, nunca «verificada» o «guardada». La wallet sigue vacía.
Recepción real requiere issuer compatible, protocolo, validación, claves Android y
persistencia cifrada en unidades posteriores. No se ha probado un teléfono.
