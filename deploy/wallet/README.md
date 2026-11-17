# Toolchain Flutter/Android para el laboratorio

Imagen de desarrollo **Linux x64**, con Flutter, Dart, JDK y Android SDK oficiales,
usuario no-root y compilación Android comprobada con un proyecto default desechable.
Cubre solamente la preparación Android de T1/S1: **no contiene una wallet**, backend,
recepción de ofertas ni pruebas en teléfono. No acredita S2–S3 ni conformance.

## Construcción

Desde la raíz del repositorio:

```bash
git diff --check
docker build --check deploy/wallet
docker build --progress=plain --platform linux/amd64 -t hukid-wallet-dev:local deploy/wallet
docker run --rm --network none hukid-wallet-dev:local flutter --version
docker run --rm --network none hukid-wallet-dev:local dart --version
docker run --rm --network none hukid-wallet-dev:local java -version
```

La construcción requiere Docker disponible, red y varios GiB libres en el disco
**de Docker Desktop**, no sólo en WSL. El SDK Flutter comprimido ocupa
1 517 633 656 bytes; Android, extracción, etapas y caches requieren espacio adicional.
El build observado terminó dentro del límite de 1800 s; no se promete igual duración
ni reproducción bit a bit. APT y los paquetes Android resueltos por SDK Manager no
están fijados a snapshots. No ejecutar `flutter upgrade` ni cambiar su pin/hash.

## Licencia: autorización local explícita

El propietario aceptó los [términos Android SDK](https://developer.android.com/studio/terms)
con «dale mi compa» después de la pregunta explícita sobre aceptación, registro e
instalación estable en la imagen Docker local (T1, L17). El build aplica esa
aceptación únicamente a los paquetes seleccionados bajo `android-sdk-license`.
**Reconstruir esta imagen vuelve a aplicar esa aceptación local**; no supone
aceptación por otros usuarios ni autorización para publicar la imagen.

Se usa `sdkmanager --channel=0 --install` con una lista explícita y una respuesta
afirmativa; **no** se ejecuta `sdkmanager --licenses` ni se aceptan todas las licencias
del catálogo. El build exige que el único archivo de licencia sea
`licenses/android-sdk-license`. No instala emulator, system images ni previews.
No ejecutar `android init` ni instalar recursos sugeridos por el CLI para este smoke.

## Versiones y procedencia

| Componente | Fijación o versión observada |
| --- | --- |
| Ubuntu oficial 24.04 linux/amd64 | `sha256:77eb101c607d6e3d4f5ad0c8a02c2136c689b98aba1f359e6502ba517e5c57ec` |
| Flutter estable | `3.50.0`, commit `ab2912035e160d9cad6306df307576da6128ebdb` |
| Dart incluido | `3.14.0` |
| SHA256 del archivo Flutter | `6ea2d806fd57269ae783e6788e2a81fc26eaad782f1e0d0ff38623bb765ff9f5` |
| JDK Ubuntu, paquete `openjdk-21-jdk-headless` | `21.0.13.0.3+1-1-24.04.1-Ubuntu`, observado; APT no fija patch |
| Android command-line tools | `23.0`, archivo `commandlinetools-linux-16111833_latest.zip` |
| Platform tools / adb | `37.0.1-15733141` / `1.0.41`, observado en canal estable |
| Plataforma Android | API `36`, revisión `2` base, sin extensiones |
| Build Tools | `36.0.0`, default y mínimo de AGP 9.3 |
| NDK | `28.2.13676358` (r28c), default del Flutter fijado |
| Proyecto default generado, sin overrides de versiones | Gradle `9.5.0`, AGP `9.3.1`, Kotlin `2.4.20` |

Fuentes oficiales y compatibilidad:

- [Archivo Flutter](https://docs.flutter.dev/install/archive) y
  [manifiesto Linux](https://storage.googleapis.com/flutter_infra_release/releases/releases_linux.json).
- [Archivo Linux x64 fijado](https://storage.googleapis.com/flutter_infra_release/releases/stable/linux/flutter_linux_3.50.0-stable.tar.xz).
- [Ubuntu oficial](https://hub.docker.com/_/ubuntu).
- [AGP 9.3](https://developer.android.com/build/releases/agp-9-3-0-release-notes):
  Gradle 9.5.0, JDK mínimo 17, Build Tools mínimo/default 36.0.0 y NDK default r28c.
- [Matriz Gradle 9.5.0](https://docs.gradle.org/9.5.0/userguide/compatibility.html):
  admite JVM 17–26; Java 21 puede ejecutar Gradle desde 8.5.
- [Preparación Android para Flutter](https://docs.flutter.dev/platform-integration/android/setup).
- [Manifiesto Android oficial](https://dl.google.com/android/repository/repository2-1.xml):
  paquetes de canal 0, licencia y SHA1 de archivos. El SDK instalado confirma sus
  revisiones en `source.properties`; `platform-tools` se resuelve por canal estable,
  no por una revisión fijada en el comando.

El build comprueba SHA256 de Flutter y SHA1 oficial del bootstrap Android **antes**
de extraerlos. SDK Manager aprovisiona los demás paquetes; además se descargaron
sus archivos oficiales en streaming en un contenedor desechable y se compararon
contra estos SHA1 del manifiesto, todos con resultado OK:

| Archivo bajo `https://dl.google.com/android/repository/` | SHA1 oficial comprobado |
| --- | --- |
| `commandlinetools-linux-16111833_latest.zip` | `e025545c62a8e64c7559119566a569fb1dec5f60` |
| `platform-tools_r37.0.1-linux.zip` | `477254aa5f903c15cf51001717bdf347fb6b53e0` |
| `platform-36_r02.zip` | `2c1a80dd4d9f7d0e6dd336ec603d9b5c55a6f576` |
| `build-tools_r36_linux.zip` | `b0b6376977657e8ad9b969bacf4093601da2c6fb` |
| `android-ndk-r28c-linux.zip` | `a7b54a5de87fecd125a17d54f73c446199e72a64` |

Los comprimidos permanecen en las etapas de descarga, no en la imagen final.
No se ejecutan scripts remotos mediante una tubería. Descargas SDK e instalación
Android se ejecutan como `developer`, UID 10001.

## Comprobación aislada y reproducible del procedimiento

Sin montar el repositorio, dispositivos, volúmenes ni socket Docker:

```bash
docker run --rm --network none hukid-wallet-dev:local bash -eu -c '
  test "$(id -u)" = 10001
  for dir in /workspace "$PUB_CACHE" "$FLUTTER_ROOT" "$ANDROID_HOME" /tmp; do
    test -w "$dir"
  done
  test -s "$ANDROID_HOME/licenses/android-sdk-license"
  test "$(find "$ANDROID_HOME/licenses" -type f | wc -l)" -eq 1
  printf "non-root/write permissions and license scope: PASS\n"
'

docker run --rm -i hukid-wallet-dev:local timeout 1700 bash -s <<'SH'
set -eu
mkdir -p "$HOME/.gradle"
printf '%s\n' \
  'org.gradle.jvmargs=-Xmx1536m -XX:MaxMetaspaceSize=768m -XX:ReservedCodeCacheSize=256m -Dfile.encoding=UTF-8' \
  'org.gradle.workers.max=2' \
  'org.gradle.daemon=false' \
  'kotlin.compiler.execution.strategy=in-process' > "$HOME/.gradle/gradle.properties"
scratch=$(mktemp -d /tmp/flutter-android.XXXXXX)
cd "$scratch"
flutter create --platforms=android --project-name toolchain_smoke --org dev.example toolchain_smoke
cd toolchain_smoke
flutter analyze
flutter test
flutter build apk --debug
test -s build/app/outputs/flutter-apk/app-debug.apk
sha256sum build/app/outputs/flutter-apk/app-debug.apk
SH
```

Se necesita red para pub, artefactos Flutter, Gradle y Maven. Código, firma debug,
APK y caches viven sólo en el contenedor y desaparecen con `--rm`. No se escribe
`src/wallet`; no se usa modo privilegiado ni se requiere conectar un teléfono.
Para Bash temporal: `docker run --rm -it hukid-wallet-dev:local`.

## Evidencia y límites

En esta continuación: build y probe offline exit 0; Flutter/Dart/JDK, UID 10001,
escritura en workspace/pub-cache/SDKs y `dart-ok` comprobados. El único archivo
de licencia antes y después de compilar fue `android-sdk-license`.
`sdkmanager --version` devuelve `unknown (Android CLI)` y advierte que delega en
Android CLI; se verificó tools 23.0 por `source.properties`, no por esa salida.

El primer proyecto default pasó analyze y su test, pero `flutter build apk --debug`
falló exit 1 tras 404.3 s: `Gradle build daemon disappeared unexpectedly`.
El log mostraba heap default de 8 GiB; no demuestra la causa exacta del cierre.
La única corrección limitó heap/workers en la configuración de usuario desechable
mostrada arriba. El nuevo proyecto pasó analyze (sin issues), **1 test** y build
APK debug (258.9 s), todos exit 0, sin cambiar pins ni código generado.

APK observado antes de eliminar el contenedor:
`/tmp/flutter-android.PtdZ8u/toolchain_smoke/build/app/outputs/flutter-apk/app-debug.apk`.
SHA256 observado: `b254ed5af4c91422fa7cf1e57dd45b2f55fc054fc623a811420e7f671f88b057`.
No se conserva ni se promete reproducibilidad de ese APK debug.

Los fallos históricos de Docker ausente (L18) y del smoke Dart por comillas (L11,
corregido entonces con exit 0) siguen siendo evidencia; no se convierten en éxitos.
La prueba sólo acredita el toolchain. Cámara, recepción, Keystore y persistencia
en el teléfono, seguridad de wallet y ejecución de T2–T6 quedan pendientes.
