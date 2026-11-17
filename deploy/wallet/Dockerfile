# Base de desarrollo Linux x64; Android SDK autorizado para laboratorio (T1/L17).
FROM ubuntu:24.04@sha256:77eb101c607d6e3d4f5ad0c8a02c2136c689b98aba1f359e6502ba517e5c57ec AS prerequisites

RUN test "$(dpkg --print-architecture)" = amd64 \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl git unzip xz-utils zip libglu1-mesa openjdk-21-jdk-headless \
 && useradd --create-home --uid 10001 --shell /bin/bash developer \
 && install -d -o developer -g developer /opt/flutter /opt/android-sdk /workspace /home/developer/.pub-cache

ENV HOME=/home/developer \
    FLUTTER_ROOT=/opt/flutter \
    PUB_CACHE=/home/developer/.pub-cache \
    JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 \
    ANDROID_HOME=/opt/android-sdk \
    ANDROID_SDK_ROOT=/opt/android-sdk \
    PATH=/opt/flutter/bin:/opt/flutter/bin/cache/dart-sdk/bin:/opt/android-sdk/cmdline-tools/23.0/bin:/opt/android-sdk/platform-tools:${PATH} \
    CI=true \
    FLUTTER_SUPPRESS_ANALYTICS=true \
    DART_SUPPRESS_ANALYTICS=true

# El archivo comprimido queda sólo en esta etapa, no en la imagen final.
FROM prerequisites AS sdk
USER developer:developer
WORKDIR /tmp
RUN curl --fail --location --proto '=https' --tlsv1.2 \
      --connect-timeout 30 --max-time 1800 \
      --output flutter.tar.xz \
      https://storage.googleapis.com/flutter_infra_release/releases/stable/linux/flutter_linux_3.50.0-stable.tar.xz \
 && printf '%s  %s\n' \
      '6ea2d806fd57269ae783e6788e2a81fc26eaad782f1e0d0ff38623bb765ff9f5' \
      flutter.tar.xz | sha256sum --check --strict \
 && tar --extract --xz --file flutter.tar.xz --directory /opt/flutter --strip-components=1

# Bootstrap oficial: checksum SHA1 publicado en repository2-1.xml.
FROM prerequisites AS android
USER developer:developer
WORKDIR /tmp
RUN curl --fail --location --proto '=https' --tlsv1.2 \
      --connect-timeout 30 --max-time 600 \
      --output commandlinetools.zip \
      https://dl.google.com/android/repository/commandlinetools-linux-16111833_latest.zip \
 && printf '%s  %s\n' 'e025545c62a8e64c7559119566a569fb1dec5f60' commandlinetools.zip | sha1sum --check --strict \
 && unzip -q commandlinetools.zip -d bootstrap \
 && mkdir -p "$ANDROID_HOME/cmdline-tools" \
 && mv bootstrap/cmdline-tools "$ANDROID_HOME/cmdline-tools/23.0" \
 && printf 'y\n' | sdkmanager --sdk_root="$ANDROID_HOME" --channel=0 --install \
      'platform-tools' 'platforms;android-36' 'build-tools;36.0.0' 'ndk;28.2.13676358' \
 && test -f "$ANDROID_HOME/licenses/android-sdk-license" \
 && test "$(find "$ANDROID_HOME/licenses" -type f | wc -l)" -eq 1

FROM prerequisites AS development
COPY --from=sdk --chown=developer:developer /opt/flutter/ /opt/flutter/
COPY --from=android --chown=developer:developer /opt/android-sdk/ /opt/android-sdk/
USER developer:developer
WORKDIR /workspace
RUN flutter config --no-analytics \
 && dart --disable-analytics \
 && flutter --version
CMD ["bash"]
