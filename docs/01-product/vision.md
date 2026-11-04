# Visión del producto

## Events

Plataforma para que IncubaUNAS, la UNAS y futuras instituciones creen, publiquen y operen eventos, congresos y convocatorias. Sustituye formularios dispersos, consolidación manual de listas y check-in en papel por un flujo trazable.

El primer cliente natural es IncubaUNAS. Los usuarios son visitantes, participantes, líderes de emprendimientos, organizadores, revisores y personal de asistencia. El producto debe servir desde un taller hasta un congreso con programas paralelos o una convocatoria de equipos.

La institución publica su sitio y evento; recibe inscripciones o postulaciones; gestiona cupos y QR; registra asistencia; consulta reportes y emite certificados PDF.

## HukID

Producto independiente para que instituciones emitan credenciales verificables y sus titulares las reciban, conserven y presenten desde una wallet. Incluye Platform en Go y Wallet en Flutter. Events es un sistema fuente; los ejemplos POS y SIS prueban que el núcleo admite otros dominios.

La institución respalda los datos y actúa como issuer. HukID aporta definición versionada, oferta, emisión, firma, estado y protocolos de entrega. Una credencial digital y el PDF de Events son artefactos distintos.

## Valor y criterios de éxito

- Institución: menos trabajo operativo, control de cupos, permisos y evidencia auditable.
- Participante: registro confiable, ticket y acceso a constancias.
- Holder: custodia local de credenciales y consentimiento al compartir.
- Integrador: API estable y reintentos sin duplicados.
- Verifier: evaluación técnica separada de confianza en el emisor y decisión de negocio.

El MVP Events debe completar publicación→registro→asistencia→certificado PDF. La integración HukID se valida desde certificado elegible hasta oferta, wallet y status, sin bloquear la operación del evento. Las métricas de activación y uso de la wallet siguen el [roadmap HukID](../05-delivery/hukid-roadmap.md).

## Fuentes

[Descripción original conservada](../05-delivery/archive/original-project-overview.md), [modelo conceptual HukID](../03-design/hukid-standards-and-model.md), [backend y wallet](../03-design/hukid-wallet-backend.md). Ver [alcance](scope.md) para los cortes de entrega.
