# Glosario

| Término | Significado |
| --- | --- |
| Events | Plataforma de publicación, participación, asistencia y certificación de actividades. |
| Organización | Institución operativa y límite de autorización de Events; identificada por organization_id. |
| Tenant HukID | Cliente contractual y límite administrativo de HukID; identificado por tenant_id. No se equipara automáticamente con organización Events. |
| Consola / panel web HukID | Aplicación administrativa React que se usa en el navegador. No es la terminal de desarrollo ni la wallet Flutter. |
| Terminal de desarrollo | Herramienta para ejecutar comandos de arranque, pruebas y mantenimiento autorizado; no es la interfaz del usuario final. |
| Issuer | Entidad que respalda una afirmación y cuya clave firma la credencial. Un tenant puede tener varios. |
| Sistema fuente | Events, POS, SIS u otro sistema que aporta datos y evidencia para una emisión. |
| Integration client | Identidad de máquina autorizada para actuar sobre issuers/definitions concretos. |
| Grant | Permiso acotado por cliente, issuer, definición, ambiente y acción. |
| Subject | Entidad sobre la que la credencial afirma datos. |
| Holder | Quien controla una credencial y su clave de presentación; puede diferir del subject. |
| Wallet | Aplicación Flutter que protege claves, guarda credenciales y obtiene consentimiento. |
| Verifier | Sistema que solicita una presentación, verifica evidencia y aplica su política de confianza. |
| Claim | Dato afirmado por el issuer dentro de una credencial. |
| Credential Definition | Contrato de claims, mapping, formato, binding, vigencia, status y display. |
| Definition version | Snapshot publicado e inmutable de una definición. |
| Credential configuration | Capacidad anunciada por el issuer en metadata OID4VCI. |
| Oferta | Invitación temporal para recoger una credencial; no es la credencial. |
| Credencial verificable / VC | Documento digital asegurado criptográficamente por el issuer. |
| Presentación / VP | Artefacto con el que el holder responde a un verifier y demuestra control de clave. |
| Certificado PDF | Documento generado por Operations con reglas de elegibilidad; distinto de la VC. |
| Ticket QR | Credencial operativa de Participation para acceso al evento; distinto de la oferta HukID. |
| Holder binding | Vínculo criptográfico con la clave de la wallet; en HukID usa cnf.jkt. No prueba por sí solo identidad civil. |
| OID4VCI | Protocolo de entrega de credenciales del issuer a la wallet. |
| OID4VP | Protocolo de solicitud y entrega de presentaciones al verifier. |
| KMS/HSM | Servicio o hardware que protege y utiliza claves criptográficas. |
| JWKS / kid | Conjunto público de claves y el identificador de la clave utilizada. |
| Status | Estado verificable de suspensión/revocación; distinguir deseado de publicado. |
| Release / publication_id | Configuración completa e inmutable de evento que los consumidores activan coherentemente. |
| Idempotencia | Repetir el mismo comando produce el mismo resultado semántico sin duplicar efectos. |
| Outbox / inbox | Persistencia transaccional para publicación durable y deduplicación de eventos. |
| Trust policy | Reglas para reconocer issuers y tipos; distintas de validar una firma. |
| Crypto-shredding | Eliminación controlada de capacidad de descifrado conforme a retención y legal hold. |

Detalle: [estándares y modelo conceptual](../03-design/hukid-standards-and-model.md).
