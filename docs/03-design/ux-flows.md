# Flujos de usuario

## Events: participante y organizador

1. Organizador crea evento, agenda, formulario y policy; valida y publica una release completa.
2. Visitante consulta la landing e inicia registro o postulación.
3. Participation valida datos/consentimiento y confirma, solicita revisión o asigna waitlist según policy.
4. Participante confirmado obtiene ticket QR; puede consultar/cancelar con sesión o enlace autorizado.
5. Staff inicia turno, valida readiness y escanea ticket; una corrección crea void trazable.
6. Operations evalúa elegibilidad y genera certificado PDF descargable/verificable.

En convocatorias, el líder gestiona equipo, invitaciones, archivos y borrador; enviar congela revisión. Subsanar crea otra revisión. Estados y alternativas: [historias](../02-requirements/user-stories.md) y [máquinas de estado](contracts/events-state-machines.md).

## Events→HukID: recibir una credencial

1. Usuario/organización solicita la credencial para un certificado elegible con consentimiento.
2. Adaptador Team 4 crea request en HukID y registra referencia/estado.
3. Events presenta o entrega la oferta por un canal definido para el piloto.
4. Ana abre enlace en el celular o escanea el QR desde la wallet. La app valida URI, issuer y compatibilidad; no autoacepta.
5. La policy puede exigir autenticación de destinatario o tx_code por canal separado. Escanear un QR no demuestra identidad.
6. Ana acepta; la wallet realiza OID4VCI, genera proof y recibe la VC inmediata o mediante polling diferido.
7. Verifica firma, binding, schema, tiempo y status; guarda cifrado y muestra el resultado.
8. Events reconcilia su entrega mediante polling de la solicitud HukID. El estado issued no sustituye una prueba no definida de retención permanente en el dispositivo.

## Wallet: consulta, presentación y recuperación

El holder consulta credenciales y status, con última comprobación visible offline. Para presentar, revisa verifier, propósito y contenido completo que se compartirá; puede cancelar. La presentación es wallet→verifier y no requiere mediación del backend HukID.

Eliminar la copia local no revoca la credencial. Ante pérdida, local-only remite al issuer/sistema fuente; issuer-reauth permite nueva emisión a nueva clave según policy. No hay recuperación cloud/account-linked en v0.

## Estados de interacción

Cubrir loading, vacío, error recuperable, expirado, cancelado, sin permiso y confirmación. Distinguir QR de ticket Events, QR de oferta y QR de presentación. Diseñar teclado/foco, lector de pantalla, permisos de cámara, conectividad y reanudación sin duplicados.

Detalle: [UC-01–12 y matriz de riesgo HukID](hukid-ux-flows.md), [wallet/backend](hukid-wallet-backend.md), [perfil](hukid-profile.md). Pantallas finales y canal de distribución de app siguen pendientes del piloto.
