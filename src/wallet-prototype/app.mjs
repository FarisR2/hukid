import { createWallet, DEMO_INPUTS } from './model.mjs';

const wallet = createWallet();
const app = document.querySelector('#app');
let route = 'welcome';
let selectedId = null;
let pendingOffer = null;
let pendingPresentation = null;
let receiveMode = 'scan';
let message = '';
let messageIsError = false;

const paths = {
  wallet: '<rect x="3" y="5" width="18" height="15" rx="3"/><path d="M3 9h18m-6 4h6v4h-6z"/>',
  scan: '<path d="M8 3H3v5m13-5h5v5M3 16v5h5m13-5v5h-5M3 12h18"/><path d="M8 8h2v2H8zm6 6h2v2h-2z"/>',
  activity: '<path d="M4 5v5h5M4 10a8 8 0 1 1 0 6m8-9v5l3 2"/>',
  settings: '<path d="M12 3v3m0 12v3M3 12h3m12 0h3M6 6l2 2m8 8 2 2M6 18l2-2m8-8 2-2"/><circle cx="12" cy="12" r="5"/>',
  arrow: '<path d="m9 5 7 7-7 7"/>',
  back: '<path d="m14 5-7 7 7 7"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  shield: '<path d="m12 3 8 3v6c0 4-4 7-8 9-4-2-8-5-8-9V6z"/><path d="m8 12 3 3 5-6"/>',
  check: '<path d="m5 12 4 4L19 6"/>',
  share: '<path d="M12 16V3m-5 5 5-5 5 5M5 13v7h14v-7"/>',
  trash: '<path d="M3 6h18M9 6V3h6v3M6 6l1 15h10l1-15M10 10v7m4-7v7"/>',
  fingerprint: '<path d="M5 13v-2a7 7 0 0 1 14 0v3m-10 6v-9a3 3 0 0 1 6 0v6m-3-6v11M5 16v3m14-2v2"/>',
  key: '<circle cx="8" cy="9" r="5"/><path d="m12 13 8 8m-2-2 3-3m-6 0 3-3"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6m0-11v1"/>',
};
const icon = name => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.info}</svg>`;
const escape = text => String(text).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const button = (action, label, symbol, style = 'primary', extra = '') => `<button type="button" class="button ${style}" data-action="${action}" ${extra}>${symbol ? icon(symbol) : ''}<span>${label}</span></button>`;
const errors = {
  'malformed-link': 'Enlace no válido. Usa un código demo de la lista; no se abrirán enlaces externos.',
  'expired-offer': 'Esta oferta demo venció. No se guardó nada. Prueba demo:campus.',
  'used-offer': 'Esta oferta demo ya fue utilizada. Eliminar la copia no permite reutilizarla.',
  'untrusted-issuer': 'Emisor no confiable en esta simulación. Una firma válida no implica confianza. No se guardó nada.',
  'invalid-credential': 'Firma inválida en la simulación. No se guardó la credencial.',
  'expired-credential': 'Credencial vencida en la simulación. No se guardó nada.',
  'invalid-presentation': 'Solicitud de presentación inválida. No se compartió nada. Usa demo:library.',
  'status-unknown': 'Sin conexión simulada: el estado actual es desconocido. No se compartió nada.',
  cancelled: 'Operación cancelada. No se cambió ni compartió nada.',
  'not-found': 'Esta copia ya no está en la wallet. No se cambió nada.',
  locked: 'Primero crea tu wallet de demostración.',
  'invalid-method': 'Selecciona un método de acceso de demostración.',
  'already-initialized': 'La wallet demo ya está creada.',
};

function notify(text, isError = false) {
  message = text;
  messageIsError = isError;
  const target = document.querySelector('#feedback');
  if (target) {
    target.textContent = message;
    target.classList.toggle('error', isError);
    target.hidden = false;
  }
}
function resultError(result) {
  if (result.ok) return false;
  notify(errors[result.code] || 'No se pudo completar la simulación. No se cambió nada.', true);
  return true;
}
function go(next, notice = '') {
  route = next;
  message = notice;
  messageIsError = false;
  render();
}
function cancel(next) {
  const result = wallet.cancel();
  pendingOffer = null;
  pendingPresentation = null;
  go(next, errors[result.code]);
}
const status = credential => credential.status === 'unknown'
  ? '<span class="status unknown">Estado desconocido · Sin conexión demo</span>'
  : '<span class="status">✓ Vigente en escenario demo</span>';
const fields = credential => `<dl class="document-fields">${Object.entries(credential.fields).map(([key, value]) => `<div><dt>${escape(key)}</dt><dd>${escape(value)}</dd></div>`).join('')}
  <div><dt>Emisión</dt><dd>${credential.issued}</dd></div><div><dt>Vencimiento</dt><dd>${credential.expires}</dd></div></dl>`;
const credentialCard = (credential, interactive = true) => {
  const content = `<div class="card-top"><span>${icon('shield')} ${escape(credential.issuer)}</span><span class="card-mark">h.</span></div>
    <div class="card-body"><p>${escape(credential.type)}</p><h2>${escape(credential.title)}</h2></div>
    <div class="card-bottom"><span>Persona de demostración</span>${interactive ? icon('arrow') : '<span>Demo</span>'}</div>`;
  return interactive ? `<button class="credential-card ${credential.id === 'workshop' ? 'light-card' : ''}" data-action="detail" data-id="${credential.id}" aria-label="Ver ${escape(credential.title)}">${content}</button>`
    : `<div class="credential-card ${credential.id === 'workshop' ? 'light-card' : ''}">${content}</div>`;
};
function heading(title, subtitle, back = null) {
  return `${back ? `<button class="back" data-action="${back}">${icon('back')} Volver</button>` : ''}
    <header class="page-heading"><h1 tabindex="-1">${title}</h1>${subtitle ? `<p>${subtitle}</p>` : ''}</header>`;
}
function welcome() {
  return `<div class="onboarding"> <div class="mini-brand"><span class="brand-symbol">h</span> hukid.</div>
    <div class="wallet-art" aria-hidden="true"><div class="art-back"></div><div class="art-card"><span>Universidad Demo</span>${icon('shield')}<strong>Tu identidad,<br>en tus manos.</strong><span>Credencial de demostración</span></div><div class="art-seal">${icon('check')}</div></div>
    ${heading('Tu próxima credencial empieza aquí.', 'Un lugar para recibir lo que te acredita y compartirlo solo cuando tú decidas.')}
    ${button('start', 'Explorar mi wallet', 'arrow')}
    <p class="fineprint">Demo sin registro. No ingreses información personal.<br>Al recargar, todo vuelve a empezar.</p></div>`;
}
function setup() {
  return `${heading('Hazla tuya.', 'Elige cómo quieres representar el acceso a tu wallet. Aquí no se crea ninguna protección real.', 'welcome')}
    <div class="setup-symbol">${icon('fingerprint')}</div>
    <div class="choice-list">${button('init-pin', 'Simular acceso con PIN', 'key', 'choice')}${button('init-bio', 'Simular acceso biométrico', 'fingerprint', 'choice')}</div>
    <p class="notice">No solicitamos ni guardamos un PIN o una huella. Ambas opciones solo abren esta demo; no autentican ni cifran datos.</p>`;
}
function home(state) {
  return `<div class="home-brand"><span class="mini-brand">hukid.</span><span class="local-label">Sesión local</span></div>
    ${heading('Mi wallet', 'Tus credenciales. Tú decides.')}
    <div class="section-label"><h2>Credenciales</h2><span>${state.credentials.length} guardadas</span></div>
    ${state.credentials.length ? `<div class="card-list">${state.credentials.map(c => credentialCard(c)).join('')}</div>` : `<div class="empty-state"><div class="empty-icon">${icon('wallet')}</div><h2>Este espacio es tuyo.</h2><p>Recibe tu primera credencial de ejemplo. No necesitas una cuenta.</p>${button('receive', 'Recibir credencial', 'plus')}</div>`}
    ${state.credentials.length ? button('receive', 'Recibir otra credencial', 'plus', 'secondary') : ''}
    <div class="privacy-note">${icon('shield')}<p>Solo en esta sesión.<br><span>Sin sincronización. Sin datos reales.</span></p></div>`;
}
function receive() {
  return `${heading('Recibir credencial', 'Escanea una oferta demo o pega un enlace de ejemplo.', 'cancel-home')}
    <div class="segmented" aria-label="Método de recepción">${button('mode-scan', 'Escanear demo', 'scan', receiveMode === 'scan' ? 'selected' : 'plain', `aria-pressed="${receiveMode === 'scan'}"`)}${button('mode-link', 'Usar enlace', null, receiveMode === 'link' ? 'selected' : 'plain', `aria-pressed="${receiveMode === 'link'}"`)}</div>
    ${receiveMode === 'scan' ? `<div class="scanner"><div class="scan-corners">${icon('scan')}<span>Oferta de ejemplo</span></div><p>Escáner simulado<br><small>No usa cámara ni lee códigos QR reales.</small></p></div>
      <form id="scan-form"><label for="scan-code">Escenario del código simulado</label><select id="scan-code" name="code">${DEMO_INPUTS.map(input => `<option value="${input.code}">${input.label}</option>`).join('')}</select><button class="button primary" type="submit">${icon('scan')} Simular lectura</button></form>`
    : `<form id="link-form"><label for="offer-link">Código o enlace demo</label><input id="offer-link" name="code" type="text" autocomplete="off" spellcheck="false" placeholder="demo:campus" required aria-describedby="link-help"><p id="link-help" class="helper">Solo se aceptan ejemplos de esta demo. Nunca se visita el enlace.</p><button class="button primary" type="submit">Revisar oferta</button></form>
      <details class="examples"><summary>Ver entradas de ejemplo</summary><ul>${DEMO_INPUTS.map(input => `<li><code>${input.code}</code><span>${input.label}</span></li>`).join('')}</ul><p>También: <code>https://demo.hukid.invalid/offer/campus</code></p></details>`}
    <p class="fineprint">Nada se guarda hasta que revises y aceptes la oferta.</p>`;
}
function offer() {
  const c = pendingOffer;
  return `${heading('Una credencial para ti', 'Revisa el emisor y el contenido antes de guardarla.', 'cancel-receive')}
    ${credentialCard(c, false)}
    <section class="verification"><h2>Resultado simulado</h2><p>${icon('shield')} Emisor: confiable en el escenario demo</p><p>${icon('check')} Firma: válida en el escenario demo</p>${status(c)}<p class="helper">Confianza en el emisor y firma son evaluaciones distintas. Aquí ninguna comprobación es real.</p></section>
    ${fields(c)}<p class="notice">${c.status === 'unknown' ? 'Sin conexión simulada. Puedes guardar esta copia, pero su estado actual es desconocido y no podrás compartirla.' : 'Última comprobación: ficticia al recibir. No acredita validez actual en un servicio real.'}</p>
    ${button('accept', 'Aceptar y guardar', 'plus')}${button('cancel-receive', 'Cancelar', null, 'text')}`;
}
function detail(state) {
  const c = state.credentials.find(item => item.id === selectedId);
  if (!c) return `${heading('Copia no disponible', 'Esta credencial ya no está guardada.', 'home')}`;
  return `${heading('Tu credencial', '', 'home')}${credentialCard(c, false)}${status(c)}
    ${fields(c)}<section class="verification"><h2>Comprobaciones de ejemplo</h2><p>Emisor: confiable en demo</p><p>Firma: válida en demo</p><p>Última comprobación: ${c.lastCheck || 'No disponible; sin conexión demo'}</p><p class="helper">No hay validación en tiempo real ni evidencia criptográfica.</p></section>
    ${button('present', 'Presentar credencial', 'share', 'primary', c.status === 'unknown' ? 'disabled aria-describedby="unknown-help"' : '')}
    ${c.status === 'unknown' ? '<p id="unknown-help" class="helper">Estado actual desconocido. La presentación queda bloqueada en este escenario; prueba una credencial de campus.</p>' : ''}
    ${button('delete', 'Eliminar copia local', 'trash', 'danger-text')}`;
}
function presentationRequest() {
  return `${heading('Presentar credencial', 'Primero revisaremos a quién y qué vas a compartir.', 'cancel-detail')}
    <div class="request-symbol">${icon('share')}</div>
    <form id="request-form"><label for="request">Solicitud de presentación demo</label><select id="request" name="request"><option value="demo:library">Biblioteca demo · Solicitud válida</option><option value="demo:invalid-presentation">Solicitud inválida</option></select><button class="button primary" type="submit">Revisar solicitud</button></form>
    <p class="notice">No se contactará a ningún destinatario. Esta es una presentación simulada del documento completo.</p>`;
}
function consent() {
  const p = pendingPresentation;
  return `${heading('Tú tienes la última palabra.', 'Revisa todo lo que se incluirá en esta simulación.', 'cancel-detail')}
    <section class="recipient"><span class="recipient-icon">${icon('wallet')}</span><div><h2>${p.recipient}</h2><p>${p.purpose}</p></div></section>
    <p class="notice disclosure"><strong>Se revela el documento completo.</strong> No hay selección de campos. El destinatario recibiría todos los datos que ves debajo, incluido emisor, fechas y comprobaciones demo.</p>
    <h2 class="subheading">Documento a presentar</h2>${credentialCard(p.credential, false)}${fields(p.credential)}
    <dl class="document-fields"><div><dt>Estado</dt><dd>Vigente en escenario demo</dd></div><div><dt>Emisor / firma</dt><dd>Confiable / válida en demo</dd></div><div><dt>Última comprobación</dt><dd>${p.credential.lastCheck}</dd></div><div><dt>ID demo</dt><dd>${p.credential.id}</dd></div></dl>
    <form id="consent-form"><label class="checkbox"><input type="checkbox" name="consent" required><span>Entiendo que se presentará el documento completo a Biblioteca demo.</span></label><button class="button primary" type="submit">${icon('share')} Compartir en simulación</button></form>${button('cancel-detail', 'No compartir', null, 'text')}`;
}
function deleteView(state) {
  const c = state.credentials.find(item => item.id === selectedId);
  return `${heading('¿Eliminar esta copia?', '', 'cancel-detail')}<div class="delete-symbol">${icon('trash')}</div><h2 class="subheading">${escape(c?.title || 'Credencial')}</h2><p>Se quitará solo de esta sesión y quedará una entrada en la actividad local.</p><p class="notice"><strong>Eliminar no revoca la credencial.</strong> No borra copias del emisor ni de terceros. La oferta ya utilizada no podrá usarse otra vez; para repetir la demo, reiníciala.</p>${button('confirm-delete', 'Sí, eliminar copia local', 'trash', 'danger')}${button('cancel-detail', 'Conservar credencial', null, 'secondary')}`;
}
function activity(state) {
  const labels = { 'initialized-demo': 'Inicio de demo', 'saved-demo': 'Guardada en demo', 'shared-demo': 'Presentación simulada; sin envío', 'deleted-local': 'Copia local eliminada' };
  return `${heading('Actividad', 'Un registro local, no una auditoría real.')}
    <ol class="timeline">${state.activity.toReversed().map(item => `<li><span class="timeline-icon">${icon(item.kind === 'shared-demo' ? 'share' : item.kind === 'deleted-local' ? 'trash' : 'check')}</span><div><h2>${labels[item.kind]}</h2><p>${escape(item.title)}</p><small>Paso ${item.id} de esta sesión demo</small></div></li>`).join('')}</ol>
    <p class="fineprint">Las cancelaciones no modifican el registro. Se borra al recargar o reiniciar.</p>`;
}
function settings(state) {
  return `${heading('Ajustes', 'Un laboratorio pequeño. Tú llevas el control.')}
    <section class="settings-section"><h2>Acceso representado</h2><p>${state.method === 'pin-demo' ? 'PIN simulado' : 'Biometría simulada'}</p><p class="helper">No hay PIN almacenado, autenticación ni cifrado. Cualquiera con acceso a esta pestaña puede usar la demo.</p></section>
    <section class="settings-section"><h2>Prueba la experiencia</h2><p>Carga una identidad universitaria y una constancia ficticia. No duplica ofertas ya utilizadas.</p>${button('seed', 'Cargar credenciales demo', 'plus', 'secondary')}</section>
    <section class="settings-section"><h2>Datos de esta sesión</h2><p>Solo memoria de la pestaña. Al recargar se pierde todo. No hay recuperación ni sincronización.</p>${button('reset', 'Reiniciar demostración', 'activity', 'danger-text')}</section>
    <p class="notice">Prototipo HTML, CSS y JavaScript. No es una wallet productiva ni una aplicación Flutter. No recibe credenciales reales.</p>`;
}
function resetView() {
  return `${heading('Volver a empezar', '', 'cancel-settings')}<p>Se borrarán las credenciales ficticias, las ofertas utilizadas, el método simulado y la actividad de esta sesión.</p><p class="notice">No se revoca ninguna credencial. No hay servicios externos conectados.</p>${button('confirm-reset', 'Sí, reiniciar demo', 'activity', 'danger')}${button('cancel-settings', 'Conservar demo', null, 'secondary')}`;
}
function nav() {
  const active = ['home', 'receive', 'activity', 'settings'].includes(route) ? route : 'home';
  return `<nav class="bottom-nav" aria-label="Navegación principal">${[['home', 'wallet', 'Wallet'], ['receive', 'scan', 'Recibir'], ['activity', 'activity', 'Actividad'], ['settings', 'settings', 'Ajustes']].map(([target, symbol, label]) => `<button data-action="${target}" ${active === target ? 'aria-current="page"' : ''}>${icon(symbol)}<span>${label}</span></button>`).join('')}</nav>`;
}
function render() {
  const state = wallet.snapshot();
  const views = { welcome, setup, home: () => home(state), receive, offer, detail: () => detail(state),
    request: presentationRequest, consent, delete: () => deleteView(state), activity: () => activity(state),
    settings: () => settings(state), reset: resetView };
  // Consequential flows deliberately have no tab navigation; explicit back/cancel is always available.
  const showNav = state.initialized && ['home', 'receive', 'activity', 'settings'].includes(route);
  app.innerHTML = `<main class="screen ${showNav ? 'with-nav' : ''}" id="main">${views[route]()}
    <p id="feedback" class="feedback ${messageIsError ? 'error' : ''}" role="status" aria-live="polite" aria-atomic="true" ${message ? '' : 'hidden'}>${escape(message)}</p></main>${showNav ? nav() : ''}`;
  document.querySelector('h1')?.focus({ preventScroll: true });
  document.querySelector('.device').scrollTop = 0;
}
function inspectOffer(input) {
  const result = wallet.previewOffer(input);
  if (resultError(result)) return;
  pendingOffer = result.offer;
  go('offer');
}
app.addEventListener('click', event => {
  const target = event.target.closest('button[data-action]');
  if (!target || target.disabled) return;
  const action = target.dataset.action;
  const actions = {
    start: () => go('setup'), welcome: () => go('welcome'),
    'init-pin': () => initialize('pin-demo'), 'init-bio': () => initialize('biometry-demo'),
    home: () => go('home'), receive: () => go('receive'), activity: () => go('activity'), settings: () => go('settings'),
    'mode-scan': () => { receiveMode = 'scan'; go('receive'); },
    'mode-link': () => { receiveMode = 'link'; go('receive'); },
    detail: () => { selectedId = target.dataset.id; go('detail'); },
    accept: () => {
      const result = wallet.acceptOffer(pendingOffer?.code);
      if (resultError(result)) return;
      selectedId = result.credential.id;
      pendingOffer = null;
      go('detail', 'Credencial guardada en esta sesión demo.');
    },
    present: () => go('request'), delete: () => go('delete'), reset: () => go('reset'),
    'confirm-delete': () => {
      if (resultError(wallet.deleteCredential(selectedId, true))) return;
      selectedId = null;
      go('home', 'Copia local eliminada. Esto no revoca la credencial.');
    },
    'confirm-reset': () => {
      if (resultError(wallet.reset(true))) return;
      selectedId = pendingOffer = pendingPresentation = null;
      receiveMode = 'scan';
      go('welcome', 'Demo reiniciada.');
    },
    seed: () => {
      if (resultError(wallet.seed())) return;
      go('home', 'Ejemplos cargados sin duplicar ni reutilizar ofertas consumidas.');
    },
    'cancel-home': () => cancel('home'), 'cancel-receive': () => cancel('receive'),
    'cancel-detail': () => cancel('detail'), 'cancel-settings': () => cancel('settings'),
  };
  actions[action]?.();
});
function initialize(method) {
  if (!resultError(wallet.initialize(method))) go('home', 'Wallet demo creada. No se ha configurado protección real.');
}
app.addEventListener('submit', event => {
  event.preventDefault();
  const data = new FormData(event.target);
  if (['scan-form', 'link-form'].includes(event.target.id)) inspectOffer(data.get('code'));
  if (event.target.id === 'request-form') {
    const request = data.get('request');
    const result = wallet.previewPresentation(selectedId, request);
    if (resultError(result)) return;
    pendingPresentation = { ...result.presentation, request };
    go('consent');
  }
  if (event.target.id === 'consent-form') {
    const result = wallet.share(selectedId, pendingPresentation?.request, data.get('consent') === 'on');
    if (resultError(result)) return;
    pendingPresentation = null;
    go('detail', 'Presentación simulada registrada. No se envió ningún dato.');
  }
});
render();
