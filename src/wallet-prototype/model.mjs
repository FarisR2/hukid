// Synthetic fixtures only. No network, cryptography, authentication or persistence.
export const DEMO_INPUTS = Object.freeze([
  { code: 'demo:campus', label: 'Credencial universitaria' },
  { code: 'demo:workshop', label: 'Constancia de taller' },
  { code: 'demo:expired-offer', label: 'Oferta vencida' },
  { code: 'demo:used-offer', label: 'Oferta utilizada' },
  { code: 'demo:untrusted', label: 'Emisor no confiable' },
  { code: 'demo:invalid', label: 'Firma inválida' },
  { code: 'demo:expired', label: 'Credencial vencida' },
  { code: 'demo:offline', label: 'Sin conexión / estado desconocido' },
]);

const fixtures = {
  campus: { title: 'Identidad universitaria', issuer: 'Universidad Demo', type: 'Comunidad universitaria',
    fields: { Titular: 'Persona de demostración', Vínculo: 'Estudiante demo', Sede: 'Campus de ejemplo' } },
  workshop: { title: 'Diseño de futuros', issuer: 'Laboratorio Demo', type: 'Constancia de participación',
    fields: { Titular: 'Persona de demostración', Actividad: 'Taller de ejemplo', Duración: '12 horas ficticias' } },
  offline: { title: 'Acceso al laboratorio', issuer: 'Universidad Demo', type: 'Acceso de demostración',
    fields: { Titular: 'Persona de demostración', Espacio: 'Laboratorio de ejemplo' } },
};
const errors = {
  'expired-offer': 'expired-offer', 'used-offer': 'used-offer', untrusted: 'untrusted-issuer',
  invalid: 'invalid-credential', expired: 'expired-credential',
};
const fail = code => ({ ok: false, code });
const clone = value => structuredClone(value);
const initial = () => ({ initialized: false, method: null, credentials: [], usedOffers: [], activity: [] });

export function createWallet() {
  let state = initial();
  const record = (kind, title) => state.activity.push({ id: state.activity.length + 1, kind, title });
  const offerKey = input => {
    if (typeof input !== 'string') return null;
    // Exact allowlist: never fetch, navigate to or infer trust from an input URL.
    const value = input.trim();
    const candidate = DEMO_INPUTS.find(({ code }) => value === code ||
      value === `https://demo.hukid.invalid/offer/${code.slice(5)}`);
    return candidate?.code.slice(5) ?? null;
  };
  const previewOffer = input => {
    if (!state.initialized) return fail('locked');
    const key = offerKey(input);
    if (!key) return fail('malformed-link');
    if (errors[key]) return fail(errors[key]);
    if (state.usedOffers.includes(key)) return fail('used-offer');
    return { ok: true, offer: clone({ ...fixtures[key], code: `demo:${key}`, id: key,
      issuerTrusted: true, signature: 'valid-demo', status: key === 'offline' ? 'unknown' : 'valid-demo',
      lastCheck: key === 'offline' ? null : 'Comprobación ficticia al recibir',
      issued: '01/02/2026 (ficticia)', expires: '01/02/2030 (ficticia)',
    }) };
  };
  const acceptOffer = input => {
    const result = previewOffer(input);
    if (!result.ok) return result;
    const { code, ...credential } = result.offer;
    state.credentials.push(credential);
    state.usedOffers.push(credential.id);
    record('saved-demo', credential.title);
    return { ok: true, credential: clone(credential) };
  };
  const previewPresentation = (id, request) => {
    if (!state.initialized) return fail('locked');
    const credential = state.credentials.find(item => item.id === id);
    if (!credential) return fail('not-found');
    if (request !== 'demo:library') return fail('invalid-presentation');
    if (credential.status === 'unknown') return fail('status-unknown');
    return { ok: true, presentation: { recipient: 'Biblioteca demo', purpose: 'Simular el acceso a recursos',
      disclosure: 'full-document', credential: clone(credential) } };
  };
  return {
    snapshot: () => clone(state),
    initialize(method) {
      if (state.initialized) return fail('already-initialized');
      if (!['pin-demo', 'biometry-demo'].includes(method)) return fail('invalid-method');
      state.initialized = true;
      state.method = method;
      record('initialized-demo', 'Wallet de demostración creada');
      return { ok: true };
    },
    previewOffer,
    acceptOffer,
    previewPresentation,
    share(id, request, consent) {
      if (!state.initialized) return fail('locked');
      if (consent !== true) return fail('cancelled');
      const result = previewPresentation(id, request);
      if (!result.ok) return result;
      record('shared-demo', result.presentation.credential.title);
      return { ok: true };
    },
    deleteCredential(id, consent) {
      if (!state.initialized) return fail('locked');
      if (consent !== true) return fail('cancelled');
      const credential = state.credentials.find(item => item.id === id);
      if (!credential) return fail('not-found');
      state.credentials = state.credentials.filter(item => item.id !== id);
      record('deleted-local', credential.title);
      return { ok: true };
    },
    cancel: () => fail('cancelled'),
    seed() {
      if (!state.initialized) return fail('locked');
      // Same acceptance path and invariants as a user, including single-use offers.
      for (const code of ['demo:campus', 'demo:workshop']) {
        if (!state.usedOffers.includes(code.slice(5))) acceptOffer(code);
      }
      return { ok: true };
    },
    reset(consent) {
      if (consent !== true) return fail('cancelled');
      state = initial();
      return { ok: true };
    },
  };
}
