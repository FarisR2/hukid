import test from 'node:test';
import assert from 'node:assert/strict';
import { createWallet, DEMO_INPUTS } from './model.mjs';

const ready = () => {
  const wallet = createWallet();
  assert.equal(wallet.initialize('pin-demo').ok, true);
  return wallet;
};
const unchanged = (wallet, action, code) => {
  const before = wallet.snapshot();
  assert.deepEqual(action(), { ok: false, code });
  assert.deepEqual(wallet.snapshot(), before);
};

test('starts empty; initialization is simulated, validated, and cannot repeat', () => {
  const wallet = createWallet();
  assert.deepEqual(wallet.snapshot(), { initialized: false, method: null, credentials: [], usedOffers: [], activity: [] });
  unchanged(wallet, () => wallet.initialize('123456'), 'invalid-method');
  unchanged(wallet, () => wallet.previewOffer('demo:campus'), 'locked');
  assert.equal(wallet.initialize('biometry-demo').ok, true);
  assert.equal(wallet.snapshot().method, 'biometry-demo');
  unchanged(wallet, () => wallet.initialize('pin-demo'), 'already-initialized');
});

test('offer preview does not save; explicit accept saves once, including after deletion', () => {
  const wallet = ready();
  const before = wallet.snapshot();
  const preview = wallet.previewOffer('https://demo.hukid.invalid/offer/campus');
  assert.equal(preview.ok, true);
  assert.equal(preview.offer.issuerTrusted, true);
  assert.equal(preview.offer.signature, 'valid-demo');
  assert.deepEqual(wallet.snapshot(), before);
  assert.equal(wallet.acceptOffer(preview.offer.code).ok, true);
  assert.equal(wallet.snapshot().credentials.length, 1);
  assert.equal(wallet.snapshot().activity.length, 2);
  unchanged(wallet, () => wallet.acceptOffer('demo:campus'), 'used-offer');
  assert.equal(wallet.deleteCredential('campus', true).ok, true);
  unchanged(wallet, () => wallet.acceptOffer('demo:campus'), 'used-offer');
  unchanged(wallet, () => wallet.deleteCredential('campus', true), 'not-found');
});

for (const [input, code] of [
  ['https://evil.invalid/offer/campus', 'malformed-link'],
  ['javascript:alert(1)', 'malformed-link'],
  ['demo:unknown', 'malformed-link'],
  ['demo:expired-offer', 'expired-offer'],
  ['demo:used-offer', 'used-offer'],
  ['demo:untrusted', 'untrusted-issuer'],
  ['demo:invalid', 'invalid-credential'],
  ['demo:expired', 'expired-credential'],
]) {
  test(`rejects ${input} without changing stored data or counters`, () => {
    const wallet = ready();
    unchanged(wallet, () => wallet.previewOffer(input), code);
    unchanged(wallet, () => wallet.acceptOffer(input), code);
  });
}

test('offline offer has unknown status, no current check and cannot be shared', () => {
  const wallet = ready();
  const preview = wallet.previewOffer('demo:offline');
  assert.equal(preview.offer.status, 'unknown');
  assert.equal(preview.offer.lastCheck, null);
  assert.equal(wallet.acceptOffer('demo:offline').ok, true);
  unchanged(wallet, () => wallet.previewPresentation('offline', 'demo:library'), 'status-unknown');
  unchanged(wallet, () => wallet.share('offline', 'demo:library', true), 'status-unknown');
});

test('presentation previews full document and recipient; share requires explicit consent', () => {
  const wallet = ready();
  wallet.acceptOffer('demo:campus');
  const before = wallet.snapshot();
  const preview = wallet.previewPresentation('campus', 'demo:library');
  assert.equal(preview.ok, true);
  assert.equal(preview.presentation.recipient, 'Biblioteca demo');
  assert.equal(preview.presentation.disclosure, 'full-document');
  assert.deepEqual(preview.presentation.credential, before.credentials[0]);
  assert.deepEqual(wallet.snapshot(), before);
  unchanged(wallet, () => wallet.share('campus', 'demo:library', false), 'cancelled');
  unchanged(wallet, () => wallet.share('campus', 'demo:library', 'yes'), 'cancelled');
  unchanged(wallet, () => wallet.share('campus', 'https://evil.invalid', true), 'invalid-presentation');
  unchanged(wallet, () => wallet.previewPresentation('campus', 'demo:invalid-presentation'), 'invalid-presentation');
  assert.equal(wallet.share('campus', 'demo:library', true).ok, true);
  assert.equal(wallet.snapshot().activity.at(-1).kind, 'shared-demo');
  assert.deepEqual(wallet.snapshot().credentials, before.credentials);
});

test('cancellation, unknown identifiers and deletion have distinct safe outcomes', () => {
  const wallet = ready();
  wallet.acceptOffer('demo:campus');
  unchanged(wallet, () => wallet.cancel(), 'cancelled');
  unchanged(wallet, () => wallet.deleteCredential('campus', false), 'cancelled');
  unchanged(wallet, () => wallet.deleteCredential('campus', 'yes'), 'cancelled');
  unchanged(wallet, () => wallet.previewPresentation('missing', 'demo:library'), 'not-found');
  unchanged(wallet, () => wallet.share('missing', 'demo:library', true), 'not-found');
  assert.equal(wallet.deleteCredential('campus', true).ok, true);
  assert.equal(wallet.snapshot().credentials.length, 0);
  assert.equal(wallet.snapshot().activity.at(-1).kind, 'deleted-local');
});

test('seed uses ordinary acceptance, is idempotent, respects consumed offers; reset is explicit', () => {
  const wallet = ready();
  assert.equal(wallet.seed().ok, true);
  assert.equal(wallet.snapshot().credentials.length, 2);
  const seeded = wallet.snapshot();
  wallet.seed();
  assert.deepEqual(wallet.snapshot(), seeded);
  wallet.deleteCredential('campus', true);
  wallet.seed();
  assert.equal(wallet.snapshot().credentials.some(c => c.id === 'campus'), false);
  unchanged(wallet, () => wallet.reset(false), 'cancelled');
  assert.equal(wallet.reset(true).ok, true);
  assert.deepEqual(wallet.snapshot(), createWallet().snapshot());
});

test('snapshots and previews cannot mutate private state; all demo inputs resolve deterministically', () => {
  const wallet = ready();
  wallet.acceptOffer('demo:campus');
  const copy = wallet.snapshot();
  copy.credentials[0].title = 'tampered';
  copy.activity.length = 0;
  assert.notEqual(wallet.snapshot().credentials[0].title, 'tampered');
  assert.equal(wallet.snapshot().activity.length, 2);
  for (const { code } of DEMO_INPUTS) assert.equal(typeof ready().previewOffer(code).ok, 'boolean');
});

test('locked wallet cannot seed, accept, delete or present', () => {
  const wallet = createWallet();
  for (const action of [() => wallet.seed(), () => wallet.acceptOffer('demo:campus'),
    () => wallet.deleteCredential('campus', true), () => wallet.share('campus', 'demo:library', true),
    () => wallet.previewPresentation('campus', 'demo:library')]) unchanged(wallet, action, 'locked');
});
