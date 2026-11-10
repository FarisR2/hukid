// Offline tests: no files, no network. Run with: node --test scripts/staging-secrets.test.mjs
import assert from 'node:assert/strict';
import test from 'node:test';
import { MANUAL, ROLES, generate, parseEnv, render } from './staging-secrets.mjs';

const OIDC = 'o'.repeat(48);

test('generates every API secret with the formats the API accepts', () => {
  const { values, created } = generate({}, OIDC);
  for (const name of ['HUKID_AUTH_KEY', 'HUKID_INVITATION_KEY', 'HUKID_INVITATION_HMAC_KEY', 'HUKID_MEMBERS_CURSOR_KEY', 'HUKID_DASHBOARD_CURSOR_KEY']) {
    assert.equal(Buffer.from(values[name], 'base64').length, 32, name);
    assert.equal(Buffer.from(values[name], 'base64').toString('base64'), values[name], `${name} is strict standard base64`);
  }
  for (const role of ROLES) assert.match(values[`HUKID_RUNTIME_PASSWORD_${role}`], /^[A-Za-z0-9_-]{32,128}$/);
  assert.equal(values.HUKID_OIDC_CLIENT_SECRET, OIDC);
  assert.equal(values.HUKID_AUTH_KEY_VERSION, 'staging-1');
  assert.ok(created.includes('HUKID_AUTH_KEY'));
});

test('keys and runtime passwords are all different from each other', () => {
  const { values } = generate({}, OIDC);
  const secret = Object.entries(values).filter(([name]) => /KEY$|PASSWORD_/.test(name)).map(([, value]) => value);
  assert.equal(new Set(secret).size, secret.length);
});

test('a rerun never overwrites an existing value and reports no changes', () => {
  const first = generate({}, OIDC).values;
  const second = generate(first, OIDC);
  assert.deepEqual(second.values, first);
  assert.deepEqual(second.created, []);
});

test('the database owner password is left for the owner and never generated', () => {
  const { values } = generate({}, OIDC);
  for (const name of MANUAL) assert.equal(values[name], '');
  assert.equal(generate({ HUKID_DB_ADMIN_PASSWORD: 'kept-by-owner' }, OIDC).values.HUKID_DB_ADMIN_PASSWORD, 'kept-by-owner');
});

test('without a Keycloak client secret the OIDC secret stays unset, not invented', () => {
  assert.equal(generate({}, '').values.HUKID_OIDC_CLIENT_SECRET, undefined);
});

test('duplicate API keys are rejected', () => {
  const same = 'a'.repeat(43) + '=';
  assert.throws(() => generate({ HUKID_AUTH_KEY: same, HUKID_INVITATION_KEY: same }, OIDC), /repetirse/);
});

test('render and parseEnv round-trip values containing = + /', () => {
  const values = { A: 'x+y/z==', B: '' };
  assert.deepEqual(parseEnv(render(values)), values);
});
