// Offline tests: no network, no Keycloak. Run with: node --test scripts/staging-keycloak.test.mjs
import assert from 'node:assert/strict';
import test from 'node:test';
import { reconcileKeycloak, selectMode, verifyKeycloak } from './local-keycloak.mjs';
import { VARIABLES, ensureAccountConsole, ensureOperator, loadStagingConfig, main } from './staging-keycloak.mjs';

const SECRETS = { HUKID_KC_ADMIN_PASSWORD: 'admin-pass-AAAAAAAAAAAA', HUKID_KC_CLIENT_SECRET: 'c'.repeat(40), HUKID_KC_OPERATOR_PASSWORD: 'operator-pass-BBBBBBBB' };
const valid = () => ({
  HUKID_KC_ADMIN_URL: 'http://127.0.0.1:8081', HUKID_KC_ADMIN_USER: 'kcadmin', HUKID_KC_OPERATOR_USER: 'ana.perez',
  HUKID_KC_OPERATOR_EMAIL: 'ana@example.com', HUKID_KC_CONSOLE_ORIGIN: 'https://hukid.zentrycore.com', ...SECRETS,
});
const rejects = (override, pattern) => assert.throws(() => loadStagingConfig({ ...valid(), ...override }), pattern);

test('mode defaults to local and accepts only local or staging', () => {
  assert.equal(selectMode({}), 'local');
  assert.equal(selectMode({ HUKID_KEYCLOAK_MODE: 'local' }), 'local');
  assert.equal(selectMode({ HUKID_KEYCLOAK_MODE: 'staging' }), 'staging');
  for (const bad of ['', 'production', 'Staging', 'toString', '__proto__']) assert.throws(() => selectMode({ HUKID_KEYCLOAK_MODE: bad }), /local.*staging/);
});

test('a valid staging configuration loads and trims a trailing slash on the admin URL', () => {
  const config = loadStagingConfig({ ...valid(), HUKID_KC_ADMIN_URL: 'http://127.0.0.1:8081/' });
  assert.equal(config.adminUrl, 'http://127.0.0.1:8081');
  assert.equal(config.origin, 'https://hukid.zentrycore.com');
  assert.equal(config.operatorUser, 'ana.perez');
});

test('every required variable is reported by name when missing or empty', () => {
  assert.throws(() => loadStagingConfig({}), error => VARIABLES.every(name => error.message.includes(name)));
  for (const name of VARIABLES) {
    const env = valid();
    delete env[name];
    assert.throws(() => loadStagingConfig(env), new RegExp(`Faltan variables.*${name}`));
    assert.throws(() => loadStagingConfig({ ...valid(), [name]: '' }), new RegExp(name));
  }
});

test('admin URL: https anywhere, http only on loopback, no credentials or path', () => {
  loadStagingConfig({ ...valid(), HUKID_KC_ADMIN_URL: 'https://kc-admin.zentrycore.com' });
  loadStagingConfig({ ...valid(), HUKID_KC_ADMIN_URL: 'http://localhost:8081' });
  for (const bad of ['http://kc.zentrycore.com:8081', 'ftp://127.0.0.1', 'http://u:p@127.0.0.1:8081', 'http://127.0.0.1:8081/admin', 'no-url']) rejects({ HUKID_KC_ADMIN_URL: bad }, /ADMIN_URL/);
});

test('console origin must be a public lowercase https origin', () => {
  const bad = ['http://hukid.zentrycore.com', 'https://hukid.zentrycore.com/', 'https://hukid.zentrycore.com/app', 'https://hukid.zentrycore.com:8443',
    'https://127.0.0.1', 'https://localhost', 'https://app.local', 'https://app.example', 'https://Hukid.ZentryCore.com', 'https://hukid', 'https://-bad.zentrycore.com'];
  for (const origin of bad) rejects({ HUKID_KC_CONSOLE_ORIGIN: origin }, /CONSOLE_ORIGIN/);
});

test('staging never reuses the local operator or the Keycloak admin user', () => {
  rejects({ HUKID_KC_OPERATOR_USER: 'operador.local' }, /operador\.local/);
  rejects({ HUKID_KC_OPERATOR_USER: 'admin' }, /OPERATOR_USER/);
  rejects({ HUKID_KC_OPERATOR_USER: 'Ana Perez' }, /OPERATOR_USER/);
});

test('secrets need minimum strength and must not repeat each other', () => {
  rejects({ HUKID_KC_CLIENT_SECRET: 'short' }, /CLIENT_SECRET/);
  rejects({ HUKID_KC_OPERATOR_PASSWORD: 'short' }, /OPERATOR_PASSWORD/);
  rejects({ HUKID_KC_OPERATOR_PASSWORD: SECRETS.HUKID_KC_ADMIN_PASSWORD }, /repetir/);
  rejects({ HUKID_KC_OPERATOR_EMAIL: 'not-an-email' }, /OPERATOR_EMAIL/);
});

test('error messages never contain secret values', () => {
  const env = { ...valid(), HUKID_KC_CLIENT_SECRET: 'weak-secret-value', HUKID_KC_OPERATOR_PASSWORD: 'weak-operator-pw', HUKID_KC_CONSOLE_ORIGIN: 'http://bad' };
  assert.throws(() => loadStagingConfig(env), error => {
    for (const value of ['weak-secret-value', 'weak-operator-pw', SECRETS.HUKID_KC_ADMIN_PASSWORD]) assert.ok(!error.message.includes(value));
    return true;
  });
});

test('main rejects an unknown command before reading the environment', async () => {
  await assert.rejects(main('delete', {}), /Uso:/);
  await assert.rejects(main(undefined, {}), /Uso:/);
});

test('verifyKeycloak in staging requires sslRequired=external, local does not ask', async () => {
  const fake = sslRequired => async (method, resource) => {
    assert.equal(method, 'GET');
    if (resource === 'hukid') return { sslRequired };
    return [];
  };
  const target = { realm: 'hukid', client: 'hukid-console', origin: 'https://hukid.zentrycore.com' };
  await assert.rejects(verifyKeycloak(fake('none'), { ...target, mode: 'staging' }), /sslRequired=external/);
  await assert.rejects(verifyKeycloak(fake('all'), { ...target, mode: 'staging' }), /sslRequired=external/);
  // external passes the staging gate and then fails later on the (empty) client, not on SSL.
  await assert.rejects(verifyKeycloak(fake('external'), { ...target, mode: 'staging' }), error => !/sslRequired/.test(error.message));
  // local mode never fails on sslRequired (its realm uses "none").
  await assert.rejects(verifyKeycloak(fake('none'), { ...target, mode: 'local' }), error => !/sslRequired/.test(error.message));
  await assert.rejects(verifyKeycloak(fake('none'), { ...target, mode: 'bogus' }), /modo desconocido/);
});

test('reconcile creates the staging realm with sslRequired=external and local with none', async () => {
  // The fake lacks the realm, accepts its creation and the realm update, then stops the run.
  const created = async mode => {
    const calls = [];
    const api = async (method, resource, body) => {
      calls.push({ method, resource, body });
      if (method === 'GET' && resource === '') return [];
      if (method === 'POST' && resource === '') return null;
      throw new Error('stop');
    };
    await assert.rejects(reconcileKeycloak(api, { realm: 'hukid', client: 'hukid-console', origin: 'https://x.example.com', clientSecret: 'x', mode }), /stop/);
    return calls;
  };
  assert.equal((await created('staging')).find(call => call.method === 'POST').body.sslRequired, 'external');
  assert.equal((await created('local')).find(call => call.method === 'POST').body.sslRequired, 'none');
  assert.equal((await created('staging')).find(call => call.method === 'PUT').body.sslRequired, 'external');
  assert.equal('sslRequired' in (await created('local')).find(call => call.method === 'PUT').body, false);
});

test('ensureOperator creates a temporary-password user once and never touches an existing one', async () => {
  const config = loadStagingConfig(valid());
  const calls = [];
  const empty = async (method, resource, body) => { calls.push({ method, resource, body }); return method === 'GET' ? [] : null; };
  assert.equal(await ensureOperator(empty, config), 'creado');
  const post = calls.find(call => call.method === 'POST');
  assert.equal(post.body.username, 'ana.perez');
  assert.deepEqual(post.body.requiredActions, ['CONFIGURE_TOTP', 'UPDATE_PASSWORD']);
  assert.equal(post.body.credentials[0].temporary, true);
  const existing = [];
  const present = async (method, resource) => { existing.push(method); return [{ username: 'ana.perez' }]; };
  assert.equal(await ensureOperator(present, config), 'existente');
  assert.deepEqual(existing, ['GET']);
});

test('ensureAccountConsole pins only redirect URIs and web origins, and is idempotent', async () => {
  const origin = 'https://hukid-id.zentrycore.com';
  const stored = { id: 'abc', clientId: 'account-console', publicClient: true, redirectUris: ['/realms/hukid/account/*'], webOrigins: ['+'] };
  const calls = [];
  const api = async (method, resource, body) => { calls.push({ method, resource, body }); return method === 'GET' ? [stored] : null; };
  assert.equal(await ensureAccountConsole(api, origin), 'actualizado');
  const put = calls.find(call => call.method === 'PUT');
  assert.equal(put.resource, 'hukid/clients/abc');
  assert.deepEqual(put.body.redirectUris, [origin + '/realms/hukid/account/*']);
  assert.deepEqual(put.body.webOrigins, [origin]);
  assert.equal(put.body.publicClient, true);
  Object.assign(stored, { redirectUris: put.body.redirectUris, webOrigins: put.body.webOrigins });
  calls.length = 0;
  assert.equal(await ensureAccountConsole(api, origin), 'sin cambios');
  assert.deepEqual(calls.map(call => call.method), ['GET']);
  await assert.rejects(ensureAccountConsole(async () => [], origin), /account-console/);
});
