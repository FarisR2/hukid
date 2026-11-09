// Real Keycloak + isolated realm/PostgreSQL/API/console. Never opens the local DB.
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes, createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, writeFileSync, unlinkSync, readFileSync, openSync, closeSync } from 'node:fs';
import { createServer } from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { adminClient, reconcileKeycloak } from './local-keycloak.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const base = path.join(root, '.cache/keycloak-tests'); mkdirSync(base, { recursive: true });
const scratch = mkdtempSync(path.join(base, 'run-'));
const local = JSON.parse(readFileSync(path.join(root, '.cache/local/secrets.json'), 'utf8'));
const kc = 'http://127.0.0.1:8081';
const realm = `hukid-e2e-${randomBytes(6).toString('hex')}`;
const pgBin = process.env.HUKID_PG_BIN || path.join(root, '.cache/toolchains/postgresql-18.6-5/pgsql/bin');
const go = process.env.HUKID_GO || path.join(root, '.cache/toolchains/go1.27.3/go/bin/go.exe');
const executable = name => path.join(pgBin, process.platform === 'win32' ? `${name}.exe` : name);
const password = randomBytes(32).toString('hex');
const clientSecret = randomBytes(32).toString('hex');
const data = path.join(scratch, 'data');
const children = [];
const git = args => run('git', args).trim();
function sourceDigest() {
  const hash = createHash('sha256');
  const files = run('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z']).split('\0').filter(Boolean).sort();
  for (const name of files) { const content = readFileSync(path.join(root, name)); hash.update(name + '\0' + content.length + '\0'); hash.update(content); }
  return hash.digest('hex');
}
const report = { scope: 'isolated-real-keycloak', realm, status: 'running', startedAt: new Date().toISOString(),
  head: git(['rev-parse', 'HEAD']), dirty: git(['status', '--porcelain']) !== '', sourceDigest: sourceDigest(), checks: [] };
const save = () => writeFileSync(path.join(base, 'latest.json'), JSON.stringify(report, null, 2) + '\n');
save();
function run(cmd, args, options = {}) {
  const result = spawnSync(cmd, args, { cwd: root, encoding: 'utf8', windowsHide: true, timeout: 90000, ...options });
  if (result.error || result.status !== 0) throw new Error(`${path.basename(cmd)} failed (${result.status}); isolated keycloak test`);
  return result.stdout;
}
async function freePort() {
  const server = createServer(); await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port; await new Promise(resolve => server.close(resolve)); return port;
}
function launch(cmd, args, name, env) {
  const log = openSync(path.join(scratch, `${name}.log`), 'a');
  try { const child = spawn(cmd, args, { cwd: root, env, windowsHide: true, stdio: ['ignore', log, log] }); children.push(child); return child; }
  finally { closeSync(log); }
}
async function wait(url) {
  for (let n = 0; n < 100; n++) {
    try { if ((await fetch(url, { signal: AbortSignal.timeout(1000) })).ok) return; } catch {}
    await new Promise(resolve => setTimeout(resolve, 200));
  }
  throw new Error('Owned service did not start');
}
let pgStarted = false;
let realmCreated = false;
try {
  const api = await adminClient(kc, local.kcAdminPassword);
  const ports = [await freePort(), await freePort(), await freePort()];
  const [pgPort, apiPort, webPort] = ports;
  const origin = `http://127.0.0.1:${webPort}`, issuer = `${kc}/realms/${realm}`;
  const profile = { realm, client: 'hukid-console', origin, clientSecret };
  // Own realm first, so cleanup also covers partial reconciliation failures.
  await api('POST', '', { realm, enabled: true, sslRequired: 'none' }); realmCreated = true;
  await reconcileKeycloak(api, profile);
  const counts = async () => {
    const clients = await api('GET', `${realm}/clients?clientId=hukid-console`);
    const flows = await api('GET', `${realm}/authentication/flows`);
    const mappers = await api('GET', `${realm}/clients/${clients[0].id}/protocol-mappers/models`);
    return [clients.length, flows.length, mappers.length];
  };
  const before = await counts();
  const signingKey = (await api('GET', `${realm}/keys`)).active.ES256;
  // Repair a real drift, not just an already matching second invocation.
  const [drifted] = await api('GET', `${realm}/clients?clientId=hukid-console`);
  await api('PUT', `${realm}/clients/${drifted.id}`, { ...drifted, directAccessGrantsEnabled: true,
    attributes: { ...drifted.attributes, 'id.token.signed.response.alg': 'RS256', 'access.token.header.type.rfc9068': 'false' } });
  await reconcileKeycloak(api, profile);
  if (JSON.stringify(before) !== JSON.stringify(await counts())) throw new Error('Keycloak reconciliation duplicated resources');
  if ((await api('GET', `${realm}/keys`)).active.ES256 !== signingKey) throw new Error('Keycloak reconciliation replaced the signing key');
  const repaired = await api('GET', `${realm}/clients/${drifted.id}`);
  if (repaired.directAccessGrantsEnabled || repaired.attributes['id.token.signed.response.alg'] !== 'ES256') throw new Error('Keycloak client drift not repaired');
  report.checks.push('keycloak_reconcile_twice'); save();

  const pwfile = path.join(scratch, 'init-password'); writeFileSync(pwfile, password, { mode: 0o600 });
  try { run(executable('initdb'), ['-D', data, '-U', 'hukid_e2e_admin', '--pwfile', pwfile, '--auth=scram-sha-256', '--encoding=UTF8', '--locale=C']); }
  finally { unlinkSync(pwfile); }
  const handle = openSync(path.join(scratch, 'startup.log'), 'a');
  try { run(executable('pg_ctl'), ['-D', data, '-l', path.join(scratch, 'postgres.log'), '-o', `-h 127.0.0.1 -p ${pgPort} -c log_statement=none -c log_min_error_statement=panic`, '-w', 'start'], { stdio: ['ignore', handle, handle] }); pgStarted = true; }
  finally { closeSync(handle); }
  const sql = input => run(executable('psql'), ['-X', '-q', '-t', '-A', '-v', 'ON_ERROR_STOP=1', '-h', '127.0.0.1', '-p', String(pgPort), '-U', 'hukid_e2e_admin', '-d', 'hukid_local'], { input, env: { ...process.env, PGPASSWORD: password } }).trim();
  run(executable('psql'), ['-X', '-q', '-v', 'ON_ERROR_STOP=1', '-h', '127.0.0.1', '-p', String(pgPort), '-U', 'hukid_e2e_admin', '-d', 'postgres', '-c', 'CREATE DATABASE hukid_local'], { env: { ...process.env, PGPASSWORD: password } });
  const dsn = user => { const url = new URL(`postgresql://127.0.0.1:${pgPort}/hukid_local?sslmode=disable`); url.username = user; url.password = password; return url.href; };
  const goEnv = { ...process.env, HUKID_ENV: 'local', HUKID_DATABASE_URL: dsn('hukid_e2e_admin'), GOTOOLCHAIN: 'local' };
  const localdb = args => run(go, ['run', './cmd/localdb', ...args], { cwd: path.join(root, 'src/platform'), env: goEnv });
  localdb(['migrate']);
  const roles = ['session', 'context', 'tenant', 'members', 'dashboard'];
  for (const role of roles) sql(`CREATE ROLE e2e_${role} LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '${password}'; GRANT hukid_${role}_runtime TO e2e_${role};`);
  const users = [];
  for (const label of ['a', 'b']) {
    const username = `e2e-${label}`, userPassword = randomBytes(24).toString('hex');
    await api('POST', `${realm}/users`, { username, enabled: true, email: `${username}@example.invalid`, emailVerified: true,
      firstName: 'E2E', lastName: label, requiredActions: ['CONFIGURE_TOTP'], credentials: [{ type: 'password', value: userPassword, temporary: false }] });
    const [user] = await api('GET', `${realm}/users?username=${username}&exact=true`);
    localdb(['bootstrap', issuer, user.id, `Keycloak test ${label}`]);
    const tenant = sql(`SELECT m.tenant_id FROM tenancy.memberships m JOIN tenancy.operator_identities i USING(operator_identity_id) WHERE i.subject='${user.id}';`);
    users.push({ username, password: userPassword, subject: user.id, tenant });
  }
  const count = sql('SELECT count(*) FROM tenancy.memberships;');
  localdb(['bootstrap', issuer, users[0].subject, 'must not create duplicate']);
  if (sql('SELECT count(*) FROM tenancy.memberships;') !== count) throw new Error('Bootstrap duplicated a membership');
  report.checks.push('bootstrap_idempotent'); save();
  const policy = { ...JSON.parse(readFileSync(path.join(root, 'src/platform/config/auth.local.json'))), issuer, consoleOrigin: origin, redirectUri: `${origin}/console/auth/callback` };
  const policyFile = path.join(scratch, 'auth.json'); writeFileSync(policyFile, JSON.stringify(policy));
  const key = () => randomBytes(32).toString('base64');
  const env = { ...process.env, HUKID_ENV: 'local', HUKID_AUTH_POLICY: policyFile, HUKID_LISTEN_ADDR: `127.0.0.1:${apiPort}`, HUKID_CONSOLE_PROXY_ORIGIN: origin,
    HUKID_OIDC_CLIENT_SECRET: clientSecret, HUKID_AUTH_KEY: key(), HUKID_AUTH_KEY_VERSION: 'e2e-1',
    HUKID_CONSOLE_API_TARGET: `http://127.0.0.1:${apiPort}`, HUKID_MEMBERS_POLICY: path.join(root, 'src/platform/config/user-management.test.json'),
    HUKID_MEMBERS_CURSOR_KEY: key(), HUKID_INVITATION_KEY: key(), HUKID_INVITATION_HMAC_KEY: key(), HUKID_INVITATION_KEY_VERSION: 'e2e-1',
    HUKID_DASHBOARD_POLICY: path.join(root, 'src/platform/config/dashboard.test.json'), HUKID_DASHBOARD_CURSOR_KEY: key() };
  for (const role of roles) env[`HUKID_${role.toUpperCase()}_DATABASE_URL`] = dsn(`e2e_${role}`);
  launch(path.join(root, '.cache/build/hukid-api.exe'), [], 'api', env);
  launch(process.execPath, ['node_modules/vite/bin/vite.js', 'preview', 'src/console', '--host', '127.0.0.1', '--port', String(webPort), '--strictPort'], 'console', env);
  await wait(`http://127.0.0.1:${apiPort}/healthz`); await wait(origin);
  const python = spawnSync(process.env.HUKID_PYTHON || 'python', ['tests/browser/keycloak.py'], { cwd: root, encoding: 'utf8', windowsHide: true, timeout: 300000,
    input: JSON.stringify({ origin, issuer, clientSecret, users, pgBin, pgPort, password, scratch, pgData: data }) + '\n' });
  const browserReport = path.join(scratch, 'browser.json');
  try { report.browser = JSON.parse(readFileSync(browserReport, 'utf8')); } catch { report.browser = { status: 'missing' }; }
  if (python.error || python.status !== 0) throw new Error(`Keycloak browser failed: ${report.browser.failedCase || 'execution'}`);
  for (const file of ['api.log', 'console.log']) {
    const log = readFileSync(path.join(scratch, file), 'utf8');
    const confidential = [password, clientSecret, ...users.map(u => u.password), ...Object.entries(env).filter(([name]) => name.endsWith('_KEY')).map(([, value]) => value), 'invitee@example.invalid'];
    if (confidential.some(value => value && log.includes(value))) throw new Error('Secret/recipient found in owned application logs');
  }
  report.checks.push('application_log_redaction');
  report.status = 'passed';
} catch (error) {
  report.status = 'failed'; report.error = error.message; process.exitCode = 1;
} finally {
  for (const child of children.reverse()) {
    if (child.pid) {
      if (process.platform === 'win32') spawnSync('taskkill', ['/PID', String(child.pid), '/T', '/F'], { stdio: 'ignore', windowsHide: true });
      else child.kill('SIGTERM');
    }
  }
  if (realmCreated) {
    try { const api = await adminClient(kc, local.kcAdminPassword); await api('DELETE', realm); report.realmCleanup = 'passed'; }
    catch { report.realmCleanup = 'failed'; report.status = 'failed'; process.exitCode = 1; }
  }
  if (pgStarted) {
    const stopped = spawnSync(executable('pg_ctl'), ['-D', data, '-m', 'fast', '-w', 'stop'], { stdio: 'ignore', windowsHide: true, timeout: 20000 });
    report.postgresCleanup = stopped.status === 0 ? 'passed' : 'failed';
    if (stopped.status !== 0) { report.status = 'failed'; process.exitCode = 1; }
  }
  if (sourceDigest() !== report.sourceDigest) { report.status = 'source_changed'; process.exitCode = 1; }
  report.finishedAt = new Date().toISOString();
  save(); console.log(`Real Keycloak gate: ${report.status}; .cache/keycloak-tests/latest.json`);
}
