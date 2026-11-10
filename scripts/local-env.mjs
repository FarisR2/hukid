// Persistent single-machine environment ("local" profile, ADR-0025).
// Unlike .cache/local-login-demo.mjs it never creates throwaway databases and never
// stops services it did not start. State lives in .cache/local (ignored by git).
//   node scripts/local-env.mjs init          one-time: PostgreSQL cluster, database, roles, secrets
//   node scripts/local-env.mjs keycloak-init one-time: realm, client and operator user in Keycloak
//   node scripts/local-env.mjs bootstrap     link the Keycloak operator to a tenant (idempotent)
//   node scripts/local-env.mjs start|stop    run / stop PostgreSQL, Keycloak, API and console
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync, openSync, closeSync, unlinkSync } from 'node:fs';
import { createServer } from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { adminClient, reconcileKeycloak, verifyKeycloak } from './local-keycloak.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const state = path.join(root, '.cache/local');
const secretsPath = path.join(state, 'secrets.json');
const pidsPath = path.join(state, 'pids.json');
const pgBin = process.env.HUKID_PG_BIN || path.join(root, '.cache/toolchains/postgresql-18.6-5/pgsql/bin');
const kcHome = path.join(root, '.cache/toolchains/keycloak-26.8.2/keycloak-26.8.2');
const goBin = path.join(root, '.cache/toolchains/go1.27.3/go/bin');
const PG_PORT = 54329, KC_PORT = 8081, API_PORT = 8080, CONSOLE_PORT = 5173;
const REALM = 'hukid', CLIENT = 'hukid-console', OPERATOR = 'operador.local';
const issuer = `http://127.0.0.1:${KC_PORT}/realms/${REALM}`;
const consoleOrigin = `http://127.0.0.1:${CONSOLE_PORT}`;
const exe = (name) => path.join(pgBin, process.platform === 'win32' ? `${name}.exe` : name);
const b64 = () => randomBytes(32).toString('base64');
const hex = () => randomBytes(24).toString('hex');
const children = [];
let ownsPostgres = false;
function killTree(pid) { spawnSync('taskkill', ['/PID', String(pid), '/T', '/F'], { windowsHide: true }); }
function stopChildren() {
  const owned = children.splice(0).filter(c => c.pid);
  const pids = readJson(pidsPath, {});
  for (const c of owned) { killTree(c.pid); for (const [name, pid] of Object.entries(pids)) if (pid === c.pid) delete pids[name]; }
  if (existsSync(pidsPath)) writeFileSync(pidsPath, JSON.stringify(pids));
}
process.on('SIGINT', () => { stopChildren(); if (pgRunning()) { try { run(exe('pg_ctl'), ['-D', path.join(state, 'pgdata'), '-m', 'fast', '-w', 'stop']); } catch {} } console.log('Detenido. Los datos se conservan.'); process.exit(0); });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function run(cmd, args, options = {}) {
  const r = spawnSync(cmd, args, { cwd: root, encoding: 'utf8', windowsHide: true, ...options });
  if (r.error || r.status !== 0) throw new Error(`Fallo: ${path.basename(cmd)} ${args[0] ?? ''}\n${(r.stderr || '').trim().split('\n').slice(-3).join('\n')}`);
  return r.stdout;
}
const readJson = (file, fallback) => (existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : fallback);
const secrets = () => { if (!existsSync(secretsPath)) throw new Error('Ejecuta primero: node scripts/local-env.mjs init'); return readJson(secretsPath); };
const saveSecrets = (s) => writeFileSync(secretsPath, JSON.stringify(s, null, 2), { mode: 0o600 });
const dsn = (user, password, database = 'hukid_local') => {
  const u = new URL(`postgresql://127.0.0.1:${PG_PORT}/${database}?sslmode=disable`);
  u.username = user; u.password = password; return u.href;
};
function sql(database, input, s) {
  return run(exe('psql'), ['-X', '-q', '-v', 'ON_ERROR_STOP=1', '-h', '127.0.0.1', '-p', String(PG_PORT), '-U', 'hukid_local_admin', '-d', database], { input, env: { ...process.env, PGPASSWORD: s.pgAdmin } });
}
function portFree(port) {
  return new Promise((resolve) => { const s = createServer(); s.once('error', () => resolve(false)); s.listen(port, '127.0.0.1', () => s.close(() => resolve(true))); });
}
const pgRunning = () => spawnSync(exe('pg_ctl'), ['-D', path.join(state, 'pgdata'), 'status'], { windowsHide: true }).status === 0;
function startPostgres() {
  if (pgRunning()) return;
  const log = openSync(path.join(state, 'startup.log'), 'a');
  try { run(exe('pg_ctl'), ['-D', path.join(state, 'pgdata'), '-l', path.join(state, 'postgres.log'), '-o', `-h 127.0.0.1 -p ${PG_PORT} -c log_statement=none`, '-w', '-t', '30', 'start'], { stdio: ['ignore', log, log] }); } finally { closeSync(log); }
  ownsPostgres = true;
}
function goEnv(s) {
  return { ...process.env, PATH: `${goBin}${path.delimiter}${process.env.PATH}`, GOTMPDIR: path.join(root, '.cache/gotmp'), HUKID_ENV: 'local', HUKID_DATABASE_URL: dsn('hukid_local_admin', s.pgAdmin) };
}
async function waitHttp(url, label, tries = 600) {
  for (let n = 0; n < tries; n++) { try { const r = await fetch(url, { signal: AbortSignal.timeout(1500) }); if (r.ok) return; } catch {} await sleep(500); }
  throw new Error(`${label} no respondió: ${url}`);
}

async function init() {
  mkdirSync(state, { recursive: true }); mkdirSync(path.join(root, '.cache/gotmp'), { recursive: true });
  if (existsSync(secretsPath)) { provision(secrets()); console.log('OK: configuración local actualizada; datos y secretos conservados.'); return; }
  if (!(await portFree(PG_PORT))) throw new Error(`El puerto ${PG_PORT} está ocupado`);
  const s = { pgAdmin: hex(), roles: {}, authKey: b64(), authKeyVersion: 'local-1', oidcClientSecret: hex(), kcAdminPassword: hex(), operatorPassword: hex(), invitationKey: b64(), invitationHmacKey: b64(), membersCursorKey: b64() };
  const pwfile = path.join(state, 'init-password');
  writeFileSync(pwfile, s.pgAdmin, { mode: 0o600 });
  try { run(exe('initdb'), ['-D', path.join(state, 'pgdata'), '-U', 'hukid_local_admin', '--pwfile', pwfile, '--auth=scram-sha-256', '--encoding=UTF8', '--locale=C']); } finally { if (existsSync(pwfile)) unlinkSync(pwfile); }
  saveSecrets(s);
  startPostgres();
  sql('postgres', 'CREATE DATABASE hukid_local;', s);
  provision(s);
  console.log('OK: PostgreSQL persistente (puerto %d), base hukid_local migrada y roles de runtime creados.', PG_PORT);
}

function provision(s) {
  startPostgres();
  run(path.join(goBin, 'go.exe'), ['run', './cmd/localdb', 'migrate'], { cwd: path.join(root, 'src/platform'), env: goEnv(s) });
  for (const role of ['session', 'context', 'tenant', 'members', 'dashboard']) {
    if (!s.roles[role]) { s.roles[role] = { login: `hukid_local_${role}`, pw: hex() }; saveSecrets(s); }
    const { login, pw } = s.roles[role];
    if (login !== `hukid_local_${role}` || !/^[a-zA-Z0-9_-]+$/.test(pw)) throw new Error('Credencial runtime local inválida');
    sql('hukid_local', `DO $local$ BEGIN IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname='${login}') THEN CREATE ROLE ${login} LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '${pw}'; END IF; END $local$; GRANT hukid_${role}_runtime TO ${login};`, s);
  }
  for (const key of ['dashboardCursorKey', 'membersCursorKey', 'invitationKey', 'invitationHmacKey']) if (!s[key]) s[key] = b64();
  saveSecrets(s);
}

function kcEnv(s) {
  return { ...process.env, KC_BOOTSTRAP_ADMIN_USERNAME: 'admin', KC_BOOTSTRAP_ADMIN_PASSWORD: s.kcAdminPassword };
}
function kcStart(s) {
  const log = openSync(path.join(state, 'keycloak.log'), 'a');
  const child = spawn('cmd.exe', ['/d', '/c', path.join(kcHome, 'bin', 'kc.bat'), 'start-dev', `--http-port=${KC_PORT}`, '--http-host=127.0.0.1', '--hostname-strict=false'], { cwd: kcHome, env: kcEnv(s), windowsHide: true, stdio: ['ignore', log, log] });
  closeSync(log); children.push(child); return child.pid;
}
async function keycloakInit() {
  const s = secrets();
  if (!(await portFree(KC_PORT))) console.log('Keycloak ya escucha en %d; se reutiliza.', KC_PORT);
  else { console.log('Arrancando Keycloak (primer arranque tarda)...'); const pid = kcStart(s); writePids({ keycloak: pid }); }
  await waitHttp(`http://127.0.0.1:${KC_PORT}/realms/master`, 'Keycloak');
  const api = await adminClient(`http://127.0.0.1:${KC_PORT}`, s.kcAdminPassword);
  await reconcileKeycloak(api, { realm: REALM, client: CLIENT, origin: consoleOrigin, clientSecret: s.oidcClientSecret });
  const users = await api('GET', `${REALM}/users?username=${OPERATOR}&exact=true`);
  if (!users.some(u => u.username === OPERATOR)) await api('POST', `${REALM}/users`, {
    username: OPERATOR, enabled: true, email: `${OPERATOR}@hukid.local`, emailVerified: true,
    requiredActions: ['CONFIGURE_TOTP'], credentials: [{ type: 'password', value: s.operatorPassword, temporary: false }],
  });
  console.log('OK: realm %s, cliente %s y usuario %s. Contraseña inicial en .cache/local/secrets.json (operatorPassword); TOTP se configura en el primer login.', REALM, CLIENT, OPERATOR);
  console.log('Perfil operator reconciliado: ES256/at+jwt, Code+refresh, MFA por ejecuciones reales y LoA 2.');
  stopChildren();
}

async function bootstrap() {
  const s = secrets();
  const api = await adminClient(`http://127.0.0.1:${KC_PORT}`, s.kcAdminPassword);
  const matches = (await api('GET', `${REALM}/users?username=${OPERATOR}&exact=true`)).filter(u => u.username === OPERATOR);
  if (matches.length > 1) throw new Error('Identidad de operador ambigua');
  const id = matches[0]?.id;
  if (!id) throw new Error('No se encontró el usuario en Keycloak; ejecuta keycloak-init (con Keycloak activo).');
  startPostgres();
  run(path.join(goBin, 'go.exe'), ['run', './cmd/localdb', 'bootstrap', issuer, id, process.env.HUKID_TENANT_NAME || 'Organización local'], { cwd: path.join(root, 'src/platform'), env: goEnv(s) });
  console.log('OK: identidad %s vinculada como tenant_admin (idempotente).', id);
}

function writePids(update) { writeFileSync(pidsPath, JSON.stringify({ ...readJson(pidsPath, {}), ...update }, null, 2)); }
async function start() {
  const s = secrets();
  if (!s.roles.members || !s.roles.dashboard || !s.dashboardCursorKey) throw new Error('Ejecuta local-env.mjs init para actualizar el perfil local');
  mkdirSync(path.join(root, '.cache/build'), { recursive: true });
  for (const [port, name] of [[API_PORT, 'API'], [CONSOLE_PORT, 'consola']]) if (!(await portFree(port))) throw new Error(`El puerto ${port} (${name}) está ocupado`);
  startPostgres();
  if (await portFree(KC_PORT)) { const pid = kcStart(s); writePids({ keycloak: pid }); }
  await waitHttp(`${issuer}/.well-known/openid-configuration`, 'Keycloak');
  await verifyKeycloak(await adminClient(`http://127.0.0.1:${KC_PORT}`, s.kcAdminPassword), { realm: REALM, client: CLIENT, origin: consoleOrigin });
  run(path.join(goBin, 'go.exe'), ['build', '-o', path.join(root, '.cache/build/hukid-api.exe'), './cmd/api'], { cwd: path.join(root, 'src/platform'), env: goEnv(s) });
  // The console has no access page, so it can be served as built; keep it apart from dist/.
  const outDir = path.join(state, 'console-dist');
  run(process.execPath, ['node_modules/vite/bin/vite.js', 'build', 'src/console', '--outDir', outDir, '--emptyOutDir'], { env: { ...process.env, HUKID_CONSOLE_API_TARGET: `http://127.0.0.1:${API_PORT}` } });
  const policy = path.join(root, 'src/platform/config/auth.local.json');
  const env = { ...process.env, HUKID_ENV: 'local', HUKID_AUTH_POLICY: policy, HUKID_LISTEN_ADDR: `127.0.0.1:${API_PORT}`, HUKID_CONSOLE_PROXY_ORIGIN: consoleOrigin, HUKID_SESSION_DATABASE_URL: dsn(s.roles.session.login, s.roles.session.pw), HUKID_CONTEXT_DATABASE_URL: dsn(s.roles.context.login, s.roles.context.pw), HUKID_TENANT_DATABASE_URL: dsn(s.roles.tenant.login, s.roles.tenant.pw), HUKID_OIDC_CLIENT_SECRET: s.oidcClientSecret, HUKID_AUTH_KEY: s.authKey, HUKID_AUTH_KEY_VERSION: s.authKeyVersion, HUKID_CONSOLE_API_TARGET: `http://127.0.0.1:${API_PORT}` };
  Object.assign(env, {
    HUKID_MEMBERS_DATABASE_URL: dsn(s.roles.members.login, s.roles.members.pw), HUKID_MEMBERS_POLICY: path.join(root, 'src/platform/config/user-management.test.json'), HUKID_MEMBERS_CURSOR_KEY: s.membersCursorKey,
    HUKID_INVITATION_KEY: s.invitationKey, HUKID_INVITATION_HMAC_KEY: s.invitationHmacKey, HUKID_INVITATION_KEY_VERSION: 'local-1',
    HUKID_DASHBOARD_DATABASE_URL: dsn(s.roles.dashboard.login, s.roles.dashboard.pw), HUKID_DASHBOARD_POLICY: path.join(root, 'src/platform/config/dashboard.test.json'), HUKID_DASHBOARD_CURSOR_KEY: s.dashboardCursorKey,
  });
  const spawnLogged = (cmd, args, name, e) => { const log = openSync(path.join(state, `${name}.log`), 'a'); const c = spawn(cmd, args, { cwd: root, env: e, windowsHide: true, stdio: ['ignore', log, log] }); closeSync(log); children.push(c); return c.pid; };
  const api = spawnLogged(path.join(root, '.cache/build/hukid-api.exe'), [], 'api', env);
  const web = spawnLogged(process.execPath, ['node_modules/vite/bin/vite.js', 'preview', 'src/console', '--outDir', outDir, '--host', '127.0.0.1', '--port', String(CONSOLE_PORT), '--strictPort'], 'console', env);
  writePids({ api, web });
  await waitHttp(`http://127.0.0.1:${API_PORT}/healthz`, 'API'); await waitHttp(consoleOrigin, 'Consola');
  console.log('LISTO %s  (Keycloak %s). Detener: node scripts/local-env.mjs stop', consoleOrigin, issuer);
}
function stop() {
  const pids = readJson(pidsPath, {});
  for (const [name, pid] of Object.entries(pids)) { if (name === 'keycloak') continue; try { process.kill(pid); } catch {} }
  if (pids.keycloak) spawnSync('taskkill', ['/PID', String(pids.keycloak), '/T', '/F'], { windowsHide: true });
  if (pgRunning()) run(exe('pg_ctl'), ['-D', path.join(state, 'pgdata'), '-m', 'fast', '-w', 'stop']);
  writeFileSync(pidsPath, '{}');
  console.log('Detenido. Los datos de PostgreSQL y Keycloak se conservan.');
}

const commands = { init, 'keycloak-init': keycloakInit, bootstrap, start, stop };
const command = process.argv[2];
if (!commands[command]) { console.error('Uso: node scripts/local-env.mjs init|keycloak-init|bootstrap|start|stop'); process.exit(1); }
try { await commands[command](); } catch (error) {
  stopChildren();
  if (ownsPostgres && pgRunning()) { try { run(exe('pg_ctl'), ['-D', path.join(state, 'pgdata'), '-m', 'fast', '-w', 'stop']); } catch {} }
  console.error(error.message); process.exit(1);
}
