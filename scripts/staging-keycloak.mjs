// Reconciles the hukid realm on an already deployed Keycloak (staging, ADR-0028).
//   node scripts/staging-keycloak.mjs reconcile   realm + client + operator user, then verify
//   node scripts/staging-keycloak.mjs verify      read-only check of the realm profile
// Every input comes from the environment; see scripts/README.md. Nothing secret is
// stored, defaulted or printed. Importing this module never contacts a server.
import { pathToFileURL } from 'node:url';
import { adminClient, reconcileKeycloak, verifyKeycloak } from './local-keycloak.mjs';

export const REALM = 'hukid';
export const CLIENT = 'hukid-console';
export const VARIABLES = [
  'HUKID_KC_ADMIN_URL', 'HUKID_KC_ADMIN_USER', 'HUKID_KC_ADMIN_PASSWORD', 'HUKID_KC_CLIENT_SECRET',
  'HUKID_KC_OPERATOR_USER', 'HUKID_KC_OPERATOR_EMAIL', 'HUKID_KC_OPERATOR_PASSWORD', 'HUKID_KC_CONSOLE_ORIGIN',
];
const RESERVED_USERS = new Set(['operador.local', 'admin']);
const RESERVED_SUFFIXES = ['.localhost', '.local', '.internal', '.invalid', '.test', '.example'];

function validOrigin(value) {
  let url;
  try { url = new URL(value); } catch { return false; }
  const host = url.hostname;
  return url.protocol === 'https:' && !url.username && !url.password && !url.port && url.pathname === '/' && !url.search && !url.hash
    && value === `https://${host}` && host === host.toLowerCase() && host.includes('.') && !/^[\d.]+$/.test(host) && !host.includes(':')
    && !RESERVED_SUFFIXES.some(suffix => host.endsWith(suffix))
    && host.split('.').every(label => /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(label));
}

// The admin console is only reachable through a tunnel, so plain http is accepted
// for loopback only; any other host must use https.
function validAdminUrl(value) {
  let url;
  try { url = new URL(value); } catch { return false; }
  if (url.username || url.password || url.search || url.hash || (url.pathname !== '/' && url.pathname !== '')) return false;
  const loopback = ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
  return url.protocol === 'https:' || (url.protocol === 'http:' && loopback);
}

// Returns the validated configuration or throws one error naming every problem.
// Error text only ever contains variable names, never their values.
export function loadStagingConfig(env = process.env) {
  const missing = VARIABLES.filter(name => !env[name]);
  if (missing.length) throw new Error(`Faltan variables de entorno: ${missing.join(', ')}`);
  const problems = [];
  const adminUrl = env.HUKID_KC_ADMIN_URL.replace(/\/+$/, '');
  if (!validAdminUrl(adminUrl)) problems.push('HUKID_KC_ADMIN_URL debe ser https, o http solo en loopback (túnel SSH), sin credenciales ni ruta');
  if (!validOrigin(env.HUKID_KC_CONSOLE_ORIGIN)) problems.push('HUKID_KC_CONSOLE_ORIGIN debe ser un origen https público en minúsculas, sin puerto ni ruta');
  if (env.HUKID_KC_CLIENT_SECRET.length < 32) problems.push('HUKID_KC_CLIENT_SECRET necesita al menos 32 caracteres');
  if (!/^[a-z0-9][a-z0-9._-]{2,63}$/.test(env.HUKID_KC_OPERATOR_USER) || RESERVED_USERS.has(env.HUKID_KC_OPERATOR_USER)) problems.push('HUKID_KC_OPERATOR_USER inválido o reservado (no reutilices operador.local ni admin)');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(env.HUKID_KC_OPERATOR_EMAIL) || env.HUKID_KC_OPERATOR_EMAIL.length > 254) problems.push('HUKID_KC_OPERATOR_EMAIL no es un correo válido');
  if (env.HUKID_KC_OPERATOR_PASSWORD.length < 16) problems.push('HUKID_KC_OPERATOR_PASSWORD necesita al menos 16 caracteres');
  if (env.HUKID_KC_OPERATOR_PASSWORD === env.HUKID_KC_ADMIN_PASSWORD || env.HUKID_KC_OPERATOR_PASSWORD === env.HUKID_KC_CLIENT_SECRET) problems.push('HUKID_KC_OPERATOR_PASSWORD no puede repetir otro secreto');
  if (problems.length) throw new Error(`Configuración de staging inválida:\n- ${problems.join('\n- ')}`);
  return {
    adminUrl, adminUser: env.HUKID_KC_ADMIN_USER, adminPassword: env.HUKID_KC_ADMIN_PASSWORD, clientSecret: env.HUKID_KC_CLIENT_SECRET,
    operatorUser: env.HUKID_KC_OPERATOR_USER, operatorEmail: env.HUKID_KC_OPERATOR_EMAIL, operatorPassword: env.HUKID_KC_OPERATOR_PASSWORD,
    origin: env.HUKID_KC_CONSOLE_ORIGIN,
  };
}

// Creates the operator only when absent. An existing user is never touched, so a
// rerun cannot reset a password or an enrolled OTP factor. The password is temporary.
export async function ensureOperator(api, config) {
  const users = await api('GET', `${REALM}/users?username=${encodeURIComponent(config.operatorUser)}&exact=true`);
  if (users.some(user => user.username === config.operatorUser)) return 'existente';
  await api('POST', `${REALM}/users`, {
    username: config.operatorUser, enabled: true, email: config.operatorEmail, emailVerified: true,
    requiredActions: ['CONFIGURE_TOTP', 'UPDATE_PASSWORD'],
    credentials: [{ type: 'password', value: config.operatorPassword, temporary: true }],
  });
  return 'creado';
}

// Behind the proxy Keycloak resolves the built-in account-console's relative redirect
// URIs and web origins against the wrong base, so the token endpoint answers 403
// "Invalid origin" to the browser. Pinning them to the public Keycloak origin fixes it.
// Only these two fields change; every other client setting is kept as read.
export async function ensureAccountConsole(api, publicOrigin) {
  const [client] = await api('GET', `${REALM}/clients?clientId=account-console`);
  if (!client) throw new Error('Keycloak: el cliente account-console no existe en el realm');
  const redirectUris = [`${publicOrigin}/realms/${REALM}/account/*`];
  const webOrigins = [publicOrigin];
  if (JSON.stringify(client.redirectUris) === JSON.stringify(redirectUris) && JSON.stringify(client.webOrigins) === JSON.stringify(webOrigins)) return 'sin cambios';
  await api('PUT', `${REALM}/clients/${client.id}`, { ...client, redirectUris, webOrigins });
  return 'actualizado';
}

export async function main(command, env = process.env) {
  if (!['reconcile', 'verify'].includes(command)) throw new Error('Uso: node scripts/staging-keycloak.mjs reconcile|verify');
  const config = loadStagingConfig(env);
  const api = await adminClient(config.adminUrl, config.adminPassword, config.adminUser);
  const target = { realm: REALM, client: CLIENT, origin: config.origin, mode: 'staging' };
  if (command === 'verify') {
    await verifyKeycloak(api, target);
    console.log('OK: el realm %s cumple el perfil staging (sslRequired=external, origen %s).', REALM, config.origin);
    return;
  }
  await reconcileKeycloak(api, { ...target, clientSecret: config.clientSecret });
  console.log('OK: realm %s y cliente %s reconciliados y verificados (origen %s).', REALM, CLIENT, config.origin);
  console.log('Usuario operador %s: %s. Contraseña temporal; TOTP y cambio de contraseña se exigen en el primer login.', config.operatorUser, await ensureOperator(api, config));
  const publicOrigin = env.HUKID_KC_PUBLIC_ORIGIN;
  if (!publicOrigin) console.log('account-console: omitido (define HUKID_KC_PUBLIC_ORIGIN, el origen público de Keycloak).');
  else if (!validOrigin(publicOrigin)) throw new Error('HUKID_KC_PUBLIC_ORIGIN debe ser un origen https público en minúsculas, sin puerto ni ruta');
  else console.log('account-console: %s.', await ensureAccountConsole(api, publicOrigin));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { await main(process.argv[2]); } catch (error) { console.error(error.message); process.exit(1); }
}
