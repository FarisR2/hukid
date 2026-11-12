// Generates the API secrets for the staging compose file (deploy/staging/compose.yaml).
//   node scripts/staging-secrets.mjs      writes .env.staging.compose (gitignored by .env.*)
// Missing values are generated; existing ones are never overwritten, so a rerun cannot
// rotate a key by accident. Values are never printed: only variable names are.
// HUKID_OIDC_CLIENT_SECRET is reused from HUKID_KC_CLIENT_SECRET in .env.staging so the
// API and the Keycloak client agree. HUKID_DB_ADMIN_PASSWORD is the Dokploy database
// owner's password and is yours to fill in; it is never generated here.
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

export const ROLES = ['SESSION', 'CONTEXT', 'TENANT', 'MEMBERS', 'DASHBOARD'];
const KEYS = ['HUKID_AUTH_KEY', 'HUKID_INVITATION_KEY', 'HUKID_INVITATION_HMAC_KEY', 'HUKID_MEMBERS_CURSOR_KEY', 'HUKID_DASHBOARD_CURSOR_KEY'];
const VERSIONS = { HUKID_AUTH_KEY_VERSION: 'staging-1', HUKID_INVITATION_KEY_VERSION: 'staging-1' };
export const MANUAL = ['HUKID_DB_ADMIN_PASSWORD'];
const b64 = () => randomBytes(32).toString('base64');
const hex = () => randomBytes(24).toString('hex');

export function parseEnv(text) {
  const values = {};
  for (const line of text.split(/\r?\n/)) {
    const match = /^([A-Z0-9_]+)=(.*)$/.exec(line);
    if (match) values[match[1]] = match[2];
  }
  return values;
}

// Returns the complete value set plus the names that were newly created.
export function generate(existing = {}, oidcClientSecret = '') {
  const values = { ...existing };
  const created = [];
  const fill = (name, make) => { if (!values[name]) { values[name] = make(); created.push(name); } };
  for (const name of KEYS) fill(name, b64);
  for (const [name, version] of Object.entries(VERSIONS)) fill(name, () => version);
  for (const role of ROLES) fill(`HUKID_RUNTIME_PASSWORD_${role}`, hex);
  if (oidcClientSecret) fill('HUKID_OIDC_CLIENT_SECRET', () => oidcClientSecret);
  for (const name of MANUAL) if (!(name in values)) { values[name] = ''; created.push(name); }
  // Distinct-key rule enforced by the API (memberconfig/secrets.go); never reuse a value.
  const secrets = KEYS.map(name => values[name]);
  if (new Set(secrets).size !== secrets.length) throw new Error('Las claves de la API no pueden repetirse entre sí');
  return { values, created };
}

export function render(values) {
  return Object.entries(values).map(([name, value]) => `${name}=${value}`).join('\n') + '\n';
}

export function main(root = process.cwd()) {
  const target = `${root}/.env.staging.compose`;
  const keycloak = existsSync(`${root}/.env.staging`) ? parseEnv(readFileSync(`${root}/.env.staging`, 'utf8')) : {};
  const existing = existsSync(target) ? parseEnv(readFileSync(target, 'utf8')) : {};
  const { values, created } = generate(existing, keycloak.HUKID_KC_CLIENT_SECRET);
  writeFileSync(target, render(values), { mode: 0o600 });
  console.log('Archivo: .env.staging.compose (ignorado por git).');
  console.log(created.length ? `Creadas: ${created.join(', ')}` : 'Sin cambios: todas las variables ya existían.');
  const missing = [...MANUAL, 'HUKID_OIDC_CLIENT_SECRET'].filter(name => !values[name]);
  if (missing.length) console.log(`Falta rellenar a mano: ${missing.join(', ')}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { main(); } catch (error) { console.error(error.message); process.exit(1); }
}
