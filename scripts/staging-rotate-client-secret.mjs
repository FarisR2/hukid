// Rotates the hukid-console client secret for staging without ever printing it.
//   node scripts/staging-rotate-client-secret.mjs
// It writes one new random value to BOTH files that must agree and prints only variable names:
//   .env.staging          HUKID_KC_CLIENT_SECRET   (read by scripts/staging-keycloak.mjs)
//   .env.staging.compose  HUKID_OIDC_CLIENT_SECRET (pasted into Dokploy for the API)
// Both files are ignored by git (.env.*). Keycloak is NOT touched here: the new secret takes effect
// when you run `node scripts/staging-keycloak.mjs reconcile`, then redeploy the API with the new
// environment. See scripts/README.md for the order and the short login gap between those steps.
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

export const TARGETS = [
  { file: '.env.staging', name: 'HUKID_KC_CLIENT_SECRET' },
  { file: '.env.staging.compose', name: 'HUKID_OIDC_CLIENT_SECRET' },
];

// Replaces the value of `name`, or appends it when absent. Other lines are kept byte for byte.
export function setVariable(text, name, value) {
  const line = new RegExp(`^${name}=.*$`, 'm');
  if (line.test(text)) return text.replace(line, () => `${name}=${value}`);
  return `${text.replace(/\n*$/, '\n')}${name}=${value}\n`;
}

export function rotate(files, secret) {
  if (!/^[0-9a-f]{64}$/.test(secret)) throw new Error('El secreto nuevo debe tener 64 caracteres hexadecimales');
  return Object.fromEntries(TARGETS.map(({ file, name }) => [file, setVariable(files[file], name, secret)]));
}

export function main(root = process.cwd()) {
  const paths = Object.fromEntries(TARGETS.map(({ file }) => [file, `${root}/${file}`]));
  const missing = TARGETS.filter(({ file }) => !existsSync(paths[file])).map(({ file }) => file);
  if (missing.length) throw new Error(`Faltan archivos: ${missing.join(', ')}`);
  const current = Object.fromEntries(TARGETS.map(({ file }) => [file, readFileSync(paths[file], 'utf8')]));
  const next = rotate(current, randomBytes(32).toString('hex'));
  // Validate everything first, then write both: a failure cannot leave only one file rotated.
  for (const { file } of TARGETS) writeFileSync(paths[file], next[file]);
  console.log(`Rotado en: ${TARGETS.map(({ file, name }) => `${file} (${name})`).join(', ')}`);
  console.log('Siguiente: reconcile en Keycloak y redespliegue de la API con el nuevo entorno.');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { main(); } catch (error) { console.error(error.message); process.exit(1); }
}
