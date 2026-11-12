import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { TARGETS, main, rotate, setVariable } from './staging-rotate-client-secret.mjs';

const secret = 'a'.repeat(64);

test('setVariable replaces only the named value and keeps other lines untouched', () => {
  const out = setVariable('# nota\nHUKID_X=1\nHUKID_KC_CLIENT_SECRET=viejo\nHUKID_Y=2\n', 'HUKID_KC_CLIENT_SECRET', secret);
  assert.equal(out, `# nota\nHUKID_X=1\nHUKID_KC_CLIENT_SECRET=${secret}\nHUKID_Y=2\n`);
});

test('setVariable appends the variable when it is absent or the value is empty', () => {
  assert.equal(setVariable('HUKID_X=1', 'HUKID_KC_CLIENT_SECRET', secret), `HUKID_X=1\nHUKID_KC_CLIENT_SECRET=${secret}\n`);
  assert.equal(setVariable('HUKID_KC_CLIENT_SECRET=\n', 'HUKID_KC_CLIENT_SECRET', secret), `HUKID_KC_CLIENT_SECRET=${secret}\n`);
});

test('setVariable treats a dollar sequence in the value literally', () => {
  assert.equal(setVariable('A=1\n', 'A', '$&$1'), 'A=$&$1\n');
});

test('rotate rejects a secret that is not 64 hex characters', () => {
  for (const bad of ['', 'x'.repeat(64), 'a'.repeat(63), 'A'.repeat(64)]) {
    assert.throws(() => rotate({ '.env.staging': '', '.env.staging.compose': '' }, bad), /64 caracteres/);
  }
});

test('main writes the same new value to both files and prints only variable names', () => {
  const dir = mkdtempSync(join(tmpdir(), 'rotate-'));
  writeFileSync(join(dir, '.env.staging'), 'HUKID_KC_CLIENT_SECRET=\nHUKID_KC_ADMIN_USER=admin\n');
  writeFileSync(join(dir, '.env.staging.compose'), 'HUKID_AUTH_KEY=k\nHUKID_OIDC_CLIENT_SECRET=viejo\n');
  const lines = [];
  const original = console.log;
  console.log = (...args) => lines.push(args.join(' '));
  try { main(dir); } finally { console.log = original; }
  const values = TARGETS.map(({ file, name }) => new RegExp(`^${name}=(.*)$`, 'm').exec(readFileSync(join(dir, file), 'utf8'))[1]);
  assert.match(values[0], /^[0-9a-f]{64}$/);
  assert.equal(values[0], values[1]);
  assert.equal(lines.some(line => line.includes(values[0])), false, 'the secret must never be printed');
  assert.match(readFileSync(join(dir, '.env.staging'), 'utf8'), /HUKID_KC_ADMIN_USER=admin/);
  assert.match(readFileSync(join(dir, '.env.staging.compose'), 'utf8'), /HUKID_AUTH_KEY=k/);
});

test('main refuses to run when a target file is missing and writes nothing', () => {
  const dir = mkdtempSync(join(tmpdir(), 'rotate-'));
  writeFileSync(join(dir, '.env.staging'), 'HUKID_KC_CLIENT_SECRET=viejo\n');
  assert.throws(() => main(dir), /Faltan archivos: \.env\.staging\.compose/);
  assert.equal(readFileSync(join(dir, '.env.staging'), 'utf8'), 'HUKID_KC_CLIENT_SECRET=viejo\n');
});
