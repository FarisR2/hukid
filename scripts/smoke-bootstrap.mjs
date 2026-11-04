import { spawn, spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const binary = path.join(root, '.cache', 'build', process.platform === 'win32' ? 'hukid-api.exe' : 'hukid-api');
const children = [];
let startupError;
function start(executable, args, env = process.env) {
  const child = spawn(executable, args, { cwd: root, env, stdio: 'ignore' });
  child.on('error', error => { startupError = error; });
  children.push(child);
}
async function ready(url) {
  for (let attempt = 0; attempt < 50; attempt++) {
    if (startupError) throw startupError;
    if (children.some(child => child.exitCode !== null)) throw new Error('Bootstrap process exited; verify the build and available smoke ports.');
    try {
      return await fetch(url, { signal: AbortSignal.timeout(1000) });
    } catch {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
  }
  throw new Error(`Startup timeout: ${url}`);
}
function assert(condition, message) {
  if (!condition) throw new Error(message);
}

try {
  const policyPath = path.join(root, 'src', 'platform', 'config', 'auth.test.json');
  for (const env of [
    { HUKID_ENV: 'production', HUKID_AUTH_POLICY: policyPath },
    { HUKID_ENV: 'test', HUKID_AUTH_POLICY: '' },
  ]) {
    const rejected = spawnSync(binary, [], { cwd: root, env: { ...process.env, ...env }, encoding: 'utf8', timeout: 10000 });
    assert(rejected.status === 1, `Unsafe auth configuration did not stop before listening (status=${rejected.status}, error=${rejected.error?.code || 'none'}, signal=${rejected.signal || 'none'})`);
  }
  start(binary, [], { ...process.env, HUKID_LISTEN_ADDR: '127.0.0.1:18080', HUKID_ENV: 'test', HUKID_AUTH_POLICY: policyPath });
  start(process.execPath, ['node_modules/vite/bin/vite.js', 'preview', 'src/console', '--host', '127.0.0.1', '--port', '14173', '--strictPort']);
  const health = await ready('http://127.0.0.1:18080/healthz');
  assert(health.status === 204 && health.headers.get('cache-control') === 'no-store', 'Invalid liveness');
  const unavailable = await fetch('http://127.0.0.1:18080/console/auth/login');
  assert(unavailable.status === 404, 'Unexpected auth route');
  const page = await ready('http://127.0.0.1:14173/');
  const html = await page.text();
  const match = html.match(/src="([^"]+\.js)"/);
  assert(page.status === 200 && html.includes('lang="es"') && match, 'Invalid console build');
  const asset = await fetch(new URL(match[1], 'http://127.0.0.1:14173'));
  assert(asset.status === 200, 'Console asset unavailable');
  console.log('Smoke: invalid/production auth policy stops startup; valid test policy starts Go health 204/no-store; auth 404; console HTML and JS 200.');
} finally {
  for (const child of children) child.kill();
}
