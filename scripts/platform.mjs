import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const platform = path.join(root, 'src', 'platform');
const localGo = path.join(root, '.cache', 'toolchains', 'go1.27.3', 'go', 'bin', 'go.exe');
const executable = process.env.HUKID_GO || (process.platform === 'win32' && existsSync(localGo) ? localGo : 'go');
const env = { ...process.env, GOTOOLCHAIN: 'local', GOCACHE: path.join(root, '.cache', 'go-build'), GOMODCACHE: path.join(root, '.cache', 'go-mod') };

function run(args, capture = false, tool = executable) {
  const result = spawnSync(tool, args, {
    cwd: platform, env, encoding: 'utf8', stdio: capture ? 'pipe' : 'inherit',
  });
  if (result.error) {
    console.error(`No se pudo ejecutar Go: ${result.error.message}. Consulta docs/04-engineering/local-development.md.`);
    process.exit(1);
  }
  if (result.status !== 0) {
    if (capture) process.stderr.write(result.stderr || result.stdout || 'Go no terminó correctamente.\n');
    process.exit(result.status || 1);
  }
  return result.stdout;
}

const command = process.argv[2];
if (!['dev', 'check', 'build', 'test:postgres', 'migrate:test', 'bootstrap:test'].includes(command)) {
  console.error('Uso: node scripts/platform.mjs dev|check|build|test:postgres|migrate:test|bootstrap:test');
  process.exit(1);
}
const version = run(['version'], true).trim();
if (!/^go version go1\.27\.3\s/.test(version)) {
  console.error(`Se requiere Go 1.27.3; encontrado: ${version}`);
  process.exit(1);
}

if (command === 'dev') run(['run', './cmd/api']);
if (command === 'migrate:test') run(['run', './cmd/testdb', 'migrate']);
if (command === 'bootstrap:test') run(['run', './cmd/testdb', 'bootstrap']);
if (command === 'test:postgres') run(['test', '-tags=integration', '-count=1', '-timeout=120s', './internal/adapters/postgres']);
if (command === 'check') {
  const goroot = run(['env', 'GOROOT'], true).trim();
  const gofmt = path.join(goroot, 'bin', process.platform === 'win32' ? 'gofmt.exe' : 'gofmt');
  const unformatted = run(['-l', '.'], true, gofmt).trim();
  if (unformatted) {
    console.error(`Ejecuta go fmt ./... en src/platform:\n${unformatted}`);
    process.exit(1);
  }
  run(['vet', './...']);
  run(['test', '-count=1', './...']);
}
if (command === 'build') {
  const output = path.join(root, '.cache', 'build');
  mkdirSync(output, { recursive: true });
  run(['build', '-trimpath', '-o', path.join(output, process.platform === 'win32' ? 'hukid-api.exe' : 'hukid-api'), './cmd/api']);
}
