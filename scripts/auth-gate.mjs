// Reproducible local/CI laboratory gate. Reports contain metadata, never logs/env.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const npm = process.env.npm_execpath;
if (!npm) throw new Error('Run npm run test:auth:gate');
function git(args) {
  const result = spawnSync('git', args, { cwd: root, encoding: 'utf8', windowsHide: true });
  if (result.error || result.status !== 0) throw new Error('Cannot identify gate source');
  return result.stdout;
}
function sourceDigest() {
  const hash = createHash('sha256');
  const files = git(['ls-files', '--cached', '--others', '--exclude-standard', '-z']).split('\0').filter(Boolean).sort();
  for (const name of files) {
    const data = readFileSync(path.join(root, name));
    hash.update(name + '\0' + data.length + '\0');
    hash.update(data);
  }
  return hash.digest('hex');
}
const report = {
  scope: 'laboratory', startedAt: new Date().toISOString(), head: git(['rev-parse', 'HEAD']).trim(),
  dirty: git(['status', '--porcelain']).trim() !== '', sourceDigest: sourceDigest(), node: process.version,
  status: 'running', steps: ['check', 'build', 'test:postgres', 'smoke', 'test:browser'].map(command => ({ command, status: 'pending' })),
};
const directory = path.join(root, '.cache', 'auth-gate');
mkdirSync(directory, { recursive: true });
const output = path.join(directory, 'latest.json');
function save() { writeFileSync(output, JSON.stringify(report, null, 2) + '\n'); }
save();
for (const step of report.steps) {
  step.status = 'running';
  save();
  const start = Date.now();
  const result = spawnSync(process.execPath, [npm, 'run', step.command], { cwd: root, stdio: 'inherit', windowsHide: true });
  step.elapsedMs = Date.now() - start;
  step.exitCode = result.status;
  step.status = !result.error && result.status === 0 ? 'passed' : 'failed';
  save();
  if (step.status === 'failed') { report.status = 'failed'; process.exitCode = 1; break; }
}
if (report.status === 'running') report.status = 'passed';
if (sourceDigest() !== report.sourceDigest) { report.status = 'source_changed'; process.exitCode = 1; }
report.finishedAt = new Date().toISOString();
save();
console.log('Authentication laboratory gate: ' + report.status + '; report .cache/auth-gate/latest.json');
