import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const result = spawnSync(process.execPath, ['--test', '--test-concurrency=1', 'tests/auth/*.test.mjs'], {
  cwd: fileURLToPath(new URL('../', import.meta.url)),
  env: { ...process.env, NODE_ENV: 'test', HUKID_TEST_IDP: '1', DEBUG: '' },
  stdio: 'inherit',
});
if (result.error) console.error(result.error.message);
process.exit(result.status ?? 1);
