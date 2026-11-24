// Builds dist/ as self-contained files so the plugin works straight from a
// GitHub install, with no `npm install` or build step on the user's machine.
//   dist/server.js        MCP server (dependencies inlined, except playwright-core)
//   dist/node_modules/playwright-core  shipped as-is: it reads its own files at runtime
//   dist/hook/main.js     PreToolUse guard hook
//   dist/win/*.ps1, dist/exo/*.ps1  PowerShell helpers
import { build } from 'esbuild';
import { rmSync, cpSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const dist = join(root, 'dist');

rmSync(dist, { recursive: true, force: true });

const common = {
  bundle: true,
  platform: 'node',
  target: 'node20',
  format: 'esm',
  legalComments: 'none',
  logLevel: 'warning',
  // Some dependencies are CommonJS and call require(); give the ESM bundle one.
  banner: {
    js: "import { createRequire as __cr } from 'node:module'; const require = __cr(import.meta.url);",
  },
};

await build({
  ...common,
  entryPoints: [join(root, 'src/server.ts')],
  outfile: join(dist, 'server.js'),
  external: ['playwright-core'],
});
cpSync(join(root, 'node_modules/playwright-core'), join(dist, 'node_modules/playwright-core'), {
  recursive: true,
  filter: (src) => !src.includes(`${'playwright-core'}/types`) && !src.endsWith('.d.ts'),
});
await build({ ...common, entryPoints: [join(root, 'src/hook/main.ts')], outfile: join(dist, 'hook/main.js') });

await import('./copy-assets.mjs');
