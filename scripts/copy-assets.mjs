// Copies every src/**/*.ps1 to the same relative path under dist.
import { readdirSync, mkdirSync, copyFileSync } from 'node:fs';
import { join, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const src = join(root, 'src');
const dist = join(root, 'dist');

function walk(dir) {
  const out = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) out.push(...walk(p));
    else if (e.isFile() && e.name.endsWith('.ps1')) out.push(p);
  }
  return out;
}

for (const file of walk(src)) {
  const dest = join(dist, relative(src, file));
  mkdirSync(dirname(dest), { recursive: true });
  copyFileSync(file, dest);
}
