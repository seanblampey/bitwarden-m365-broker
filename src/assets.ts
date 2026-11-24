import { fileURLToPath } from 'node:url';

/**
 * Absolute path of a bundled asset (e.g. 'win/password.ps1').
 * This file sits at the source root, and the bundle (dist/server.js) sits at
 * the dist root, so the same relative path works under vitest and when bundled.
 */
export function assetPath(rel: string): string {
  return fileURLToPath(new URL(`./${rel}`, import.meta.url));
}
