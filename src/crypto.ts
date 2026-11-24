import { createHash, randomBytes } from 'node:crypto';
import * as OTPAuth from 'otpauth';

/** Current TOTP code from a base32 seed or an otpauth:// URI. */
export function totp(seed: string, nowMs: number = Date.now()): string {
  const s = seed.trim();
  const t = s.toLowerCase().startsWith('otpauth://')
    ? (OTPAuth.URI.parse(s) as OTPAuth.TOTP)
    : new OTPAuth.TOTP({ secret: OTPAuth.Secret.fromBase32(s.replace(/\s+/g, '').toUpperCase()) });
  return t.generate({ timestamp: nowMs });
}

export function pkcePair(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}
