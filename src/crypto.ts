import { createHash, randomBytes } from 'node:crypto';
import { BrokerError } from './errors.js';
import * as OTPAuth from 'otpauth';

const BAD_SEED = () => new BrokerError('bad_totp_seed', 'TOTP seed is not valid base32 or otpauth URI.');

/** Current TOTP code from a base32 seed or an otpauth:// URI. */
export function totp(seed: string, nowMs: number = Date.now()): string {
  try {
    const s = seed.trim();
    const t = s.toLowerCase().startsWith('otpauth://')
      ? OTPAuth.URI.parse(s)
      : new OTPAuth.TOTP({ secret: OTPAuth.Secret.fromBase32(s.replace(/\s+/g, '').toUpperCase()) });
    if (!(t instanceof OTPAuth.TOTP)) throw BAD_SEED();
    return t.generate({ timestamp: nowMs });
  } catch {
    throw BAD_SEED();
  }
}

export function pkcePair(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}
