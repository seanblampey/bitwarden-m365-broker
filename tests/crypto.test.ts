import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { totp, pkcePair } from '../src/crypto.js';

const SEED = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

describe('totp', () => {
  it('matches RFC 6238 vector (6 digits)', () => {
    expect(totp(SEED, 59_000)).toBe('287082');
  });
  it('honours otpauth URI digits', () => {
    expect(totp(`otpauth://totp/x?secret=${SEED}&digits=8`, 59_000)).toBe('94287082');
  });
  it('honours otpauth URI period', () => {
    const uri = `otpauth://totp/x?secret=${SEED}&period=60`;
    expect(totp(uri, 59_000)).toBe(totp(uri, 0));
  });
  it('tolerates spaces/lowercase in base32', () => {
    expect(totp('gezd gnbv gy3t qojq gezd gnbv gy3t qojq', 59_000)).toBe('287082');
  });
});

describe('pkcePair', () => {
  it('produces S256 challenge of a base64url verifier', () => {
    const { verifier, challenge } = pkcePair();
    expect(verifier.length).toBeGreaterThanOrEqual(43);
    expect(verifier).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(challenge).toBe(createHash('sha256').update(verifier).digest('base64url'));
  });
  it('is random', () => {
    expect(pkcePair().verifier).not.toBe(pkcePair().verifier);
  });
});
