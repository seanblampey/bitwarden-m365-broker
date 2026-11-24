const MIN_SECRET_LENGTH = 4;
const REDACTED = '[REDACTED]';
const JWT_RE = /eyJ[\w-]+\.[\w-]+\.[\w-]*/g;

/** Removes registered secrets and JWT-shaped tokens from text. */
export class Redactor {
  private secrets: string[] = [];

  add(secret: string | undefined): void {
    if (!secret || secret.length < MIN_SECRET_LENGTH) return;
    if (this.secrets.includes(secret)) return;
    this.secrets.push(secret);
    this.secrets.sort((a, b) => b.length - a.length);
  }

  scrub(text: string): string {
    let out = text;
    for (const s of this.secrets) out = out.split(s).join(REDACTED);
    return out.replace(JWT_RE, REDACTED);
  }

  scrubDeep<T>(value: T): T {
    if (typeof value === 'string') return this.scrub(value) as unknown as T;
    if (Array.isArray(value)) return value.map((v) => this.scrubDeep(v)) as unknown as T;
    if (value && typeof value === 'object') {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value)) out[this.scrub(k)] = this.scrubDeep(v);
      return out as T;
    }
    return value;
  }
}
