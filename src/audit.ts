import { appendFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import type { Redactor } from './redact.js';

export type AuditEvent = {
  type: 'unlock' | 'lock' | 'connect' | 'signin_failed' | 'call' | 'approved' | 'denied' | 'error';
  tenant?: string;
  detail?: string;
};

export class AuditLog {
  constructor(private file: string, private redactor: Redactor) {}

  /** Appends one JSON line. Never throws: failures only warn on stderr. */
  write(e: AuditEvent): void {
    try {
      const line = this.redactor.scrub(
        JSON.stringify({ ts: new Date().toISOString(), ...e, ...(e.detail !== undefined ? { detail: this.redactor.scrub(e.detail) } : {}) }),
      );
      mkdirSync(dirname(this.file), { recursive: true });
      appendFileSync(this.file, line + '\n', 'utf8');
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code ?? 'error';
      try {
        process.stderr.write(`claude-bw-broker: audit log write failed (${code})\n`);
      } catch {
        /* nothing more to do */
      }
    }
  }
}
