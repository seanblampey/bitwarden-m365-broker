/** Error whose `message` is safe to show Claude (never contains secrets). */
export class BrokerError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = 'BrokerError';
    this.code = code;
  }
}
