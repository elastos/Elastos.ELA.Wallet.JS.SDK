export class WalletErrorException extends Error {
  constructor(public code: number, public reason: string) {
    super(`Code: ${code}, Reason: ${reason}`);
    this.code = code;
    this.reason = reason;
    this.name = this.constructor.name;
  }
}
