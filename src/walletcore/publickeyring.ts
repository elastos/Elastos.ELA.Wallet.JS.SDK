export type PublicKeyRingInfo = {
  xPubKey: string;
  requestPubKey: string;
};

export class PublicKeyRing {
  private _xPubKey: string;
  private _requestPubKey: string;

  constructor(pubkey?: string, xpub?: string) {
    this._xPubKey = xpub;
    this._requestPubKey = pubkey;
  }

  public toJson(): PublicKeyRingInfo {
    return {
      xPubKey: this._xPubKey,
      requestPubKey: this._requestPubKey
    };
  }

  public fromJson(j: PublicKeyRingInfo): PublicKeyRing {
    this._xPubKey = j["xPubKey"] as string;
    this._requestPubKey = j["requestPubKey"] as string;
    return this;
  }

  public getxPubKey(): string {
    return this._xPubKey;
  }

  public getRequestPubKey(): string {
    return this._requestPubKey;
  }

  public setRequestPubKey(pubkey: string) {
    this._requestPubKey = pubkey;
  }

  public setxPubKey(xpubkey: string) {
    this._xPubKey = xpubkey;
  }
}
