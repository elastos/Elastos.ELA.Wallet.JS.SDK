// Copyright (c) 2012-2018 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

import { PublicKeyRingInfo } from "./publickeyring";

export type BitcoreWalletClientInfo = {
  xPrivKey?: string;
  coin?: string;
  network?: string;
  xPubKey?: string;
  requestPrivKey?: string;
  requestPubKey?: string;
  copayerId?: string;
  publicKeyRing?: PublicKeyRingInfo[];
  walletId?: string;
  walletName?: string;
  m?: number;
  n?: number;
  walletPrivKey?: string;
  personalEncryptingKey?: string;
  sharedEncryptingKey?: string;
  copayerName?: string;
  entropySource?: string;
  mnemonicHasPassphrase?: boolean;
  derivationStrategy?: string;
  account?: number;
  compliantDerivation?: boolean;
  addressType?: string;
};

export class BitcoreWalletClientJson {
  protected _coin: string;
  protected _network: string;
  protected _xPrivKey: string;
  protected _xPubKey: string;
  protected _requestPrivKey: string;
  protected _requestPubKey: string;
  protected _copayerId: string;
  protected _publicKeyRing: PublicKeyRingInfo[];
  protected _walletId: string;
  protected _walletName: string;
  protected _m: number;
  protected _n: number;
  protected _walletPrivKey: string;
  protected _personalEncryptingKey: string;
  protected _sharedEncryptingKey: string;
  protected _copayerName: string;
  protected _entropySource: string;
  protected _mnemonicHasPassphrase: boolean;
  protected _derivationStrategy: string;
  protected _account: number;
  protected _compliantDerivation: boolean;
  protected _addressType: string;

  constructor() {
    this._m = 0;
    this._n = 0;
    this._account = 0;
    this._mnemonicHasPassphrase = false;
    this._compliantDerivation = false;
  }

  destroy() {
    this._xPrivKey = "";
    this._requestPrivKey = "";
  }

  xPrivKey(): string {
    return this._xPrivKey;
  }

  setxPrivKey(xprv: string) {
    this._xPrivKey = xprv;
  }

  xPubKey(): string {
    return this._xPubKey;
  }

  setxPubKey(xpub: string) {
    this._xPubKey = xpub;
  }

  requestPrivKey(): string {
    return this._requestPrivKey;
  }

  setRequestPrivKey(key: string) {
    this._requestPrivKey = key;
  }

  requestPubKey(): string {
    return this._requestPubKey;
  }

  setRequestPubKey(pubkey: string) {
    this._requestPubKey = pubkey;
  }

  hasPassPhrase(): boolean {
    return this._mnemonicHasPassphrase;
  }

  setHasPassPhrase(has: boolean) {
    this._mnemonicHasPassphrase = has;
  }

  getPublicKeyRing() {
    return this._publicKeyRing;
  }

  addPublicKeyRing(publicKeyRing: PublicKeyRingInfo) {
    this._publicKeyRing.push(publicKeyRing);
  }

  setPublicKeyRing(ring: PublicKeyRingInfo[]) {
    this._publicKeyRing = ring;
  }

  getM(): number {
    return this._m;
  }

  setM(m: number) {
    this._m = m;
  }

  getN(): number {
    return this._n;
  }

  setN(n: number) {
    this._n = n;
  }

  derivationStrategy(): string {
    return this._derivationStrategy;
  }

  setDerivationStrategy(strategy: string) {
    this._derivationStrategy = strategy;
  }

  account(): number {
    return this._account;
  }

  setAccount(account: number) {
    this._account = account;
  }

  toJson(withPrivKey: boolean) {
    let j = <BitcoreWalletClientInfo>{};
    j["xPrivKey"] = this._xPrivKey;
    j["coin"] = this._coin;
    j["network"] = this._network;
    j["xPubKey"] = this._xPubKey;
    j["requestPrivKey"] = this._requestPrivKey;
    j["requestPubKey"] = this._requestPubKey;
    j["copayerId"] = this._copayerId;
    j["publicKeyRing"] = this._publicKeyRing;
    j["walletId"] = this._walletId;
    j["walletName"] = this._walletName;
    j["m"] = this._m;
    j["n"] = this._n;
    j["walletPrivKey"] = this._walletPrivKey;
    j["personalEncryptingKey"] = this._personalEncryptingKey;
    j["sharedEncryptingKey"] = this._sharedEncryptingKey;
    j["copayerName"] = this._copayerName;
    j["entropySource"] = this._entropySource;
    j["mnemonicHasPassphrase"] = this._mnemonicHasPassphrase;
    j["derivationStrategy"] = this._derivationStrategy;
    j["account"] = this._account;
    j["compliantDerivation"] = this._compliantDerivation;
    j["addressType"] = this._addressType;

    if (!withPrivKey) {
      delete j.xPrivKey;
      delete j.requestPrivKey;
      delete j.coin;
      delete j.account;
      delete j.derivationStrategy;
      delete j.addressType;
      delete j.copayerId;
      delete j.copayerName;
      delete j.entropySource;
      delete j.personalEncryptingKey;
      delete j.walletPrivKey;
      delete j.walletName;
      delete j.walletId;
      delete j.sharedEncryptingKey;
      delete j.compliantDerivation;
    }

    return j;
  }

  fromJson(j: BitcoreWalletClientInfo) {
    this._coin = j["coin"] ? j["coin"] : "";
    this._network = j["network"] ? j["network"] : "";
    this._xPrivKey = j["xPrivKey"] ? j["xPrivKey"] : "";
    this._xPubKey = j["xPubKey"] ? j["xPubKey"] : "";
    this._requestPrivKey = j["requestPrivKey"] ? j["requestPrivKey"] : "";
    this._requestPubKey = j["requestPubKey"] ? j["requestPubKey"] : "";
    this._copayerId = j["copayerId"] ? j["copayerId"] : "";
    this._publicKeyRing = j["publicKeyRing"];
    this._walletId = j["walletId"] ? j["walletId"] : "";
    this._walletName = j["walletName"] ? j["walletName"] : "";
    this._m = j["m"] ? j["m"] : 0;
    this._n = j["n"] ? j["n"] : 0;
    this._walletPrivKey = j["walletPrivKey"] ? j["walletPrivKey"] : "";
    this._personalEncryptingKey = j["personalEncryptingKey"]
      ? j["personalEncryptingKey"]
      : "";
    this._sharedEncryptingKey = j["sharedEncryptingKey"]
      ? j["sharedEncryptingKey"]
      : "";
    this._copayerName = j["copayerName"] ? j["copayerName"] : "";
    this._entropySource = j["entropySource"] ? j["entropySource"] : "";
    this._mnemonicHasPassphrase = j["mnemonicHasPassphrase"]
      ? j["mnemonicHasPassphrase"]
      : false;
    this._derivationStrategy = j["derivationStrategy"]
      ? j["derivationStrategy"]
      : "";
    this._account = j["account"] ? j["account"] : 0;
    this._compliantDerivation = j["compliantDerivation"]
      ? j["compliantDerivation"]
      : false;
    this._addressType = j["addressType"] ? j["addressType"] : "";
  }
}
