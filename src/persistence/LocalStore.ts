/*
 * Copyright (c) 2022 Elastos Foundation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

import { Error, ErrorChecker } from "../common/ErrorChecker";
import { AESDecrypt, AESEncrypt } from "../walletcore/aes";
import { CoinInfo, ChainIDInfo } from "../walletcore/CoinInfo";
import { PublicKeyRing, PublicKeyRingInfo } from "../walletcore/publickeyring";
import { WalletStorage } from "./WalletStorage";

export type LocalStoreInfo = {
  xPrivKey: string;
  xPubKey: string;
  xPubKeyHDPM?: string;
  requestPrivKey: string;
  requestPubKey: string;
  publicKeyRing: PublicKeyRingInfo[];
  m: number; // Multisign - number of required signers
  n: number; // Multisign - total number of signers
  mnemonicHasPassphrase: boolean;
  derivationStrategy: string;
  account: number;
  mnemonic: string;
  passphrase: string;
  ownerPubKey: string;
  singleAddress: boolean;
  readonly: boolean;
  coinInfo?: ChainIDInfo[];
  seed?: string;
  ethscPrimaryPubKey?: string;
  ripplePrimaryPubKey?: string;
  xPubKeyBitcoin?: string;
  SinglePrivateKey?: string;
};

export class LocalStore {
  // encrypted
  private _xPrivKey: string;
  private _requestPrivKey: string;
  private _mnemonic: string;
  private _passphrase: string;
  private _singlePrivateKey: string;
  private _seed: string;

  // plain text
  private _xPubKey: string;
  private _xPubKeyHDPM: string; // BIP45 / BIP44 (compatible with web wallet)
  private _requestPubKey: string;
  private _ownerPubKey: string;
  private _derivationStrategy: string;

  private _publicKeyRing: PublicKeyRing[];

  // Multisign - number of requested signatures
  private _m: number;
  // Multisign - total number of requested public keys
  private _n: number;

  private _account: number;

  private _mnemonicHasPassphrase: boolean;
  private _singleAddress: boolean;
  private _readonly: boolean;

  // for ethsc
  private _ethscPrimaryPubKey: string;

  // for ripple
  private _ripplePrimaryPubKey: string;

  // for btc
  private _xPubKeyBitcoin: string;

  private _subWalletsInfoList: CoinInfo[] = [];
  private _masterWalletID: string;
  private _walletStorage: WalletStorage;

  private toJson(): LocalStoreInfo {
    let j = <LocalStoreInfo>{};

    j["xPrivKey"] = this._xPrivKey;
    j["xPubKey"] = this._xPubKey;
    j["xPubKeyHDPM"] = this._xPubKeyHDPM;
    j["requestPrivKey"] = this._requestPrivKey;
    j["requestPubKey"] = this._requestPubKey;
    j["publicKeyRing"] =
      this._publicKeyRing.length > 0
        ? this._publicKeyRing.map((pkr) => pkr.toJson())
        : null;
    j["m"] = this._m;
    j["n"] = this._n;
    j["mnemonicHasPassphrase"] = this._mnemonicHasPassphrase;
    j["derivationStrategy"] = this._derivationStrategy;
    j["account"] = this._account;
    j["mnemonic"] = this._mnemonic;
    j["passphrase"] = this._mnemonicHasPassphrase ? this._passphrase : "";
    j["ownerPubKey"] = this._ownerPubKey;
    j["singleAddress"] = this._singleAddress;
    j["readonly"] = this._readonly;
    j["coinInfo"] =
      this._subWalletsInfoList && this._subWalletsInfoList.length > 0
        ? this._subWalletsInfoList.map((c) => c.toJson())
        : null;
    j["seed"] = this._seed;
    j["ethscPrimaryPubKey"] = this._ethscPrimaryPubKey;
    j["ripplePrimaryPubKey"] = this._ripplePrimaryPubKey;
    j["xPubKeyBitcoin"] = this._xPubKeyBitcoin;
    j["SinglePrivateKey"] = this._singlePrivateKey;

    return j;
  }

  private fromJson(j: LocalStoreInfo) {
    try {
      // new version of localstore
      this._xPrivKey = j["xPrivKey"] as string;
      this._mnemonic = j["mnemonic"] as string;
      this._xPubKey = j["xPubKey"] as string;
      this._requestPrivKey = j["requestPrivKey"] as string;
      this._requestPubKey = j["requestPubKey"] as string;
      this._publicKeyRing = (j["publicKeyRing"] as PublicKeyRingInfo[]).map(
        (pkr) => new PublicKeyRing().fromJson(pkr as PublicKeyRingInfo)
      );
      this._m = j["m"] as number;
      this._n = j["n"] as number;
      this._mnemonicHasPassphrase = j["mnemonicHasPassphrase"] as boolean;
      this._derivationStrategy = j["derivationStrategy"] as string;
      this._account = j["account"] as number;
      this._passphrase = j["passphrase"] as string;
      this._ownerPubKey = j["ownerPubKey"] as string;
      this._singleAddress = j["singleAddress"] as boolean;
      this._readonly = j["readonly"] as boolean;

      if ("xPubKeyHDPM" in j) {
        this._xPubKeyHDPM = j["xPubKeyHDPM"] as string;
      } else {
        this._xPubKeyHDPM = null;
      }

      if ("seed" in j) {
        this._seed = j["seed"] as string;
      } else {
        this._seed = null;
      }

      if ("SinglePrivateKey" in j) {
        this._singlePrivateKey = j["SinglePrivateKey"] as string;
      } else {
        this._singlePrivateKey = null;
      }

      if ("ethscPrimaryPubKey" in j) {
        this._ethscPrimaryPubKey = j["ethscPrimaryPubKey"] as string;
        let isEmpty = true;
        for (let i = 2; i < this._ethscPrimaryPubKey.length; ++i) {
          if (this._ethscPrimaryPubKey[i] != "0") {
            isEmpty = false;
            break;
          }
        }
        if (
          isEmpty ||
          this._ethscPrimaryPubKey[0] != "0" ||
          this._ethscPrimaryPubKey[1] != "4"
        )
          this._ethscPrimaryPubKey = null;
      } else {
        this._ethscPrimaryPubKey = null;
      }

      if ("ripplePrimaryPubKey" in j) {
        this._ripplePrimaryPubKey = j["ripplePrimaryPubKey"] as string;
      } else {
        this._ripplePrimaryPubKey = null;
      }

      // support btc
      if ("xPubKeyBitcoin" in j) {
        this._xPubKeyBitcoin = j["xPubKeyBitcoin"] as string;
      } else {
        this._xPubKeyBitcoin = null;
      }

      this._subWalletsInfoList = (j["coinInfo"] as ChainIDInfo[]).map((j) =>
        new CoinInfo().fromJson(j as ChainIDInfo)
      );
    } catch (e) {
      ErrorChecker.throwLogicException(
        Error.Code.InvalidLocalStore,
        "Invalid localstore: can't read data from this localstore"
      );
    }
  }

  /* LocalStore::LocalStore(const nlohmann::json &store) {
		FromJson(store);
	} */

  /* LocalStore::LocalStore(const std::string &path) :
		_path(path),
		_account(0) {
	} */

  constructor(walletStorage: WalletStorage, masterWalletID: string) {
    this._walletStorage = walletStorage;
    this._account = 0;
    this._masterWalletID = masterWalletID;
  }

  changePasswd(oldPasswd: string, newPasswd: string) {
    let bytes = AESDecrypt(this._mnemonic, oldPasswd);
    this._mnemonic = AESEncrypt(bytes, newPasswd);

    bytes = AESDecrypt(this._xPrivKey, oldPasswd);
    this._xPrivKey = AESEncrypt(bytes, newPasswd);

    bytes = AESDecrypt(this._requestPrivKey, oldPasswd);
    this._requestPrivKey = AESEncrypt(bytes, newPasswd);

    bytes = AESDecrypt(this._seed, oldPasswd);
    this._seed = AESEncrypt(bytes, newPasswd);

    bytes = AESDecrypt(this._singlePrivateKey, oldPasswd);
    this._singlePrivateKey = AESEncrypt(bytes, newPasswd);
  }

  public async load(id: string): Promise<boolean> {
    let j = await this._walletStorage.loadStore(id);

    ErrorChecker.checkLogic(
      !j,
      Error.Code.InvalidLocalStore,
      "local store content is empty"
    );

    this.fromJson(j);

    return true;
  }

  async save(): Promise<void> {
    await this._walletStorage.saveStore(this._masterWalletID, this.toJson());
  }

  async remove(): Promise<void> {
    await this._walletStorage.removeStore(this._masterWalletID);
  }

  getDataPath(): Promise<string> {
    return Promise.resolve(this._masterWalletID);
  }

  async saveTo(masterWalletID: string): Promise<void> {
    this._masterWalletID = masterWalletID;
    await this.save();
  }

  public singleAddress(): boolean {
    return this._singleAddress;
  }

  public setSingleAddress(status: boolean) {
    this._singleAddress = status;
  }

  getxPrivKey(): string {
    return this._xPrivKey;
  }

  public setxPrivKey(xprvkey: string) {
    this._xPrivKey = xprvkey;
  }

  getRequestPrivKey(): string {
    return this._requestPrivKey;
  }

  public setRequestPrivKey(prvkey: string) {
    this._requestPrivKey = prvkey;
  }

  getMnemonic(): string {
    return this._mnemonic;
  }

  public setMnemonic(mnemonic: string) {
    this._mnemonic = mnemonic;
  }

  getPassPhrase(): string {
    return this._passphrase;
  }

  public setPassPhrase(passphrase: string) {
    this._passphrase = passphrase;
  }

  getxPubKey(): string {
    return this._xPubKey;
  }

  public setxPubKey(xpubkey: string) {
    this._xPubKey = xpubkey;
  }

  getxPubKeyHDPM(): string {
    return this._xPubKeyHDPM;
  }

  public setxPubKeyHDPM(xpub: string) {
    this._xPubKeyHDPM = xpub;
  }

  getRequestPubKey(): string {
    return this._requestPubKey;
  }

  public setRequestPubKey(pubkey: string) {
    this._requestPubKey = pubkey;
  }

  getOwnerPubKey(): string {
    return this._ownerPubKey;
  }

  public setOwnerPubKey(ownerPubKey: string) {
    this._ownerPubKey = ownerPubKey;
  }

  derivationStrategy(): string {
    return this._derivationStrategy;
  }

  public setDerivationStrategy(strategy: string) {
    this._derivationStrategy = strategy;
  }

  public getPublicKeyRing(): PublicKeyRing[] {
    return this._publicKeyRing;
  }

  public addPublicKeyRing(ring: PublicKeyRing) {
    this._publicKeyRing.push(ring);
  }

  public setPublicKeyRing(pubKeyRing: PublicKeyRing[]) {
    this._publicKeyRing = pubKeyRing;
  }

  getM(): number {
    return this._m;
  }

  public setM(m: number) {
    this._m = m;
  }

  getN(): number {
    return this._n;
  }

  public setN(n: number) {
    this._n = n;
  }

  hasPassPhrase(): boolean {
    return this._mnemonicHasPassphrase;
  }

  public setHasPassPhrase(has: boolean) {
    this._mnemonicHasPassphrase = has;
  }

  readonly(): boolean {
    return this._readonly;
  }

  public setReadonly(status: boolean) {
    this._readonly = status;
  }

  public account(): number {
    return this._account;
  }

  public setAccount(account: number) {
    this._account = account;
  }

  getSubWalletInfoList(): CoinInfo[] {
    return this._subWalletsInfoList;
  }

  public addSubWalletInfoList(info: CoinInfo) {
    this._subWalletsInfoList.push(info);
  }

  public removeSubWalletInfo(chainID: string) {
    this._subWalletsInfoList = this._subWalletsInfoList.filter(
      (ci) => ci.getChainID() !== chainID
    );
  }

  public setSubWalletInfoList(infoList: CoinInfo[]) {
    this._subWalletsInfoList = infoList;
  }

  public clearSubWalletInfoList() {
    this._subWalletsInfoList = [];
  }

  public setSeed(seed: string) {
    this._seed = seed;
  }

  public getSeed(): string {
    return this._seed;
  }

  public setETHSCPrimaryPubKey(pubkey: string) {
    this._ethscPrimaryPubKey = pubkey;
  }

  public getETHSCPrimaryPubKey(): string {
    return this._ethscPrimaryPubKey;
  }

  public setxPubKeyBitcoin(xpub: string) {
    this._xPubKeyBitcoin = xpub;
  }

  public getxPubKeyBitcoin(): string {
    return this._xPubKeyBitcoin;
  }

  public setSinglePrivateKey(prvkey: string) {
    this._singlePrivateKey = prvkey;
  }

  public getSinglePrivateKey(): string {
    return this._singlePrivateKey;
  }

  public setRipplePrimaryPubKey(pubkey: string) {
    this._ripplePrimaryPubKey = pubkey;
  }

  public getRipplePrimaryPubKey(): string {
    return this._ripplePrimaryPubKey;
  }
}
