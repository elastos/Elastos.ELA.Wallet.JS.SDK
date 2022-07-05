// Copyright (c) 2012-2022 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

import { ErrorChecker, Error } from "../common/ErrorChecker";
import { Log } from "../common/Log";
import { json } from "../types";
import { CoinInfo } from "./CoinInfo";
import { ElaWebWalletJson } from "./ElaWebWalletJson";
import { HDKey, KeySpec } from "./hdkey";
import { Mnemonic } from "./mnemonic";
import { Secp256 } from "./secp256";

export class ElaNewWalletJson extends ElaWebWalletJson {
  private _coinInfoList: CoinInfo[];
  private _ownerPubKey: string;
  private _xPubKeyHDPM: string;
  private _seed: string;
  private _ethscPrimaryPubKey: string;
  private _ripplePrimaryPubKey: string;
  private _xPubKeyBitcoin: string;
  private _singlePrivateKey: string; // just for eth side chain now
  private _singleAddress: boolean;

  constructor() {
    super();
    this._singleAddress = false;
  }

  ddCoinInfo(info: CoinInfo) {
    this._coinInfoList.push(info);
  }

  clearCoinInfo() {
    this._coinInfoList = [];
  }

  getCoinInfoList(): CoinInfo[] {
    return this._coinInfoList;
  }

  setCoinInfoList(list: CoinInfo[]) {
    this._coinInfoList = list;
  }

  singleAddress(): boolean {
    return this._singleAddress;
  }

  setSingleAddress(value: boolean) {
    this._singleAddress = value;
  }

  ownerPubKey(): string {
    return this._ownerPubKey;
  }

  setOwnerPubKey(pubkey: string) {
    this._ownerPubKey = pubkey;
  }

  xPubKeyHDPM(): string {
    return this._xPubKeyHDPM;
  }

  setxPubKeyHDPM(xpub: string) {
    this._xPubKeyHDPM = xpub;
  }

  getSeed(): string {
    return this._seed;
  }

  setSeed(seed: string) {
    this._seed = seed;
  }

  getETHSCPrimaryPubKey(): string {
    return this._ethscPrimaryPubKey;
  }

  setETHSCPrimaryPubKey(pubkey: string) {
    this._ethscPrimaryPubKey = pubkey;
  }

  getxPubKeyBitcoin(): string {
    return this._xPubKeyBitcoin;
  }

  setxPubKeyBitcoin(xpub: string) {
    this._xPubKeyBitcoin = xpub;
  }

  getSinglePrivateKey(): string {
    return this._singlePrivateKey;
  }

  setSinglePrivateKey(prvkey: string) {
    this._singlePrivateKey = prvkey;
  }

  getRipplePrimaryPubKey(): string {
    return this._ripplePrimaryPubKey;
  }

  setRipplePrimaryPubKey(pubkey: string) {
    this._ripplePrimaryPubKey = pubkey;
  }

  toJson(withPrivKey: boolean) {
    // let j = ElaWebWalletJson.toJson(withPrivKey);
    // this.toJsonCommon(j);
    // return j;
  }

  fromJson(j: json) {
    // ElaWebWalletJson::FromJson(j);
    // this.fromJsonCommon(j);
  }

  private toJsonCommon(j: json) {
    let coinInfoList = [];
    for (let i = 0; i < this._coinInfoList.length; ++i)
      coinInfoList.push(this._coinInfoList[i].toJson());

    j["CoinInfoList"] = coinInfoList;
    j["SingleAddress"] = this._singleAddress;
    j["OwnerPubKey"] = this._ownerPubKey;
    j["xPubKeyHDPM"] = this._xPubKeyHDPM;
    j["seed"] = this._seed;
    j["ethscPrimaryPubKey"] = this._ethscPrimaryPubKey;
    j["xPubKeyBitcoin"] = this._xPubKeyBitcoin;
    j["singlePrivateKey"] = this._singlePrivateKey;
    j["ripplePrimaryPubKey"] = this._ripplePrimaryPubKey;
  }

  private fromJsonCommon(j: json) {
    if (j["CoinInfoList"]) {
      this._coinInfoList = [];
      let coinInfoList = j["CoinInfoList"] as [];
      for (let i = 0; i < coinInfoList.length; ++i) {
        let coinInfo = new CoinInfo();
        coinInfo.fromJson(coinInfoList[i]);
        this._coinInfoList.push(coinInfo);
      }
    }

    if (j["SingleAddress"]) {
      this._singleAddress = j["SingleAddress"] as boolean;
    }

    if (j["OwnerPubKey"]) {
      this._ownerPubKey = j["OwnerPubKey"] as string;
    }

    if (j["xPubKeyHDPM"]) {
      this._xPubKeyHDPM = j["xPubKeyHDPM"] as string;
    }

    if (j["ethscPrimaryPubKey"]) {
      this._ethscPrimaryPubKey = j["ethscPrimaryPubKey"] as string;
    }

    if (j["ripplePrimaryPubKey"]) {
      this._ripplePrimaryPubKey = j["ripplePrimaryPubKey"] as string;
    }

    if (j["xPubKeyBitcoin"]) {
      this._xPubKeyBitcoin = j["xPubKeyBitcoin"] as string;
    }

    if (j["CoSigners"] && j["Type"] == "MultiSign") {
      ErrorChecker.throwParamException(
        Error.Code.KeyStore,
        "Unsupport old version multi-sign keystore"
      );
    }

    if (j["RequiredSignCount"]) {
      ErrorChecker.throwParamException(
        Error.Code.KeyStore,
        "Unsupport old version multi-sign keystore"
      );
    }

    let passphrase = "";
    if (j["PhrasePassword"]) {
      passphrase = j["PhrasePassword"] as string;
      if (!passphrase) this._mnemonicHasPassphrase = true;
    }

    if (j["IsSingleAddress"]) {
      this._singleAddress = j["IsSingleAddress"] as boolean;
    }

    if (j["seed"]) {
      this._seed = j["seed"] as string;
    }

    if (j["singlePrivateKey"]) {
      this._singlePrivateKey = j["singlePrivateKey"] as string;
    }

    if (
      !this._seed &&
      this._mnemonic &&
      (!this._mnemonicHasPassphrase ||
        (this._mnemonicHasPassphrase && passphrase))
    ) {
      Log.info("Regerate seed from old keystore");
      let seed = Mnemonic.toSeed(this._mnemonic, passphrase);

      this._seed = seed.toString("hex");
    }

    if (!this._xPrivKey && this._seed) {
      Log.info("Regenerate xprv from old keystore");
      let seedBytes = Buffer.from(this._seed, "hex");
      let rootkey = HDKey.fromMasterSeed(seedBytes, KeySpec.Elastos);
      this._xPrivKey = rootkey.serializeBase58();
    }

    if (this._xPrivKey) {
      let rootkey = HDKey.deserializeBase58(this._xPrivKey, KeySpec.Elastos);

      this._ownerPubKey = rootkey
        .deriveWithPath("m/44'/0'/1'/0/0")
        .getPublicKeyBytes()
        .toString("hex");
      this._xPubKeyHDPM = rootkey
        .deriveWithPath("m/45'")
        .serializePublicKeyBase58();
      this._xPubKey = rootkey
        .deriveWithPath("m/44'/0'/0'")
        .serializePublicKeyBase58();

      let requestKey = rootkey.deriveWithPath("m/1'/0");
      this._requestPrivKey = requestKey.getPrivateKeyBytes().toString("hex");
      this._requestPubKey = requestKey.getPublicKeyBytes().toString("hex");
    }

    if (!this._ethscPrimaryPubKey && this._seed) {
      let seedBytes = Buffer.from(this._seed, "hex");
      let rootkey = HDKey.fromMasterSeed(seedBytes, KeySpec.Bitcoin);

      const secp256 = new Secp256(Secp256.CURVE_K1);
      this._ethscPrimaryPubKey = secp256
        .publicKeyConvert(
          rootkey.deriveWithPath("m/44'/60'/0'/0/0").getPublicKeyBytes(),
          false
        )
        .toString("hex");
    }

    if (!this._ripplePrimaryPubKey && !this._seed) {
      let seedBytes = Buffer.from(this._seed, "hex");
      let rootkey = HDKey.fromMasterSeed(seedBytes, KeySpec.Bitcoin);
      this._ripplePrimaryPubKey = rootkey
        .deriveWithPath("m/44'/144'/0'/0/0")
        .getPublicKeyBytes()
        .toString("hex");
    }

    if (!this._xPubKeyBitcoin && this._seed) {
      Log.info("Regenerate btc masterPubKey from old keystore");
      let seedBytes = Buffer.from(this._seed, "hex");
      let rootkey = HDKey.fromMasterSeed(seedBytes, KeySpec.Bitcoin);

      this._xPubKeyBitcoin = rootkey
        .deriveWithPath("m/44'/0'/0'")
        .serializePublicKeyBase58();
    }
  }
}
