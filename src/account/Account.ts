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

import { Buffer } from "buffer";
import { ByteStream } from "../common/bytestream";
import { Error, ErrorChecker } from "../common/ErrorChecker";
import { Log } from "../common/Log";
import { LocalStore } from "../persistence/LocalStore";
import { WalletStorage } from "../persistence/WalletStorage";
import { bytes_t } from "../types";
import { AESDecrypt, AESEncrypt } from "../walletcore/aes";
import { Base58Check } from "../walletcore/base58";
import { CoinInfo } from "../walletcore/CoinInfo";
import { DeterministicKey } from "../walletcore/deterministickey";
import { HDKey, KeySpec } from "../walletcore/hdkey";
import { Mnemonic } from "../walletcore/mnemonic";
import { PublicKeyRing } from "../walletcore/publickeyring";
import { Secp256 } from "../walletcore/secp256";
import { ElaNewWalletJson } from "../walletcore/ElaNewWalletJson";
import { KeyStore } from "../walletcore/keystore";

export const MAX_MULTISIGN_COSIGNERS = 6;
const READONLY_WALLET_VERSION00 = 0;

export enum SignType {
  Standard,
  MultiSign
}

export type AccountBasicInfo = {
  Type: "MultiSign" | "Standard";
  Readonly: boolean;
  SingleAddress: boolean;
  M: number; // number of required signers
  N: number; // number of total co-signers
  HasPassPhrase: boolean;
};

export type AccountPubKeyInfo = {
  derivationStrategy: "BIP44" | "BIP45";
  n: number; // number of total co-signers
  m: number; // number of required signers
  publicKeyRing: string[]; // Array of xPubKeyHDPM
  xPubKey: string; // eg: "xpub6D7Q8"
  xPubKeyHDPM: string; // eg: "xpub68VWD" (extended key)
};

export class Account {
  private _localstore: LocalStore;
  private _xpub: HDKey;
  private _btcMasterPubKey: HDKey;
  private _cosignerIndex: number;
  private _curMultiSigner: HDKey; // multi sign current wallet signer
  private _allMultiSigners: HDKey[] = []; // including _multiSigner and sorted
  private _ownerPubKey: bytes_t;
  private _requestPubKey: bytes_t;

  private init() {
    this._cosignerIndex = -1;

    if (this._localstore.getOwnerPubKey())
      this._ownerPubKey = Buffer.from(this._localstore.getOwnerPubKey(), "hex");

    if (this._localstore.getRequestPubKey())
      this._requestPubKey = Buffer.from(
        this._localstore.getRequestPubKey(),
        "hex"
      );

    let xpubRing = this._localstore.getPublicKeyRing();
    for (let i = 0; i < xpubRing.length - 1; ++i) {
      for (let j = i + 1; j < xpubRing.length; ++j) {
        if (xpubRing[i].getxPubKey() == xpubRing[j].getxPubKey()) {
          ErrorChecker.throwParamException(
            Error.Code.PubKeyFormat,
            "Contain same xpub in PublicKeyRing"
          );
        }
      }
    }

    if (this._localstore.getxPubKey()) {
      ErrorChecker.checkParam(
        !Base58Check.decode(this._localstore.getxPubKey()),
        Error.Code.PubKeyFormat,
        "xpub decode error"
      );
      this._xpub = HDKey.deserializeBase58(
        this._localstore.getxPubKey(),
        KeySpec.Elastos
      );
    } else {
      this._xpub = null;
      Log.warn("xpub is empty");
    }

    if (this._localstore.getxPubKeyBitcoin()) {
      ErrorChecker.checkParam(
        !Base58Check.decode(this._localstore.getxPubKeyBitcoin()),
        Error.Code.PubKeyFormat,
        "xpubkeyBitcoin decode error"
      );
      this._btcMasterPubKey = HDKey.deserializeBase58(
        this._localstore.getxPubKeyBitcoin(),
        KeySpec.Bitcoin
      );
    } else {
      this._btcMasterPubKey = null;
      Log.warn("btcMasterPubKey is empty");
    }

    if (this._localstore.getxPubKeyHDPM()) {
      ErrorChecker.checkParam(
        !Base58Check.decode(this._localstore.getxPubKeyHDPM()),
        Error.Code.PubKeyFormat,
        "xpubHDPM decode error"
      );
      this._curMultiSigner = HDKey.deserializeBase58(
        this._localstore.getxPubKeyHDPM(),
        KeySpec.Elastos
      );
    } else {
      Log.warn("xpubHDPM is empty");
    }

    if (this._localstore.getN() > 1) {
      if (this._localstore.derivationStrategy() == "BIP44") {
        this._curMultiSigner = this._xpub;
        for (let i = 0; i < this._localstore.getPublicKeyRing().length; ++i) {
          let publicKeyRing = this._localstore.getPublicKeyRing()[i];
          let xPubKey: string = publicKeyRing.getxPubKey();
          ErrorChecker.checkParam(
            !Base58Check.decode(xPubKey),
            Error.Code.PubKeyFormat,
            "xpub decode error"
          );
          let xpub = HDKey.deserializeBase58(xPubKey, KeySpec.Elastos);
          this._allMultiSigners.push(xpub);
        }
      } else if (this._localstore.derivationStrategy() == "BIP45") {
        let sortedSigners: HDKey[] = [];
        for (let i = 0; i < this._localstore.getPublicKeyRing().length; ++i) {
          let xPubKey = this._localstore.getPublicKeyRing()[i].getxPubKey();
          ErrorChecker.checkLogic(
            !Base58Check.decode(xPubKey),
            Error.Code.PubKeyFormat,
            "xpub HDPM decode error"
          );
          let xpub = HDKey.deserializeBase58(xPubKey, KeySpec.Elastos);
          sortedSigners.push(xpub);
        }

        sortedSigners.sort((a, b) => {
          return a
            .getPublicKeyBytes()
            .toString("hex")
            .localeCompare(b.getPublicKeyBytes().toString("hex"));
        });

        // The derivation path m'/45'/cosigner_index
        for (let i = 0; i < sortedSigners.length; ++i) {
          let tmp = sortedSigners[i].deriveWithIndex(i);
          if (
            this._curMultiSigner &&
            this._cosignerIndex == -1 &&
            // compare two hdkeys
            this._curMultiSigner.equals(sortedSigners[i])
          ) {
            this._curMultiSigner = tmp;
            this._cosignerIndex = i;
          }
          this._allMultiSigners.push(tmp);
        }
      }
    }
  }

  private constructor() {}

  public static newFromLocalStore(store: LocalStore) {
    let account = new Account();
    account._localstore = store;
    account.init();
    return account;
  }

  public static async newFromAccount(id: string, storage: WalletStorage) {
    let account = new Account();
    account._localstore = new LocalStore(storage, id);
    await account._localstore.load(id);
    account.init();
    return account;
  }

  public static newFromPublicKeyRings(
    id: string,
    storage: WalletStorage,
    cosigners: PublicKeyRing[],
    m: number,
    singleAddress: boolean,
    compatible: boolean
  ) {
    ErrorChecker.checkParam(
      cosigners.length > MAX_MULTISIGN_COSIGNERS,
      Error.Code.MultiSign,
      "Too much signers"
    );

    let account = new Account();
    account._localstore = new LocalStore(storage, id);
    account._localstore.setM(m);
    account._localstore.setN(cosigners.length);
    account._localstore.setSingleAddress(singleAddress);
    account._localstore.setReadonly(true);
    account._localstore.setHasPassPhrase(false);
    account._localstore.setPublicKeyRing(cosigners);
    account._localstore.setMnemonic("");
    account._localstore.setxPrivKey("");
    account._localstore.setxPubKey("");
    account._localstore.setxPubKeyHDPM("");
    account._localstore.setRequestPubKey("");
    account._localstore.setRequestPrivKey("");
    account._localstore.setOwnerPubKey("");
    account._localstore.setSeed("");
    account._localstore.setETHSCPrimaryPubKey("");
    account._localstore.setxPubKeyBitcoin("");
    account._localstore.setSinglePrivateKey("");
    account._localstore.setRipplePrimaryPubKey("");

    if (compatible) {
      account._localstore.setDerivationStrategy("BIP44");
    } else {
      account._localstore.setDerivationStrategy("BIP45");
    }

    account.init();
    return account;
  }

  public static newFromXPrivateKey(
    id: string,
    storage: WalletStorage,
    xprv: string,
    payPasswd: string,
    cosigners: PublicKeyRing[],
    m: number,
    singleAddress: boolean,
    compatible: boolean
  ) {
    ErrorChecker.checkParam(
      cosigners.length + 1 > MAX_MULTISIGN_COSIGNERS,
      Error.Code.MultiSign,
      "Too much signers"
    );
    let bytes = Base58Check.decode(xprv);
    ErrorChecker.checkLogic(!bytes, Error.Code.InvalidArgument, "Invalid xprv");
    const rootkey: HDKey = HDKey.deserializeBase58(xprv, KeySpec.Elastos);

    const encryptedxPrvKey: string = AESEncrypt(xprv, payPasswd);
    const xPubKey: string = rootkey
      .deriveWithPath("m/44'/0'/0'")
      .serializePublicKeyBase58();

    const requestKey: HDKey = rootkey.deriveWithPath("m/1'/0");
    const encryptedRequestPrvKey: string = AESEncrypt(
      requestKey.serializeBase58(),
      payPasswd
    );
    const requestPubKey: string = requestKey
      .getPublicKeyBytes()
      .toString("hex");

    const account = new Account();
    account._localstore = new LocalStore(storage, id);
    account._localstore.setM(m);
    account._localstore.setN(cosigners.length + 1);
    account._localstore.setSingleAddress(singleAddress);
    account._localstore.setReadonly(false);
    account._localstore.setHasPassPhrase(false);
    account._localstore.setPublicKeyRing(cosigners);
    account._localstore.setMnemonic("");
    account._localstore.setxPrivKey(encryptedxPrvKey);
    account._localstore.setxPubKey(xPubKey);
    account._localstore.setRequestPubKey(requestPubKey);
    account._localstore.setRequestPrivKey(encryptedRequestPrvKey);
    account._localstore.setOwnerPubKey("");
    account._localstore.setSeed("");
    account._localstore.setETHSCPrimaryPubKey("");
    account._localstore.setRipplePrimaryPubKey("");
    account._localstore.setxPubKeyBitcoin("");
    account._localstore.setSinglePrivateKey("");

    if (compatible) {
      account._localstore.setDerivationStrategy("BIP44");
      account._localstore.addPublicKeyRing(new PublicKeyRing("", xPubKey));
      account._localstore.setxPubKeyHDPM(xPubKey);
    } else {
      account._localstore.setDerivationStrategy("BIP45");
      const xpubPurpose: string = rootkey
        .deriveWithPath("m/45'")
        .serializePublicKeyBase58();
      account._localstore.addPublicKeyRing(
        new PublicKeyRing(requestPubKey, xpubPurpose)
      );
      account._localstore.setxPubKeyHDPM(xpubPurpose);
    }

    account.init();
    return account;
  }

  // multi-sign seed
  public static newFromMultisignSeed(
    id: string,
    storage: WalletStorage,
    seed: Buffer,
    payPasswd: string,
    cosigners: PublicKeyRing[],
    m: number,
    singleAddress: boolean,
    compatible: boolean
  ) {
    ErrorChecker.checkParam(
      cosigners.length + 1 > MAX_MULTISIGN_COSIGNERS,
      Error.Code.MultiSign,
      "Too much signers"
    );

    const encryptedSeed: string = AESEncrypt(seed.toString("hex"), payPasswd);

    const rootkey: HDKey = HDKey.fromMasterSeed(seed, KeySpec.Elastos);
    const privateKey = rootkey.serializeBase58();

    const encryptedxPrvKey: string = AESEncrypt(privateKey, payPasswd);
    const xPubKey: string = rootkey
      .deriveWithPath("m/44'/0'/0'")
      .serializePublicKeyBase58();

    const requestKey: HDKey = rootkey.deriveWithPath("m/1'/0");
    const encryptedRequestPrvKey: string = AESEncrypt(
      requestKey.serializeBase58(),
      payPasswd
    );
    const requestPubKey: string = requestKey
      .getPublicKeyBytes()
      .toString("hex");

    const stdrootkey: HDKey = HDKey.fromMasterSeed(seed, KeySpec.Bitcoin);
    const ethkey = stdrootkey.deriveWithPath("m/44'/60'/0'/0/0");

    const encryptedethPrvKey: string = AESEncrypt(
      ethkey.serializeBase58(),
      payPasswd
    );

    const ownerPubKey: string = rootkey
      .deriveWithPath("m/44'/0'/1'/0/0")
      .getPublicKeyBytes()
      .toString("hex");

    const xpubBitcoin: string = stdrootkey
      .deriveWithPath("m/44'/0'/0'")
      .serializePublicKeyBase58();

    const secp256 = new Secp256(Secp256.CURVE_K1);
    const ethscPubKey: string = secp256
      .publicKeyConvert(ethkey.getPublicKeyBytes(), false)
      .toString("hex");

    const ripplePubKey: string = stdrootkey
      .deriveWithPath("m/44'/144'/0'/0/0")
      .getPublicKeyBytes()
      .toString("hex");

    const account = new Account();
    account._localstore = new LocalStore(storage, id);
    account._localstore.setM(m);
    account._localstore.setN(cosigners.length + 1);
    account._localstore.setSingleAddress(singleAddress);
    account._localstore.setReadonly(false);
    account._localstore.setHasPassPhrase(false);
    account._localstore.setPublicKeyRing(cosigners);
    account._localstore.setMnemonic("");
    account._localstore.setxPrivKey(encryptedxPrvKey);
    account._localstore.setxPubKey(xPubKey);
    account._localstore.setRequestPubKey(requestPubKey);
    account._localstore.setRequestPrivKey(encryptedRequestPrvKey);
    account._localstore.setOwnerPubKey(ownerPubKey);
    account._localstore.setSeed(encryptedSeed);
    account._localstore.setETHSCPrimaryPubKey(ethscPubKey);
    account._localstore.setRipplePrimaryPubKey(ripplePubKey);
    account._localstore.setxPubKeyBitcoin(xpubBitcoin);
    account._localstore.setSinglePrivateKey(encryptedethPrvKey);

    if (compatible) {
      account._localstore.setDerivationStrategy("BIP44");
      account._localstore.addPublicKeyRing(new PublicKeyRing("", xPubKey));
      account._localstore.setxPubKeyHDPM(xPubKey);
    } else {
      account._localstore.setDerivationStrategy("BIP45");
      const xpubPurpose: string = rootkey
        .deriveWithPath("m/45'")
        .serializePublicKeyBase58();
      account._localstore.addPublicKeyRing(
        new PublicKeyRing(requestPubKey, xpubPurpose)
      );
      account._localstore.setxPubKeyHDPM(xpubPurpose);
    }

    account.init();
    return account;
  }

  // multi-sign mnemonic + passphrase
  public static newFromMultiSignMnemonic(
    id: string,
    storage: WalletStorage,
    mnemonic: string,
    passphrase: string,
    payPasswd: string,
    cosigners: PublicKeyRing[],
    m: number,
    singleAddress: boolean,
    compatible: boolean
  ) {
    ErrorChecker.checkParam(
      cosigners.length + 1 > MAX_MULTISIGN_COSIGNERS,
      Error.Code.MultiSign,
      "Too much signers"
    );

    const encryptedMnemonic: string = AESEncrypt(mnemonic, payPasswd);

    const seed: Buffer = Mnemonic.toSeed(mnemonic, passphrase);
    const encryptedSeed: string = AESEncrypt(seed.toString("hex"), payPasswd);

    const stdrootkey: HDKey = HDKey.fromMasterSeed(seed, KeySpec.Bitcoin);
    const ethkey: HDKey = stdrootkey.deriveWithPath("m/44'/60'/0'/0/0");
    const encryptedethPrvKey: string = AESEncrypt(
      ethkey.serializeBase58(),
      payPasswd
    );

    const secp256 = new Secp256(Secp256.CURVE_K1);
    const ethscPubKey: string = secp256
      .publicKeyConvert(ethkey.getPublicKeyBytes(), false)
      .toString("hex");

    const ripplePubKey: string = stdrootkey
      .deriveWithPath("m/44'/144'/0'/0/0")
      .getPublicKeyBytes()
      .toString("hex");

    const rootkey: HDKey = HDKey.fromMasterSeed(seed, KeySpec.Elastos);
    const encryptedxPrvKey: string = AESEncrypt(
      rootkey.serializeBase58(),
      payPasswd
    );
    const xPubKey: string = rootkey
      .deriveWithPath("m/44'/0'/0'")
      .serializePublicKeyBase58();

    const xpubBitcoin: string = stdrootkey
      .deriveWithPath("m/44'/0'/0'")
      .serializePublicKeyBase58();

    const requestKey: HDKey = rootkey.deriveWithPath("m/1'/0");
    const encryptedRequestPrvKey: string = AESEncrypt(
      requestKey.serializeBase58(),
      payPasswd
    );
    const requestPubKey: string = requestKey
      .getPublicKeyBytes()
      .toString("hex");

    const account = new Account();
    account._localstore = new LocalStore(storage, id);
    account._localstore.setM(m);
    account._localstore.setN(cosigners.length + 1);
    account._localstore.setSingleAddress(singleAddress);
    account._localstore.setReadonly(false);
    account._localstore.setHasPassPhrase(passphrase.length !== 0);
    account._localstore.setPublicKeyRing(cosigners);
    account._localstore.setMnemonic(encryptedMnemonic);
    account._localstore.setxPrivKey(encryptedxPrvKey);
    account._localstore.setxPubKey(xPubKey);
    account._localstore.setRequestPubKey(requestPubKey);
    account._localstore.setRequestPrivKey(encryptedRequestPrvKey);
    account._localstore.setOwnerPubKey("");
    account._localstore.setSeed(encryptedSeed);
    account._localstore.setETHSCPrimaryPubKey(ethscPubKey);
    account._localstore.setxPubKeyBitcoin(xpubBitcoin);
    account._localstore.setSinglePrivateKey(encryptedethPrvKey);
    account._localstore.setRipplePrimaryPubKey(ripplePubKey);

    if (compatible) {
      account._localstore.setDerivationStrategy("BIP44");
      account._localstore.addPublicKeyRing(new PublicKeyRing("", xPubKey));
      account._localstore.setxPubKeyHDPM(xPubKey);
    } else {
      account._localstore.setDerivationStrategy("BIP45");
      const xpubPurpose: string = rootkey
        .deriveWithPath("m/45'")
        .serializePublicKeyBase58();
      account._localstore.addPublicKeyRing(
        new PublicKeyRing(requestPubKey, xpubPurpose)
      );
      account._localstore.setxPubKeyHDPM(xpubPurpose);
    }

    account.init();
    return account;
  }

  // HD standard with mnemonic + passphrase
  public static newFromMnemonicAndPassphrase(
    id: string,
    storage: WalletStorage,
    mnemonic: string,
    passphrase: string,
    payPasswd: string,
    singleAddress: boolean
  ) {
    let account = new Account();

    const seed: Buffer = Mnemonic.toSeed(mnemonic, passphrase);
    const encryptedSeed: string = AESEncrypt(seed.toString("hex"), payPasswd);

    const rootkey: HDKey = HDKey.fromMnemonic(
      mnemonic,
      passphrase,
      KeySpec.Elastos
    );

    const stdrootkey: HDKey = HDKey.fromMnemonic(
      mnemonic,
      passphrase,
      KeySpec.Bitcoin
    );
    const ethkey: HDKey = stdrootkey.deriveWithPath("m/44'/60'/0'/0/0");

    const encryptedethPrvKey: string = AESEncrypt(
      ethkey.serializeBase58(),
      payPasswd
    );

    const secp256 = new Secp256(Secp256.CURVE_K1);
    const ethscPubKey: string = secp256
      .publicKeyConvert(ethkey.getPublicKeyBytes(), false)
      .toString("hex");

    const ripplePubKey: string = stdrootkey
      .deriveWithPath("m/44'/144'/0'/0/0")
      .getPublicKeyBytes()
      .toString("hex");

    const encryptedMnemonic: string = AESEncrypt(mnemonic, payPasswd);
    const encryptedxPrvKey: string = AESEncrypt(
      rootkey.serializeBase58(),
      payPasswd
    );

    const xpubBitcoin: string = stdrootkey
      .deriveWithPath("m/44'/0'/0'")
      .serializePublicKeyBase58();

    const xPubKey: string = rootkey
      .deriveWithPath("m/44'/0'/0'")
      .serializePublicKeyBase58();

    const xpubHDPM: string = rootkey
      .deriveWithPath("m/45'")
      .serializePublicKeyBase58();

    const requestKey: HDKey = rootkey.deriveWithPath("m/1'/0");

    const encryptedRequestPrvKey: string = AESEncrypt(
      requestKey.serializeBase58(),
      payPasswd
    );

    const requestPubKey: string = requestKey
      .getPublicKeyBytes()
      .toString("hex");

    const ownerPubKey: string = rootkey
      .deriveWithPath("m/44'/0'/1'/0/0")
      .getPublicKeyBytes()
      .toString("hex");

    account._localstore = new LocalStore(storage, id);
    account._localstore.setDerivationStrategy("BIP44");
    account._localstore.setM(1);
    account._localstore.setN(1);
    account._localstore.setSingleAddress(singleAddress);
    account._localstore.setReadonly(false);
    account._localstore.setHasPassPhrase(passphrase.length > 0);
    account._localstore.setPublicKeyRing([
      new PublicKeyRing(requestPubKey, xpubHDPM)
    ]);
    account._localstore.setMnemonic(encryptedMnemonic);
    account._localstore.setxPrivKey(encryptedxPrvKey);
    account._localstore.setxPubKey(xPubKey);
    account._localstore.setxPubKeyHDPM(xpubHDPM);
    account._localstore.setRequestPubKey(requestPubKey);
    account._localstore.setRequestPrivKey(encryptedRequestPrvKey);
    account._localstore.setOwnerPubKey(ownerPubKey);
    account._localstore.setSeed(encryptedSeed);
    account._localstore.setETHSCPrimaryPubKey(ethscPubKey);
    account._localstore.setxPubKeyBitcoin(xpubBitcoin);
    account._localstore.setSinglePrivateKey(encryptedethPrvKey);
    account._localstore.setRipplePrimaryPubKey(ripplePubKey);

    account.init();
    return account;
  }

  // HD standard with seed + [mnemonic:passphrase]
  public static newFromSeed(
    id: string,
    storage: WalletStorage,
    seed: Buffer,
    payPasswd: string,
    singleAddress: boolean,
    mnemonic: string,
    passphrase: string
  ) {
    let account = new Account();

    const rootkey: HDKey = HDKey.fromMasterSeed(seed, KeySpec.Elastos);

    const encryptedSeed: string = AESEncrypt(seed.toString("hex"), payPasswd);

    const stdrootkey: HDKey = HDKey.fromMasterSeed(seed, KeySpec.Bitcoin);
    const ethkey = stdrootkey.deriveWithPath("m/44'/60'/0'/0/0");

    const encryptedethPrvKey: string = AESEncrypt(
      ethkey.serializeBase58(),
      payPasswd
    );

    const secp256 = new Secp256(Secp256.CURVE_K1);
    const ethscPubKey: string = secp256
      .publicKeyConvert(ethkey.getPublicKeyBytes(), false)
      .toString("hex");

    const ripplePubKey: string = stdrootkey
      .deriveWithPath("m/44'/144'/0'/0/0")
      .getPublicKeyBytes()
      .toString("hex");

    let encryptedMnemonic = "";
    if (mnemonic) {
      encryptedMnemonic = AESEncrypt(mnemonic, payPasswd);
    }

    const encryptedxPrvKey: string = AESEncrypt(
      rootkey.serializeBase58(),
      payPasswd
    );

    const xpubBitcoin: string = stdrootkey
      .deriveWithPath("m/44'/0'/0'")
      .serializePublicKeyBase58();

    const xPubKey: string = rootkey
      .deriveWithPath("m/44'/0'/0'")
      .serializePublicKeyBase58();

    const xpubHDPM: string = rootkey
      .deriveWithPath("m/45'")
      .serializePublicKeyBase58();

    const requestKey: HDKey = rootkey.deriveWithPath("m/1'/0");

    const encryptedRequestPrvKey: string = AESEncrypt(
      requestKey.serializeBase58(),
      payPasswd
    );

    const requestPubKey: string = requestKey
      .getPublicKeyBytes()
      .toString("hex");

    const ownerPubKey: string = rootkey
      .deriveWithPath("m/44'/0'/1'/0/0")
      .getPublicKeyBytes()
      .toString("hex");

    account._localstore = new LocalStore(storage, id);
    account._localstore.setDerivationStrategy("BIP44");
    account._localstore.setM(1);
    account._localstore.setN(1);
    account._localstore.setSingleAddress(singleAddress);
    account._localstore.setReadonly(false);
    account._localstore.setHasPassPhrase(passphrase.length > 0);
    account._localstore.setPublicKeyRing([
      new PublicKeyRing(requestPubKey, xpubHDPM)
    ]);
    account._localstore.setMnemonic(encryptedMnemonic);
    account._localstore.setxPrivKey(encryptedxPrvKey);
    account._localstore.setxPubKey(xPubKey);
    account._localstore.setxPubKeyHDPM(xpubHDPM);
    account._localstore.setRequestPubKey(requestPubKey);
    account._localstore.setRequestPrivKey(encryptedRequestPrvKey);
    account._localstore.setOwnerPubKey(ownerPubKey);
    account._localstore.setSeed(encryptedSeed);
    account._localstore.setETHSCPrimaryPubKey(ethscPubKey);
    account._localstore.setxPubKeyBitcoin(xpubBitcoin);
    account._localstore.setSinglePrivateKey(encryptedethPrvKey);
    account._localstore.setRipplePrimaryPubKey(ripplePubKey);

    account.init();
    return account;
  }

  // only eth subwallet with single private key
  public static newFromSinglePrivateKey(
    id: string,
    storage: WalletStorage,
    singlePrivateKey: string,
    passwd: string
  ) {
    const encryptedSinglePrvKey: string = AESEncrypt(singlePrivateKey, passwd);
    const k: HDKey = HDKey.deserializeBase58(
      singlePrivateKey,
      KeySpec.Ethereum
    );

    const secp256 = new Secp256(Secp256.CURVE_K1);
    const ethscPubKey: string = secp256
      .publicKeyConvert(k.getPublicKeyBytes(), false)
      .toString("hex");

    const account = new Account();
    account._localstore = new LocalStore(storage, id);
    account._localstore.setDerivationStrategy("BIP44");
    account._localstore.setM(1);
    account._localstore.setN(1);
    account._localstore.setSingleAddress(true);
    account._localstore.setReadonly(false);
    account._localstore.setHasPassPhrase(false);
    account._localstore.setPublicKeyRing([]);
    account._localstore.setMnemonic("");
    account._localstore.setxPrivKey("");
    account._localstore.setxPubKey("");
    account._localstore.setxPubKeyHDPM("");
    account._localstore.setRequestPubKey("");
    account._localstore.setRequestPrivKey("");
    account._localstore.setOwnerPubKey("");
    account._localstore.setSeed("");
    account._localstore.setETHSCPrimaryPubKey(ethscPubKey);
    account._localstore.setxPubKeyBitcoin("");
    account._localstore.setSinglePrivateKey(encryptedSinglePrvKey);
    account._localstore.setRipplePrimaryPubKey("");

    account.init();
    return account;
  }

  public static newFromReadOnlyWalletJson(
    id: string,
    storage: WalletStorage,
    walletJSON: { Data: string }
  ) {
    let account = new Account();
    account._localstore = new LocalStore(storage, id);
    ErrorChecker.checkParam(
      !account.importReadonlyWallet(walletJSON),
      Error.Code.InvalidArgument,
      "Invalid readonly wallet json"
    );
    account.init();
    return account;
  }

  public static newFromKeystore(
    id: string,
    storage: WalletStorage,
    ks: KeyStore,
    payPasswd: string
  ) {
    const json: ElaNewWalletJson = ks.walletJson();

    const account = new Account();
    account._localstore = new LocalStore(storage, id);
    account._localstore.setReadonly(true);
    if (json.xPrivKey()) {
      const encrypedPrivKey: string = AESEncrypt(json.xPrivKey(), payPasswd);
      account._localstore.setxPrivKey(encrypedPrivKey);
      account._localstore.setReadonly(false);
    }

    if (json.mnemonic()) {
      const encryptedMnemonic: string = AESEncrypt(json.mnemonic(), payPasswd);
      account._localstore.setMnemonic(encryptedMnemonic);
      account._localstore.setReadonly(false);
    }

    if (json.requestPrivKey()) {
      account._localstore.setRequestPrivKey(
        AESEncrypt(json.requestPrivKey(), payPasswd)
      );
      account._localstore.setReadonly(false);
    }

    if (json.getSeed()) {
      account._localstore.setSeed(AESEncrypt(json.getSeed(), payPasswd));
      account._localstore.setReadonly(false);
    }

    if (json.getSinglePrivateKey()) {
      account._localstore.setSinglePrivateKey(
        AESEncrypt(json.getSinglePrivateKey(), payPasswd)
      );
      account._localstore.setReadonly(false);
    }

    let publicKeyRings = [];
    if (json.getPublicKeyRing()) {
      for (let item of json.getPublicKeyRing()) {
        let publicKeyRing = new PublicKeyRing();
        publicKeyRings.push(publicKeyRing.fromJson(item));
      }
    }

    account._localstore.setxPubKeyBitcoin(json.getxPubKeyBitcoin());
    account._localstore.setxPubKey(json.xPubKey());
    account._localstore.setRequestPubKey(json.requestPubKey());
    account._localstore.setPublicKeyRing(publicKeyRings);
    account._localstore.setM(json.getM());
    account._localstore.setN(json.getN());
    account._localstore.setHasPassPhrase(json.hasPassPhrase());
    account._localstore.setSingleAddress(json.singleAddress());
    account._localstore.setDerivationStrategy(json.derivationStrategy());
    account._localstore.setxPubKeyHDPM(json.xPubKeyHDPM());
    account._localstore.setOwnerPubKey(json.ownerPubKey());
    account._localstore.setSubWalletInfoList(json.getCoinInfoList());
    account._localstore.setETHSCPrimaryPubKey(json.getETHSCPrimaryPubKey());
    account._localstore.setRipplePrimaryPubKey(json.getRipplePrimaryPubKey());

    account.init();
    return account;
  }

  public RequestPubKey(): bytes_t {
    return this._requestPubKey;
  }

  public async rootKey(payPasswd: string): Promise<HDKey> {
    if (this._localstore.readonly()) {
      ErrorChecker.throwLogicException(
        Error.Code.Key,
        "Readonly wallet without prv key"
      );
    }

    if (!this._localstore.getxPubKeyBitcoin()) {
      await this.regenerateKey(payPasswd);
      this.init();
    }

    let extkey: string = AESDecrypt(this._localstore.getxPrivKey(), payPasswd);
    let key = HDKey.deserializeBase58(extkey, KeySpec.Elastos);
    return Promise.resolve(key);
  }

  async requestPrivKey(payPassword: string): Promise<DeterministicKey> {
    if (this._localstore.readonly()) {
      ErrorChecker.throwLogicException(
        Error.Code.Key,
        "Readonly wallet without prv key"
      );
    }

    if (!this._localstore.getxPubKeyBitcoin()) {
      await this.regenerateKey(payPassword);
      this.init();
    }

    const bytes = AESDecrypt(this._localstore.getRequestPrivKey(), payPassword);
    let key = new DeterministicKey(DeterministicKey.ELASTOS_VERSIONS);
    key.privateKey = bytes;
    return Promise.resolve(key);
  }

  public masterPubKey(): HDKey {
    return this._xpub;
  }

  bitcoinMasterPubKey(): HDKey {
    return this._btcMasterPubKey;
  }

  public async getxPrvKeyString(payPasswd: string): Promise<string> {
    if (this._localstore.readonly()) {
      ErrorChecker.throwLogicException(
        Error.Code.UnsupportOperation,
        "Readonly wallet can not export private key"
      );
    }

    if (this._localstore.getxPubKeyBitcoin().length === 0) {
      await this.regenerateKey(payPasswd);
      this.init();
    }

    return Promise.resolve(
      AESDecrypt(this._localstore.getxPrivKey(), payPasswd)
    );
  }

  public masterPubKeyString(): string {
    return this._localstore.getxPubKey();
  }

  public masterPubKeyHDPMString(): string {
    return this._localstore.getxPubKeyHDPM();
  }

  public masterPubKeyRing(): PublicKeyRing[] {
    return this._localstore.getPublicKeyRing();
  }

  public ownerPubKey(): bytes_t {
    ErrorChecker.checkLogic(
      !this._ownerPubKey,
      Error.Code.Key,
      "This account unsupport owner public key"
    );
    return this._ownerPubKey;
  }

  async changePassword(oldPasswd: string, newPasswd: string): Promise<void> {
    if (!this._localstore.readonly()) {
      ErrorChecker.checkPassword(newPasswd, "New");

      if (this._localstore.getxPubKeyBitcoin().length === 0) {
        await this.regenerateKey(oldPasswd);
        this.init();
      }

      this._localstore.changePasswd(oldPasswd, newPasswd);

      await this._localstore.save();
    }
  }

  async resetPassword(
    mnemonic: string,
    passphrase: string,
    newPassword: string
  ): Promise<void> {
    if (!this._localstore.readonly()) {
      ErrorChecker.checkPassword(newPassword, "New");
      const seed: Buffer = Mnemonic.toSeed(mnemonic, passphrase);
      const rootkey = HDKey.fromMnemonic(mnemonic, passphrase, KeySpec.Elastos);
      const stdrootkey = HDKey.fromMnemonic(
        mnemonic,
        passphrase,
        KeySpec.Bitcoin
      );
      const ethkey = stdrootkey.deriveWithPath("m/44'/60'/0'/0/0");

      const xPubKey: string = rootkey
        .deriveWithPath("m/44'/0'/0'")
        .serializePublicKeyBase58();
      if (xPubKey != this._localstore.getxPubKey()) {
        ErrorChecker.throwParamException(
          Error.Code.InvalidArgument,
          "xpub not match"
        );
      }

      const encryptedSinglePrivateKey: string = AESEncrypt(
        ethkey.serializeBase58(),
        newPassword
      );

      const encryptedSeed: string = AESEncrypt(
        seed.toString("hex"),
        newPassword
      );

      const encryptedMnemonic: string = AESEncrypt(mnemonic, newPassword);

      const encryptedxPrvKey: string = AESEncrypt(
        rootkey.serializeBase58(),
        newPassword
      );

      const requestKey = rootkey.deriveWithPath("m/1'/0");
      const encryptedRequestPrvKey: string = AESEncrypt(
        requestKey.serializeBase58(),
        newPassword
      );

      this._localstore.setSeed(encryptedSeed);
      this._localstore.setMnemonic(encryptedMnemonic);
      this._localstore.setxPrivKey(encryptedxPrvKey);
      this._localstore.setRequestPrivKey(encryptedRequestPrvKey);
      this._localstore.setSinglePrivateKey(encryptedSinglePrivateKey);

      await this._localstore.save();
    }
  }

  public getBasicInfo(): AccountBasicInfo {
    let j = <AccountBasicInfo>{};

    if (this.getSignType() == SignType.MultiSign) {
      j["Type"] = "MultiSign";
    } else {
      j["Type"] = "Standard";
    }

    j["Readonly"] = this._localstore.readonly();
    j["SingleAddress"] = this._localstore.singleAddress();
    j["M"] = this._localstore.getM();
    j["N"] = this._localstore.getN();
    j["HasPassPhrase"] = this._localstore.hasPassPhrase();

    return j;
  }

  getSignType(): SignType {
    if (this._localstore.getN() > 1) return SignType.MultiSign;

    return SignType.Standard;
  }

  readonly(): boolean {
    return this._localstore.readonly();
  }

  singleAddress(): boolean {
    return this._localstore.singleAddress();
  }

  equal(account: Account): boolean {
    if (this.getSignType() != account.getSignType()) {
      return false;
    }

    if (
      (this._xpub == null && account.masterPubKey() != null) ||
      (this._xpub != null && account.masterPubKey() == null)
    ) {
      return false;
    }

    if (this._xpub == null && account.masterPubKey() == null) {
      return this.getETHSCPubKey().equals(account.getETHSCPubKey());
    }

    if (this.getSignType() == SignType.MultiSign) {
      if (this._localstore.getM() != account._localstore.getM()) {
        return false;
      }

      if (this._allMultiSigners.length != account.multiSignCosigner().length) {
        return false;
      }

      for (let i = 0; i < this._allMultiSigners.length; ++i) {
        if (!this._allMultiSigners[i].equals(account.multiSignCosigner()[i])) {
          return false;
        }
      }
    }

    return this._xpub.equals(account.masterPubKey());
  }

  getM(): number {
    return this._localstore.getM();
  }

  getN(): number {
    return this._localstore.getN();
  }

  derivationStrategy(): string {
    return this._localstore.derivationStrategy();
  }

  getPubKeyInfo(): AccountPubKeyInfo {
    let j = <AccountPubKeyInfo>{};
    const jCosigners: string[] = [];

    j["m"] = this._localstore.getM();
    j["n"] = this._localstore.getN();

    if (this._localstore.derivationStrategy() === "BIP44") {
      j["derivationStrategy"] = "BIP44";
    } else {
      j["derivationStrategy"] = "BIP45";
    }

    if (this._localstore.getN() > 1 && this._localstore.readonly()) {
      j["xPubKey"] = null;
      j["xPubKeyHDPM"] = null;
    } else {
      j["xPubKey"] = this._localstore.getxPubKey();
      j["xPubKeyHDPM"] = this._localstore.getxPubKeyHDPM();
    }

    for (let i = 0; i < this._localstore.getPublicKeyRing().length; ++i) {
      jCosigners.push(this._localstore.getPublicKeyRing()[i].getxPubKey());
    }

    j["publicKeyRing"] = jCosigners;

    return j;
  }

  public multiSignSigner(): HDKey {
    ErrorChecker.checkLogic(
      !this._xpub,
      Error.Code.Key,
      "Read-only wallet do not contain current multisigner"
    );
    return this._curMultiSigner;
  }

  public multiSignCosigner(): HDKey[] {
    return this._allMultiSigners;
  }

  public cosignerIndex(): number {
    return this._cosignerIndex;
  }

  public subWalletInfoList(): CoinInfo[] {
    return this._localstore.getSubWalletInfoList();
  }

  public addSubWalletInfoList(info: CoinInfo) {
    this._localstore.addSubWalletInfoList(info);
  }

  public setSubWalletInfoList(info: CoinInfo[]) {
    this._localstore.setSubWalletInfoList(info);
  }

  public removeSubWalletInfo(chainID: string) {
    this._localstore.removeSubWalletInfo(chainID);
  }

  async exportKeystore(payPasswd: string) {
    if (!this._localstore.readonly() && !this._localstore.getxPubKeyBitcoin()) {
      await this.regenerateKey(payPasswd);
      this.init();
    }

    let bytes = "";
    let json = new ElaNewWalletJson();
    if (!this._localstore.readonly()) {
      if (this._localstore.getxPrivKey()) {
        bytes = AESDecrypt(this._localstore.getxPrivKey(), payPasswd);
      }
      if (bytes.length > 0) {
        json.setxPrivKey(bytes);
      }

      if (!this._localstore.getMnemonic()) {
        json.setMnemonic("");
        json.setHasPassPhrase(false);
      } else {
        let mnemonic = AESDecrypt(this._localstore.getMnemonic(), payPasswd);
        json.setMnemonic(mnemonic);
      }

      if (!this._localstore.getRequestPrivKey()) {
        bytes = "";
      } else {
        bytes = AESDecrypt(this._localstore.getRequestPrivKey(), payPasswd);
      }
      json.setRequestPrivKey(bytes);

      if (!this._localstore.getSeed()) {
        json.setSeed("");
      } else {
        let seed = AESDecrypt(this._localstore.getSeed(), payPasswd);
        json.setSeed(seed);
      }

      if (!this._localstore.getSinglePrivateKey()) {
        bytes = "";
      } else {
        bytes = AESDecrypt(this._localstore.getSinglePrivateKey(), payPasswd);
      }
      json.setSinglePrivateKey(bytes);
    }

    json.setOwnerPubKey(this._localstore.getOwnerPubKey());
    json.setxPubKey(this._localstore.getxPubKey());
    json.setxPubKeyHDPM(this._localstore.getxPubKeyHDPM());
    json.setRequestPubKey(this._localstore.getRequestPubKey());
    let publicKeyRings = [];
    for (let item of this._localstore.getPublicKeyRing()) {
      publicKeyRings.push(item.toJson());
    }
    json.setPublicKeyRing(publicKeyRings);
    json.setM(this._localstore.getM());
    json.setN(this._localstore.getN());
    json.setHasPassPhrase(this._localstore.hasPassPhrase());
    json.setDerivationStrategy(this._localstore.derivationStrategy());
    json.setAccount(0);
    json.setSingleAddress(this._localstore.singleAddress());
    json.setCoinInfoList(this._localstore.getSubWalletInfoList());
    json.setETHSCPrimaryPubKey(this._localstore.getETHSCPrimaryPubKey());
    json.setxPubKeyBitcoin(this._localstore.getxPubKeyBitcoin());
    json.setRipplePrimaryPubKey(this._localstore.getRipplePrimaryPubKey());

    return KeyStore.newFromParams(json);
  }

  exportReadonlyWallet(): { Data?: string } {
    let j = {};
    let tmp: bytes_t;
    let stream = new ByteStream();

    stream.writeUInt8(READONLY_WALLET_VERSION00);
    stream.writeUInt8(this._localstore.singleAddress() ? 1 : 0);
    stream.writeUInt8(this._localstore.hasPassPhrase() ? 1 : 0);
    stream.writeUInt32(this._localstore.getM());
    stream.writeUInt32(this._localstore.getN());
    stream.writeUInt32(this._localstore.account());
    stream.writeVarString(this._localstore.derivationStrategy());

    tmp = Buffer.from(this._localstore.getETHSCPrimaryPubKey(), "hex");
    stream.writeVarBytes(tmp);

    if (this._localstore.getN() > 1) {
      tmp = Buffer.alloc(0);
      // request pubkey
      stream.writeVarBytes(tmp);
      // owner pubkey
      stream.writeVarBytes(tmp);
      // xpub
      stream.writeVarBytes(tmp);
      // btc xpub
      stream.writeVarBytes(tmp);
      // xpub HDPM
      stream.writeVarBytes(tmp);
    } else {
      tmp = Buffer.from(this._localstore.getRequestPubKey(), "hex");
      stream.writeVarBytes(tmp);

      tmp = Buffer.from(this._localstore.getOwnerPubKey());
      stream.writeVarBytes(tmp);

      tmp = Base58Check.decode(this._localstore.getxPubKey());
      if (!tmp) {
        Log.error("Decode xpub fail when exoprt read-only wallet");
        return j;
      }
      stream.writeVarBytes(tmp);

      tmp = Base58Check.decode(this._localstore.getxPubKeyBitcoin());
      if (!tmp) {
        Log.error("Decode btc xpub fail when exoprt read-only wallet");
        return j;
      }
      stream.writeVarBytes(tmp);

      tmp = Base58Check.decode(this._localstore.getxPubKeyHDPM());
      if (!tmp) {
        Log.error("Decode xpubHDPM fail when export read-only wallet");
        return j;
      }
      stream.writeVarBytes(tmp);
    }

    if (this._localstore.getN() > 1) {
      let pubkeyRing: PublicKeyRing[] = this._localstore.getPublicKeyRing();
      stream.writeVarUInt(pubkeyRing.length);
      for (let i = 0; i < pubkeyRing.length; ++i) {
        tmp = Buffer.from(pubkeyRing[i].getRequestPubKey(), "hex");
        stream.writeVarBytes(tmp);

        tmp = Base58Check.decode(pubkeyRing[i].getxPubKey());
        if (!tmp) {
          Log.error(
            "Decode pubkey ring xpub fail when export read-only wallet"
          );
          return j;
        }
        stream.writeVarBytes(tmp);
      }
    }

    let info: CoinInfo[] = this._localstore.getSubWalletInfoList();
    stream.writeVarUInt(info.length);
    for (let i = 0; i < info.length; ++i) {
      stream.writeVarString(info[i].getChainID());
    }

    let bytes = stream.getBytes();

    j["Data"] = bytes.toString("base64");

    return j;
  }

  importReadonlyWallet(walletJSON: { Data: string }) {
    if (!walletJSON["Data"]) {
      Log.error("Import read-only wallet: json format error");
      return false;
    }

    let version = 0;
    let bytes = Buffer.from(walletJSON["Data"], "base64");
    let stream = new ByteStream(bytes);

    version = stream.readUInt8();
    if (!version && version !== 0) {
      Log.error("Import read-only wallet: version");
      return false;
    }

    let byte = stream.readUInt8();
    if (!byte && byte !== 0) {
      Log.error("Import read-only wallet: single address");
      return false;
    }
    this._localstore.setSingleAddress(byte === 0 ? false : true);

    byte = stream.readUInt8();
    if (!byte && byte !== 0) {
      Log.error("Import read-only wallet: has passphrase");
      return false;
    }
    this._localstore.setHasPassPhrase(byte === 0 ? false : true);

    let tmpUint = stream.readUInt32();
    if (!tmpUint) {
      Log.error("Import read-only wallet: M");
      return false;
    }
    this._localstore.setM(tmpUint);

    tmpUint = stream.readUInt32();
    if (!tmpUint) {
      Log.error("Import read-only wallet: N");
      return false;
    }
    this._localstore.setN(tmpUint);

    tmpUint = stream.readUInt32();
    if (!tmpUint && tmpUint !== 0) {
      Log.error("Import read-only wallet: account");
      return false;
    }
    this._localstore.setAccount(tmpUint);

    let str = stream.readVarString();
    if (!str) {
      Log.error("Import read-only wallet: derivation strategy");
      return false;
    }
    this._localstore.setDerivationStrategy(str);

    let ethSCPubKey: bytes_t;
    ethSCPubKey = stream.readVarBytes(ethSCPubKey);
    if (!ethSCPubKey) {
      Log.error("Import read-only wallet: ethsc pubkey");
      return false;
    }
    this._localstore.setETHSCPrimaryPubKey(ethSCPubKey.toString("hex"));

    let requestPubKey: bytes_t;
    requestPubKey = stream.readVarBytes(requestPubKey);
    if (!requestPubKey) {
      Log.error("Import read-only wallet: request pubkey");
      return false;
    }
    if (requestPubKey.length === 0) this._localstore.setRequestPubKey("");
    else this._localstore.setRequestPubKey(requestPubKey.toString("hex"));

    let ownerPubKey: bytes_t;
    ownerPubKey = stream.readVarBytes(ownerPubKey);
    if (!ownerPubKey) {
      Log.error("Import read-only wallet: owner pubkey");
      return false;
    }
    if (ownerPubKey.length === 0) this._localstore.setOwnerPubKey("");
    else this._localstore.setOwnerPubKey(ownerPubKey.toString("hex"));

    // xpub
    let xPubKey: bytes_t;
    xPubKey = stream.readVarBytes(xPubKey);
    if (!xPubKey) {
      Log.error("Import read-only wallet: xpub");
      return false;
    }
    if (xPubKey.length === 0) this._localstore.setxPubKey("");
    else this._localstore.setxPubKey(Base58Check.encode(xPubKey));

    // btc xpub
    let xPubKeyBitcoin: bytes_t;
    xPubKeyBitcoin = stream.readVarBytes(xPubKeyBitcoin);
    if (!xPubKeyBitcoin) {
      Log.error("Import read-only wallet: btc xpub");
      return false;
    }
    if (xPubKeyBitcoin.length === 0) this._localstore.setxPubKeyBitcoin("");
    else this._localstore.setxPubKeyBitcoin(Base58Check.encode(xPubKeyBitcoin));

    // xpub HDPM
    let xPubKeyHDPM: bytes_t;
    xPubKeyHDPM = stream.readVarBytes(xPubKeyHDPM);
    if (!xPubKeyHDPM) {
      Log.error("Import read-only wallet: xpubHDPM");
      return false;
    }
    if (xPubKeyHDPM.length === 0) this._localstore.setxPubKeyHDPM("");
    else this._localstore.setxPubKeyHDPM(Base58Check.encode(xPubKeyHDPM));

    if (this._localstore.getN() > 1) {
      let len = stream.readVarUInt();
      if (!len) {
        Log.error("Import read-only wallet: pubkeyRing size");
        return false;
      }

      let requestPub: bytes_t, xpub: bytes_t;
      for (let i = 0; i < len.toNumber(); ++i) {
        requestPub = stream.readVarBytes(requestPub);
        if (!requestPub) {
          Log.error("Import read-only wallet: pubkey ring request pubkey");
          return false;
        }
        xpub = stream.readVarBytes(xpub);
        if (!xpub) {
          Log.error("Import read-only wallet: pubkey ring xpub");
          return false;
        }

        if (xpub.length === 0) {
          this._localstore.addPublicKeyRing(
            new PublicKeyRing(requestPub.toString("hex"), "")
          );
        } else {
          this._localstore.addPublicKeyRing(
            new PublicKeyRing(
              requestPub.toString("hex"),
              Base58Check.encode(xpub)
            )
          );
        }
      }
    } else {
      this._localstore.addPublicKeyRing(
        new PublicKeyRing(
          this._localstore.getRequestPubKey(),
          this._localstore.getxPubKeyHDPM()
        )
      );
    }
    let len = stream.readVarUInt();
    if (!len) {
      Log.error("Import read-only wallet: coininfo size");
      return false;
    }

    let infoList: CoinInfo[] = [];
    for (let i = 0; i < len.toNumber(); ++i) {
      let chainID = stream.readVarString();
      if (!chainID) {
        Log.error("Import read-only wallet: chainID");
        return false;
      }

      let info = new CoinInfo();
      info.setChainID(chainID);
      infoList.push(info);
    }
    this._localstore.setSubWalletInfoList(infoList);

    this._localstore.setReadonly(true);
    return true;
  }

  async exportMnemonic(payPasswd: string): Promise<string> {
    if (this._localstore.readonly()) {
      ErrorChecker.throwLogicException(
        Error.Code.UnsupportOperation,
        "Readonly wallet can not export mnemonic"
      );
    }

    if (this._localstore.getxPubKeyBitcoin()) {
      await this.regenerateKey(payPasswd);
      this.init();
    }

    let m = "";

    const encryptedMnemonic = this._localstore.getMnemonic();
    if (encryptedMnemonic) {
      m = AESDecrypt(encryptedMnemonic, payPasswd);
    }

    return Promise.resolve(m);
  }

  async regenerateKey(payPasswd: string) {
    Log.info("Doing regenerate pubkey...");
    let pubkeyRing: PublicKeyRing[] = this._localstore.getPublicKeyRing();

    let rootkey: HDKey;
    let stdrootkey: HDKey;
    let seed: Buffer;
    let tmpstr: string;
    let haveSeed = false;
    let haveRootkey = false;
    let havestdrootkey = false;

    if (
      !this._localstore.getSeed() &&
      this._localstore.getMnemonic() &&
      (!this._localstore.hasPassPhrase() ||
        (this._localstore.hasPassPhrase() && this._localstore.getPassPhrase()))
    ) {
      const mnemonic: string = AESDecrypt(
        this._localstore.getMnemonic(),
        payPasswd
      );

      const passphrase: string = AESDecrypt(
        this._localstore.getPassPhrase(),
        payPasswd
      );

      seed = Mnemonic.toSeed(mnemonic, passphrase);
      this._localstore.setSeed(AESEncrypt(seed.toString("hex"), payPasswd));
      haveSeed = true;

      if (this._localstore.getPassPhrase()) {
        this._localstore.setHasPassPhrase(true);
      }

      this._localstore.setPassPhrase("");
    } else if (this._localstore.getSeed()) {
      seed = AESDecrypt(this._localstore.getSeed(), payPasswd);
      haveSeed = true;
    }

    if (!this._localstore.getxPrivKey() && haveSeed) {
      rootkey = HDKey.fromMasterSeed(seed, KeySpec.Elastos);
      // encrypt private key
      this._localstore.setxPrivKey(
        AESEncrypt(rootkey.serializeBase58(), payPasswd)
      );

      haveRootkey = true;
    } else if (this._localstore.getxPrivKey()) {
      const privateKey = AESDecrypt(this._localstore.getxPrivKey(), payPasswd);
      rootkey = HDKey.deserializeBase58(privateKey, KeySpec.Elastos);
      haveRootkey = true;
    }

    if (!this._localstore.getRequestPrivKey() && haveRootkey) {
      const requestKey: HDKey = rootkey.deriveWithPath("m/1'/0");
      const bytes = requestKey.getPrivateKeyBytes();
      this._localstore.setRequestPrivKey(AESEncrypt(bytes, payPasswd));
      this._localstore.setRequestPubKey(
        requestKey.getPublicKeyBytes().toString("hex")
      );
    }

    // master public key
    if (!this._localstore.getxPubKey() && haveRootkey) {
      const xpub: HDKey = rootkey.deriveWithPath("m/44'/0'/0'");
      this._localstore.setxPubKey(Base58Check.encode(xpub.getPublicKeyBytes()));
    }

    if (!havestdrootkey && haveSeed) {
      stdrootkey = HDKey.fromMasterSeed(seed, KeySpec.Bitcoin);
      havestdrootkey = true;
    }

    // bitcoin master public key
    if (!this._localstore.getxPubKeyBitcoin() && havestdrootkey) {
      tmpstr = stdrootkey
        .deriveWithPath("m/44'/0'/0'")
        .serializePublicKeyBase58();
      this._localstore.setxPubKeyBitcoin(tmpstr);
    }

    // eth primary public key
    if (
      (!this._localstore.getETHSCPrimaryPubKey() ||
        !this._localstore.getSinglePrivateKey()) &&
      havestdrootkey
    ) {
      const ethkey: HDKey = stdrootkey.deriveWithPath("m/44'/60'/0'/0/0");

      const secp256 = new Secp256(Secp256.CURVE_K1);
      const ethscPubKey: string = secp256
        .publicKeyConvert(ethkey.getPublicKeyBytes(), false)
        .toString("hex");

      this._localstore.setETHSCPrimaryPubKey(ethscPubKey);
      this._localstore.setSinglePrivateKey(
        AESEncrypt(ethkey.serializeBase58(), payPasswd)
      );
    }

    // ripple primary public key
    if (!this._localstore.getRipplePrimaryPubKey() && havestdrootkey) {
      const ripplekey: HDKey = stdrootkey.deriveWithPath("44'/144'/0'/0/0");
      this._localstore.setRipplePrimaryPubKey(
        ripplekey.getPublicKeyBytes().toString("hex")
      );
    }

    if (!this._localstore.getxPubKeyHDPM() && haveRootkey) {
      const xpubHDPM: HDKey = rootkey.deriveWithPath("m/45'");
      this._localstore.setxPubKeyHDPM(xpubHDPM.serializePublicKeyBase58());
    }

    // 44'/coinIndex'/account'/change/index
    if (!this._localstore.getOwnerPubKey() && haveRootkey) {
      const bytes = rootkey
        .deriveWithPath("m/44'/0'/1'/0/0")
        .getPublicKeyBytes();
      this._localstore.setOwnerPubKey(bytes.toString("hex"));
    }

    if (this._localstore.getN() > 1 && this._localstore.getxPubKey()) {
      pubkeyRing = pubkeyRing.filter((item) => {
        !(
          this._localstore.getxPubKey() == item.getxPubKey() ||
          this._localstore.getxPubKeyHDPM() == item.getxPubKey()
        );
      });

      if (this._localstore.derivationStrategy() == "BIP44") {
        pubkeyRing.push(
          new PublicKeyRing(
            this._localstore.getRequestPubKey(),
            this._localstore.getxPubKey()
          )
        );
      } else {
        pubkeyRing.push(
          new PublicKeyRing(
            this._localstore.getRequestPubKey(),
            this._localstore.getxPubKeyHDPM()
          )
        );
      }
      this._localstore.setPublicKeyRing(pubkeyRing);
    }

    await this._localstore.save();
  }

  getSeed(payPasswd: string): Buffer {
    let seed = AESDecrypt(this._localstore.getSeed(), payPasswd);
    return Buffer.from(seed, "hex");
  }

  getETHSCPubKey(): Buffer {
    let pubkey = this._localstore.getETHSCPrimaryPubKey();
    return Buffer.from(pubkey, "hex");
  }

  getRipplePubKey(): Buffer {
    let pubkey = this._localstore.getRipplePrimaryPubKey();
    return Buffer.from(pubkey, "hex");
  }

  getSinglePrivateKey(passwd: string): Buffer {
    let privateKey = AESDecrypt(this._localstore.getSinglePrivateKey(), passwd);
    return Base58Check.decode(privateKey);
  }

  hasMnemonic(): boolean {
    return !!this._localstore.getMnemonic();
  }

  hasPassphrase(): boolean {
    return this._localstore.hasPassPhrase();
  }

  verifyPrivateKey(mnemonic: string, passphrase: string): boolean {
    if (!this._localstore.readonly() && this._xpub != null) {
      const rootkey = HDKey.fromMnemonic(mnemonic, passphrase, KeySpec.Elastos);
      const xpub: HDKey = rootkey.deriveWithPath("m/44'/0'/0'");
      if (xpub.getPublicKeyBase58() == this._xpub.getPublicKeyBase58()) {
        return true;
      }
    }

    return false;
  }

  async verifyPassPhrase(
    passphrase: string,
    payPasswd: string
  ): Promise<boolean> {
    if (!this._localstore.readonly() && this._xpub != null) {
      if (!this._localstore.getxPubKeyBitcoin()) {
        await this.regenerateKey(payPasswd);
        this.init();
      }
      let mnemonic = AESDecrypt(this._localstore.getMnemonic(), payPasswd);
      const rootkey = HDKey.fromMnemonic(mnemonic, passphrase, KeySpec.Elastos);
      const xpub: HDKey = rootkey.deriveWithPath("m/44'/0'/0'");
      if (xpub.getPublicKeyBase58() != this._xpub.getPublicKeyBase58())
        return Promise.resolve(false);

      return Promise.resolve(true);
    }

    return Promise.resolve(false);
  }

  async verifyPayPassword(payPasswd: string): Promise<boolean> {
    if (!this._localstore.readonly()) {
      if (!this._localstore.getxPubKeyBitcoin()) {
        await this.regenerateKey(payPasswd);
        this.init();
      }

      if (this._localstore.getRequestPrivKey())
        AESDecrypt(this._localstore.getRequestPrivKey(), payPasswd);
      else if (this._localstore.getSeed()) {
        AESDecrypt(this._localstore.getSeed(), payPasswd);
      } else if (this._localstore.getMnemonic()) {
        AESDecrypt(this._localstore.getMnemonic(), payPasswd);
      } else if (this._localstore.getSinglePrivateKey()) {
        AESDecrypt(this._localstore.getSinglePrivateKey(), payPasswd);
      } else if (this._localstore.getxPrivKey()) {
        AESDecrypt(this._localstore.getxPrivKey(), payPasswd);
      }

      return Promise.resolve(true);
    }

    return Promise.resolve(false);
  }

  async save(): Promise<void> {
    return await this._localstore.save();
  }

  async remove() {
    await this._localstore.remove();
  }

  async getDataPath(): Promise<string> {
    return await this._localstore.getDataPath();
  }
}
