/*
 * Copyright (c) 2019 Elastos Foundation
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

export const MAX_MULTISIGN_COSIGNERS = 6;

export enum SignType {
  Standard,
  MultiSign
}

export type AccountBasicInfo = {
  Type: "MultiSign" | "Standard";
  Readonly: boolean;
  SingleAddress: boolean;
  M: number;
  N: number;
  HasPassPhrase: boolean;
};

export type AccountPubKeyInfo = {
  m: number;
  n: number;
  derivationStrategy: string;
  xPubKey: string;
  xPubKeyHDPM: string;
  publicKeyRing: string[];
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
          // WAS return a -> pubkey().getHex() < b -> pubkey().getHex();
          return a
            .getPublicKeyBytes()
            .toString("hex")
            .localeCompare(b.getPublicKeyBytes().toString("hex"));
        });

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

    let deterministicKey: DeterministicKey = DeterministicKey.fromExtendedKey(
      xprv,
      DeterministicKey.ELASTOS_VERSIONS
    );
    const rootkey: HDKey = HDKey.fromKey(deterministicKey, KeySpec.Elastos);

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

    const encryptedSeed: string = AESEncrypt(seed, payPasswd);

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

    const encryptedMnemonic: string = AESEncrypt(
      Buffer.from(mnemonic),
      payPasswd
    );

    const seed: Buffer = Mnemonic.toSeed(mnemonic, passphrase);
    const encryptedSeed: string = AESEncrypt(seed, payPasswd);

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
    const encryptedSeed: string = AESEncrypt(seed, payPasswd);

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

    const encryptedMnemonic: string = AESEncrypt(
      Buffer.from(mnemonic),
      payPasswd
    );
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

    const encryptedSeed: string = AESEncrypt(seed, payPasswd);

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
      encryptedMnemonic = AESEncrypt(Buffer.from(mnemonic), payPasswd);
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
    const singlePrvKey = Buffer.from(singlePrivateKey);
    const encryptedSinglePrvKey: string = AESEncrypt(
      singlePrvKey.toString("hex"),
      passwd
    );

    const deterministicKey = DeterministicKey.fromExtendedKey(
      Base58Check.encode(singlePrvKey),
      DeterministicKey.ETHEREUM_VERSIONS
    );
    const k: HDKey = HDKey.fromKey(deterministicKey, KeySpec.Ethereum);

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

  /*
#if 0
  Account::Account(const std::string &path, const nlohmann &walletJSON) {
    _localstore = LocalStorePtr(new LocalStore(path));
    ErrorChecker::CheckParam(!ImportReadonlyWallet(walletJSON), Error::InvalidArgument,
                 "Invalid readonly wallet json");
    Init();
  }
#endif
*/

  /* TODO: try to migrate KeyStore later
  public static newFromKeyStore(storage: WalletStorage, ks: KeyStore, payPasswd: string) {
    const ElaNewWalletJson &json = ks.WalletJson();

    const account = new Account()
    account._localstore = new LocalStore(storage);
    let bytes: Buffer;
    let str: string;

    account._localstore.setReadonly(true);
    if (json.xPrivKey()) {
      bytes = Base58Check.decode(json.xPrivKey());
      const deterministicKey = new DeterministicKey(DeterministicKey.ELASTOS_VERSIONS)
      const rootkey: HDKey = HDKey.fromKey(deterministicKey, KeySpec.Elastos)

      const encrypedPrivKey: string = AESEncrypt(bytes, payPasswd);
      account._localstore.setxPrivKey(encrypedPrivKey);
      account._localstore.setReadonly(false);
    }

    if (json.Mnemonic()) {
      const mnemonic = json.Mnemonic()
      const encryptedMnemonic: string = AESEncrypt(Buffer.from(mnemonic), payPasswd);
      account._localstore.setMnemonic(encryptedMnemonic);
      account._localstore.setReadonly(false);
    }

    if (json.RequestPrivKey()) {
      bytes.setHex(json.RequestPrivKey());

      account._localstore.setRequestPrivKey(AESEncrypt(bytes, payPasswd));
      account._localstore.setReadonly(false);
    }

    if (json.GetSeed()) {
      bytes.setHex(json.GetSeed());
      account._localstore.setSeed(AESEncrypt(bytes, payPasswd));
      account._localstore.setReadonly(false);
    }

    if (json.GetSinglePrivateKey()) {
      bytes.setHex(json.GetSinglePrivateKey());
      account._localstore.setSinglePrivateKey(AESEncrypt(bytes, payPasswd));
      account._localstore.setReadonly(false);
    }

    account._localstore.setxPubKeyBitcoin(json.GetxPubKeyBitcoin());
    account._localstore.setxPubKey(json.xPubKey());
    account._localstore.setRequestPubKey(json.RequestPubKey());
    account._localstore.setPublicKeyRing(json.GetPublicKeyRing());
    account._localstore.setM(json.GetM());
    account._localstore.setN(json.GetN());
    account._localstore.setHasPassPhrase(json.HasPassPhrase());
    account._localstore.setSingleAddress(json.SingleAddress());
    account._localstore.setDerivationStrategy(json.DerivationStrategy());
    account._localstore.setxPubKeyHDPM(json.xPubKeyHDPM());
    account._localstore.setOwnerPubKey(json.OwnerPubKey());
    account._localstore.setSubWalletInfoList(json.GetCoinInfoList());
    account._localstore.setETHSCPrimaryPubKey(json.GetETHSCPrimaryPubKey());
    account._localstore.setRipplePrimaryPubKey(json.GetRipplePrimaryPubKey());

    account.init();
  }

*/
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

    if (this._localstore.getxPubKeyBitcoin().length === 0) {
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

      const xPubKey: string = Base58Check.encode(
        rootkey.deriveWithPath("m/44'/0'/0'").getPublicKeyBytes()
      );
      if (xPubKey != this._localstore.getxPubKey()) {
        ErrorChecker.throwParamException(
          Error.Code.InvalidArgument,
          "xpub not match"
        );
      }

      const encryptedSinglePrivateKey: string = AESEncrypt(
        ethkey.getPrivateKeyBytes(),
        newPassword
      );
      const encryptedSeed: string = AESEncrypt(seed, newPassword);
      const encryptedMnemonic: string = AESEncrypt(
        Buffer.from(mnemonic),
        newPassword
      );
      const encryptedxPrvKey: string = AESEncrypt(
        rootkey.getPrivateKeyBytes(),
        newPassword
      );
      const requestKey = rootkey.deriveWithPath("m/1'/0");

      const encryptedRequestPrvKey: string = AESEncrypt(
        requestKey.getPublicKeyBytes(),
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
    let j: AccountBasicInfo;

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
      return (
        this.getETHSCPubKey().toString() == account.getETHSCPubKey().toString()
      );
    }

    if (this.getSignType() == SignType.MultiSign) {
      if (this._allMultiSigners.length != account.multiSignCosigner().length)
        return false;

      for (let i = 0; i < this._allMultiSigners.length; ++i) {
        if (!this._allMultiSigners[i].equals(account.multiSignCosigner()[i]))
          return false;
      }

      return true;
    }

    return this._xpub.toString() == account.masterPubKey().toString();
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
    let j: AccountPubKeyInfo;
    const jCosigners: string[] = [];

    j["m"] = this._localstore.getM();
    j["n"] = this._localstore.getN();
    j["derivationStrategy"] = this._localstore.derivationStrategy();

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

  /*KeyStore Account::ExportKeystore(const std::string &payPasswd) const {
          if (!_localstore->Readonly() && _localstore->GetxPubKeyBitcoin().empty()) {
              RegenerateKey(payPasswd);
              Init();
          }

    bytes_t bytes;
    ElaNewWalletJson json;
    if (!_localstore->Readonly()) {
      bytes = AES::DecryptCCM(_localstore->GetxPrivKey(), payPasswd);
      if (!bytes.empty()) {
        json.SetxPrivKey(Base58::CheckEncode(bytes));
      }

      bytes = AES::DecryptCCM(_localstore->GetMnemonic(), payPasswd);
      json.SetMnemonic(std::string((char *)bytes.data(), bytes.size()));
      if (bytes.empty()) {
        json.SetHasPassPhrase(false);
      }

      bytes = AES::DecryptCCM(_localstore->GetRequestPrivKey(), payPasswd);
      json.SetRequestPrivKey(bytes.getHex());

      bytes = AES::DecryptCCM(_localstore->GetSeed(), payPasswd);
      json.SetSeed(bytes.getHex());

      bytes = AES::DecryptCCM(_localstore->GetSinglePrivateKey(), payPasswd);
      json.SetSinglePrivateKey(bytes.getHex());
    }

    json.SetOwnerPubKey(_localstore->GetOwnerPubKey());
    json.SetxPubKey(_localstore->GetxPubKey());
    json.SetxPubKeyHDPM(_localstore->GetxPubKeyHDPM());
    json.SetRequestPubKey(_localstore->GetRequestPubKey());
    json.SetPublicKeyRing(_localstore->GetPublicKeyRing());
    json.SetM(_localstore->GetM());
    json.SetN(_localstore->GetN());
    json.SetHasPassPhrase(_localstore->HasPassPhrase());
    json.SetDerivationStrategy(_localstore->DerivationStrategy());
    json.SetAccount(0);
    json.SetSingleAddress(_localstore->SingleAddress());
    json.SetCoinInfoList(_localstore->GetSubWalletInfoList());
    json.SetETHSCPrimaryPubKey(_localstore->GetETHSCPrimaryPubKey());
          json.SetxPubKeyBitcoin(_localstore->GetxPubKeyBitcoin());
          json.SetRipplePrimaryPubKey(_localstore->GetRipplePrimaryPubKey());

    return KeyStore(json);
  }

#if 0
#define READONLY_WALLET_VERSION00 0
  nlohmann::json Account::ExportReadonlyWallet() const {
    nlohmann::json j;
    bytes_t tmp;
    ByteStream stream;

    stream.WriteUint8(READONLY_WALLET_VERSION00);
    stream.WriteUint8((uint8_t)(_localstore->SingleAddress() ? 1 : 0));
    stream.WriteUint8((uint8_t)(_localstore->HasPassPhrase() ? 1 : 0));
    stream.WriteUint32(_localstore->GetM());
    stream.WriteUint32(_localstore->GetN());
    stream.WriteUint32(_localstore->Account());
    stream.WriteVarString(_localstore->DerivationStrategy());

    tmp.setHex(_localstore->GetETHSCPrimaryPubKey());
    stream.WriteVarBytes(tmp);

    if (_localstore->GetN() > 1) {
      tmp.clear();
      // request pubkey
      stream.WriteVarBytes(tmp);
      // owner pubkey
      stream.WriteVarBytes(tmp);
      // xpub
              stream.WriteVarBytes(tmp);
              // btc xpub
      stream.WriteVarBytes(tmp);
      // xpub HDPM
      stream.WriteVarBytes(tmp);
    } else {
      tmp.setHex(_localstore->GetRequestPubKey());
      stream.WriteVarBytes(tmp);

      tmp.setHex(_localstore->GetOwnerPubKey());
      stream.WriteVarBytes(tmp);

      if (!Base58::CheckDecode(_localstore->GetxPubKey(), tmp)) {
        Log::error("Decode xpub fail when exoprt read-only wallet");
        return j;
      }
      stream.WriteVarBytes(tmp);

              if (!Base58::CheckDecode(_localstore->GetxPubKeyBitcoin(), tmp)) {
                  Log::error("Decode btc xpub fail when exoprt read-only wallet");
                  return j;
              }
              stream.WriteVarBytes(tmp);

      if (!Base58::CheckDecode(_localstore->GetxPubKeyHDPM(), tmp)) {
        Log::error("Decode xpubHDPM fail when export read-only wallet");
        return j;
      }
      stream.WriteVarBytes(tmp);
    }

    if (_localstore->GetN() > 1) {
      const std::vector<PublicKeyRing> &pubkeyRing = _localstore->GetPublicKeyRing();
      stream.WriteVarUint(pubkeyRing.size());
      for (size_t i = 0; i < pubkeyRing.size(); ++i) {
        tmp.setHex(pubkeyRing[i].GetRequestPubKey());
        stream.WriteVarBytes(tmp);

        if (!Base58::CheckDecode(pubkeyRing[i].GetxPubKey(), tmp)) {
          Log::error("Decode pubkey ring xpub fail when export read-only wallet");
          return j;
        }
        stream.WriteVarBytes(tmp);
      }
    }

    const std::vector<CoinInfoPtr> &info = _localstore->GetSubWalletInfoList();
    stream.WriteVarUint(info.size());
    for(size_t i = 0; i < info.size(); ++i)
      stream.WriteVarString(info[i]->GetChainID());

    const bytes_t &bytes = stream.GetBytes();

    j["Data"] = bytes.getBase64();

    return j;
  }

  bool Account::ImportReadonlyWallet(const nlohmann::json &walletJSON) {
    if (walletJSON.find("Data") == walletJSON.end()) {
      Log::error("Import read-only wallet: json format error");
      return false;
    }

    uint8_t version = 0;
    bytes_t bytes;
    bytes.setBase64(walletJSON["Data"].get<std::string>());
    ByteStream stream(bytes);

    if (!stream.ReadUint8(version)) {
      Log::error("Import read-only wallet: version");
      return false;
    }

    uint8_t byte;
    if (!stream.ReadUint8(byte)) {
      Log::error("Import read-only wallet: single address");
      return false;
    }
    _localstore->SetSingleAddress(byte != 0);

    if (!stream.ReadUint8(byte)) {
      Log::error("Import read-only wallet: has passphrase");
      return false;
    }
    _localstore->SetHasPassPhrase(byte != 0);

    uint32_t tmpUint;
    if (!stream.ReadUint32(tmpUint)) {
      Log::error("Import read-only wallet: M");
      return false;
    }
    _localstore->SetM(tmpUint);

    if (!stream.ReadUint32(tmpUint)) {
      Log::error("Import read-only wallet: N");
      return false;
    }
    _localstore->SetN(tmpUint);

    if (!stream.ReadUint32(tmpUint)) {
      Log::error("Import read-only wallet: account");
      return false;
    }
    _localstore->SetAccount(tmpUint);

    std::string str;
    if (!stream.ReadVarString(str)) {
      Log::error("Import read-only wallet: derivation strategy");
      return false;
    }
    _localstore->SetDerivationStrategy(str);

    if (!stream.ReadVarBytes(bytes)) {
      Log::error("Import read-only wallet: ethsc pubkey");
      return false;
    }
    _localstore->SetETHSCPrimaryPubKey(bytes.getHex());

    if (!stream.ReadVarBytes(bytes)) {
      Log::error("Import read-only wallet: request pubkey");
      return false;
    }
    _localstore->SetRequestPubKey(bytes.getHex());

    if (!stream.ReadVarBytes(bytes)) {
      Log::error("Import read-only wallet: owner pubkey");
      return false;
    }
    _localstore->SetOwnerPubKey(bytes.getHex());

          // xpub
    if (!stream.ReadVarBytes(bytes)) {
      Log::error("Import read-only wallet: xpub");
      return false;
    }
    if (bytes.empty())
      _localstore->SetxPubKey("");
    else
      _localstore->SetxPubKey(Base58::CheckEncode(bytes));

          // btc xpub
          if (!stream.ReadVarBytes(bytes)) {
              Log::error("Import read-only wallet: btc xpub");
              return false;
          }
          if (bytes.empty())
              _localstore->SetxPubKeyBitcoin("");
          else
              _localstore->SetxPubKeyBitcoin(Base58::CheckEncode(bytes));

          // xpub HDPM
    if (!stream.ReadVarBytes(bytes)) {
      Log::error("Import read-only wallet: xpubHDPM");
      return false;
    }
    if (bytes.empty())
              _localstore->SetxPubKeyHDPM("");
    else
      _localstore->SetxPubKeyHDPM(Base58::CheckEncode(bytes));

    uint64_t len;
    if (_localstore->GetN() > 1) {
      if (!stream.ReadVarUint(len)) {
        Log::error("Import read-only wallet: pubkeyRing size");
        return false;
      }

      bytes_t requestPub, xpub;
      for (size_t i = 0; i < len; ++i) {
        if (!stream.ReadVarBytes(requestPub)) {
          Log::error("Import read-only wallet: pubkey ring request pubkey");
          return false;
        }

        if (!stream.ReadVarBytes(xpub)) {
          Log::error("Import read-only wallet: pubkey ring xpub");
          return false;
        }

        if (xpub.empty())
          _localstore->AddPublicKeyRing(PublicKeyRing(requestPub.getHex(), ""));
        else
          _localstore->AddPublicKeyRing(PublicKeyRing(requestPub.getHex(), Base58::CheckEncode(xpub)));
      }
    } else {
      _localstore->AddPublicKeyRing(PublicKeyRing(_localstore->GetRequestPubKey(), _localstore->GetxPubKeyHDPM()));
    }

    if (!stream.ReadVarUint(len)) {
      Log::error("Import read-only wallet: coininfo size");
      return false;
    }

    std::vector<CoinInfoPtr> infoList;
    for (size_t i = 0; i < len; ++i) {
      std::string chainID;
      if (!stream.ReadVarString(chainID)) {
        Log::error("Import read-only wallet: chainID");
        return false;
      }

      CoinInfoPtr info(new CoinInfo());
      info->SetChainID(chainID);

      infoList.push_back(info);
    }
    _localstore->SetSubWalletInfoList(infoList);

    _localstore->SetReadonly(true);
    return true;
  }
#endif
*/

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

    let m: string;

    const encryptedMnemonic = this._localstore.getMnemonic();
    if (encryptedMnemonic) {
      const bytes = AESDecrypt(encryptedMnemonic, payPasswd);
      m = bytes.toString();
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
      const mnemonic = AESDecrypt(this._localstore.getMnemonic(), payPasswd);

      const passphrase: string = AESDecrypt(
        this._localstore.getPassPhrase(),
        payPasswd
      );

      seed = Mnemonic.toSeed(mnemonic, passphrase);
      this._localstore.setSeed(AESEncrypt(seed, payPasswd));
      haveSeed = true;

      if (this._localstore.getPassPhrase()) {
        this._localstore.setHasPassPhrase(true);
      }

      this._localstore.setPassPhrase("");
    } else if (this._localstore.getSeed()) {
      const bytes = AESDecrypt(this._localstore.getSeed(), payPasswd);
      seed = bytes;
      haveSeed = true;
    }

    if (!this._localstore.getxPrivKey() && haveSeed) {
      rootkey = HDKey.fromMasterSeed(seed, KeySpec.Elastos);
      // encrypt private key
      this._localstore.setxPrivKey(
        AESEncrypt(rootkey.getPrivateKeyBytes(), payPasswd)
      );
      haveRootkey = true;
    } else if (this._localstore.getxPrivKey()) {
      const privateKey = AESDecrypt(this._localstore.getxPrivKey(), payPasswd);
      const deterministicKey = DeterministicKey.fromExtendedKey(
        privateKey,
        DeterministicKey.ELASTOS_VERSIONS
      );
      rootkey = HDKey.fromKey(deterministicKey, KeySpec.Elastos);
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
    const seed = AESDecrypt(this._localstore.getSeed(), payPasswd);
    return seed;
  }

  getETHSCPubKey(): Buffer {
    const pubkey = Buffer.from(this._localstore.getETHSCPrimaryPubKey());
    return pubkey;
  }

  getRipplePubKey(): Buffer {
    const pubkey = Buffer.from(this._localstore.getRipplePrimaryPubKey());
    return pubkey;
  }

  getSinglePrivateKey(passwd: string) {
    return AESDecrypt(this._localstore.getSinglePrivateKey(), passwd);
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
      const mnemonic = this._localstore.getMnemonic();
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

  remove() {
    this._localstore.remove();
  }

  async getDataPath(): Promise<string> {
    return await this._localstore.getDataPath();
  }
}
