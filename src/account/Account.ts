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

import { Error, ErrorChecker } from "../common/ErrorChecker";
import { Log } from "../common/Log";
import { LocalStore } from "../persistence/LocalStore";
import { bytes_t, json } from "../types";
import { Base58, Base58Check } from "../walletcore/base58";
import { CoinInfo } from "../walletcore/CoinInfo";
import { CoinType } from "../walletcore/cointype";
import { HDKey, KeySpec } from "../walletcore/hdkey";
import { DeterministicKey, Version } from "../walletcore/deterministickey";
import { Mnemonic } from "../walletcore/mnemonic";
import { AESDecrypt, AESEncrypt } from "../walletcore/aes";
import { PublicKeyRing } from "../walletcore/publickeyring";
import { WalletStorage } from "../persistence/WalletStorage";

export const MAX_MULTISIGN_COSIGNERS = 6;

export enum SignType {
  Standard,
  MultiSign
}

export class Account {
  private _localstore: LocalStore;
  private _xpub: HDKey;
  private _btcMasterPubKey: HDKey;
  private _cosignerIndex: number;
  private _curMultiSigner: HDKey; // multi sign current wallet signer
  private _allMultiSigners: HDKey[]; // including _multiSigner and sorted
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

    // let bytes: bytes_t; // TODO: alloc

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

    if (!this._localstore.getxPubKeyBitcoin()) {
      ErrorChecker.checkParam(
        !Base58Check.decode(this._localstore.getxPubKeyBitcoin()),
        Error.Code.PubKeyFormat,
        "xpubkeyBitcoin decode error"
      );
      const deterministicKey = new DeterministicKey(
        DeterministicKey.BITCOIN_VERSIONS
      );
      this._btcMasterPubKey = HDKey.fromKey(deterministicKey, KeySpec.Bitcoin);
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
          let xPubKey: string = this._localstore
            .getPublicKeyRing()
            [i].getxPubKey();
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
            // TODO: compare two HDKey objects
            this._curMultiSigner == sortedSigners[i]
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

  /*Account::Account(const LocalStorePtr &store) :
		_localstore(store) {
		Init();
	}
	*/

  public static newFromAccount(storage: WalletStorage) {
    let account = new Account();
    account._localstore = new LocalStore(storage);
    account._localstore.load();
    account.init();
    return account;
  }

  public static newFromPublicKeyRings(
    path: string,
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
    account._localstore = new LocalStore(path);
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
    // account._localstore.setRipplePrimaryPubKey("");

    if (compatible) {
      account._localstore.setDerivationStrategy("BIP44");
    } else {
      account._localstore.setDerivationStrategy("BIP45");
    }

    account.init();
    return account;
  }

  public static newFromXPrivateKey(
    path: string,
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
    // bytes_t bytes;
    ErrorChecker.checkLogic(
      !Base58Check.decode(xprv),
      Error.Code.InvalidArgument,
      "Invalid xprv"
    );

    const deterministicKey: DeterministicKey = new DeterministicKey(
      DeterministicKey.ELASTOS_VERSIONS
    );
    const rootkey: HDKey = HDKey.fromKey(deterministicKey, KeySpec.Elastos);
    const privateKey = rootkey.getPrivateKeyBytes();

    const encryptedxPrvKey: string = AESEncrypt(privateKey, payPasswd);
    const xPubKey: string = Base58Check.encode(
      rootkey.deriveWithPath("44'/0'/0'").getPublicKeyBytes()
    );

    const requestKey: HDKey = rootkey.deriveWithPath("1'/0");
    const encryptedRequestPrvKey: string = AESEncrypt(
      requestKey.getPrivateKeyBytes(),
      payPasswd
    );
    const requestPubKey: string = requestKey
      .getPrivateKeyBytes()
      .toString("hex");

    const account = new Account();
    account._localstore = new LocalStore(path);
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
    // account._localstore.setRipplePrimaryPubKey("");
    account._localstore.setxPubKeyBitcoin("");
    account._localstore.setSinglePrivateKey("");

    if (compatible) {
      account._localstore.setDerivationStrategy("BIP44");
      account._localstore.addPublicKeyRing(new PublicKeyRing("", xPubKey));
      account._localstore.setxPubKeyHDPM(xPubKey);
    } else {
      account._localstore.setDerivationStrategy("BIP45");
      const xpubPurpose: string = Base58Check.encode(
        rootkey.deriveWithPath("45'").getPrivateKeyBytes()
      );
      account._localstore.addPublicKeyRing(
        new PublicKeyRing(requestPubKey, xpubPurpose)
      );
      account._localstore.setxPubKeyHDPM(xpubPurpose);
    }

    account.init();
    return account;
  }

  public static newFromMultiSignMnemonic(
    path: string,
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

    const seed: Buffer = Mnemonic.toSeed(mnemonic, passphrase);
    const rootkey: HDKey = HDKey.fromMasterSeed(seed, KeySpec.Elastos);

    const stdrootkey: HDKey = HDKey.fromMasterSeed(seed, KeySpec.Bitcoin);
    const ethkey: HDKey = stdrootkey.deriveWithPath("44'/60'/0'/0/0");

    const encryptedSeed: string = AESEncrypt(seed, payPasswd);
    const encryptedethPrvKey: string = AESEncrypt(
      ethkey.getPrivateKeyBytes(),
      payPasswd
    );
    const ethscPubKey: string = ethkey.getPublicKeyBytes().toString("hex");
    const ripplePubKey: string = stdrootkey
      .deriveWithPath("44'/144'/0'/0/0")
      .getPublicKeyBytes()
      .toString("hex");
    const encryptedMnemonic: string = AESEncrypt(mnemonic, payPasswd);
    const encryptedxPrvKey: string = AESEncrypt(
      rootkey.getPrivateKeyBytes(),
      payPasswd
    );
    const xPubKey: string = Base58Check.encode(
      rootkey.deriveWithPath("44'/0'/0'").getPublicKeyBytes()
    );

    const xpubBitcoin: string = Base58Check.encode(
      stdrootkey.deriveWithPath("44'/0'/0'").getPublicKeyBytes()
    );

    const requestKey: HDKey = rootkey.deriveWithPath("1'/0");
    const encryptedRequestPrvKey: string = AESEncrypt(
      requestKey.getPrivateKeyBytes(),
      payPasswd
    );
    const requestPubKey: string = requestKey
      .getPublicKeyBytes()
      .toString("hex");

    const account = new Account();
    account._localstore = new LocalStore(path);
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
    // account._localstore.setRipplePrimaryPubKey(ripplePubKey);

    if (compatible) {
      account._localstore.setDerivationStrategy("BIP44");
      account._localstore.addPublicKeyRing(new PublicKeyRing("", xPubKey));
      account._localstore.setxPubKeyHDPM(xPubKey);
    } else {
      account._localstore.setDerivationStrategy("BIP45");
      const xpubPurpose: string = Base58Check.encode(
        rootkey.deriveWithPath("45'").getPublicKeyBytes()
      );
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
    storage: WalletStorage,
    mnemonic: string,
    passphrase: string,
    payPasswd: string,
    singleAddress: boolean
  ) {
    let account = new Account();

    const seed: Buffer = Mnemonic.toSeed(mnemonic, passphrase);
    const rootkey: HDKey = HDKey.fromMasterSeed(seed, KeySpec.Elastos);

    const stdrootkey: HDKey = HDKey.fromMasterSeed(seed, KeySpec.Bitcoin);
    const ethkey: HDKey = stdrootkey.deriveWithPath("44'/60'/0'/0/0");

    const encryptedSeed: string = AESEncrypt(seed, payPasswd);

    const encryptedethPrvKey: string = AESEncrypt(
      ethkey.getPrivateKeyBytes(),
      payPasswd
    );

    const ethscPubKey: string = ethkey.getPublicKeyBytes().toString("hex");

    const ripplePubKey: string = stdrootkey
      .deriveWithPath("44'/144'/0'/0/0")
      .getPublicKeyBytes()
      .toString("hex");

    const encryptedMnemonic: string = AESEncrypt(mnemonic, payPasswd);
    const encryptedxPrvKey: string = AESEncrypt(
      rootkey.getPrivateKeyBytes(),
      payPasswd
    );

    const xpubBitcoin: string = Base58Check.encode(
      stdrootkey.deriveWithPath("44'/0'/0'").getPublicKeyBytes()
    );

    const xPubKey: string = Base58Check.encode(
      rootkey.deriveWithPath("44'/0'/0'").getPublicKeyBytes()
    );

    const xpubHDPM: string = Base58Check.encode(
      rootkey.deriveWithPath("45'").getPublicKeyBytes()
    );

    const requestKey: HDKey = rootkey.deriveWithPath("1'/0");

    const encryptedRequestPrvKey: string = AESEncrypt(
      requestKey.getPrivateKeyBytes(),
      payPasswd
    );

    const requestPubKey: string = requestKey
      .getPublicKeyBytes()
      .toString("hex");
    const ownerPubKey: string = rootkey
      .deriveWithPath("44'/0'/1'/0/0")
      .getPublicKeyBytes()
      .toString("hex");

    // TODO: path should be replaced with a WalletStorage object
    account._localstore = new LocalStore(storage);
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
    // TODO this._localstore.setxPubKeyBitcoin(xpubBitcoin);
    account._localstore.setSinglePrivateKey(encryptedethPrvKey);
    // TODO this._localstore.setRipplePrimaryPubKey(ripplePubKey);

    account.init();
    return account;
  }

  public static newFromSinglePrivateKey(
    path: string,
    singlePrivateKey: string,
    passwd: string
  ) {
    // TODO
    // should convert singlePrivateKey to hex string
    const singlePrvKey = singlePrivateKey;
    const encryptedSinglePrvKey: string = AESEncrypt(singlePrvKey, passwd);

    const deterministicKey = new DeterministicKey(
      DeterministicKey.BITCOIN_VERSIONS
    );
    const rootkey: HDKey = HDKey.fromKey(deterministicKey, KeySpec.Elastos);
    const ethscPubKey: string = rootkey.getPublicKeyBytes().toString("hex");
    const account = new Account();
    account._localstore = new LocalStore(path);
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
    // account._localstore.setRipplePrimaryPubKey("");

    account.init();
    return account;
  }

  /*
#if 0
	Account::Account(const std::string &path, const nlohmann::json &walletJSON) {
		_localstore = LocalStorePtr(new LocalStore(path));
		ErrorChecker::CheckParam(!ImportReadonlyWallet(walletJSON), Error::InvalidArgument,
								 "Invalid readonly wallet json");
		Init();
	}
#endif
*/

	public static newFromKeyStore(path: string, ks: KeyStore, payPasswd: string) {
		const ElaNewWalletJson &json = ks.WalletJson();
		
		const account = new Account()
		account._localstore = new LocalStore(path);
		bytes_t bytes;
		std::string str;

		account._localstore.setReadonly(true);
		if (!json.xPrivKey().empty()) {
			Base58::CheckDecode(json.xPrivKey(), bytes);
			HDKeychain rootkey(CTElastos, bytes);
			
			const encrypedPrivKey: string = AESEncrypt(bytes, payPasswd);
			account._localstore.setxPrivKey(encrypedPrivKey);
			account._localstore.setReadonly(false);
		}

		if (!json.Mnemonic().empty()) {
			// TODO
			// const mnemonic = bytes_t(json.Mnemonic().data(), json.Mnemonic().size())
			const encryptedMnemonic: string = AESEncrypt(mnemonic, payPasswd);
			account._localstore.setMnemonic(encryptedMnemonic);
			account._localstore.setReadonly(false);
		}

		if (!json.RequestPrivKey().empty()) {
			bytes.setHex(json.RequestPrivKey());

			account._localstore.setRequestPrivKey(AESEncrypt(bytes, payPasswd));
			account._localstore.setReadonly(false);
		}

		if (!json.GetSeed().empty()) {
			bytes.setHex(json.GetSeed());
			account._localstore.setSeed(AESEncrypt(bytes, payPasswd));
			account._localstore.setReadonly(false);
		}

		if (!json.GetSinglePrivateKey().empty()) {
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

  public RequestPubKey(): bytes_t {
    return this._requestPubKey;
  }

  public rootKey(payPasswd: string): HDKey {
    if (this._localstore.readonly()) {
      ErrorChecker.throwLogicException(
        Error.Code.Key,
        "Readonly wallet without prv key"
      );
    }

    if (this._localstore.getxPubKeyBitcoin().length === 0) {
      // TODO
      // this.regenerateKey(payPasswd);
      this.init();
    }

    let extkey: string = AESDecrypt(this._localstore.getxPrivKey(), payPasswd);
    let key = HDKey.deserializeBase58(extkey, KeySpec.Elastos);
    return key;
  }

  requestPrivKey(payPassword: string) : DeterministicKey{
		if (this._localstore.readonly()) {
			ErrorChecker.throwLogicException(Error.Code.Key, "Readonly wallet without prv key");
		}

		if (!this._localstore.getxPubKeyBitcoin()) {
			this.regenerateKey(payPassword);
			this.init();
		}

		const bytes = AESDecrypt(this._localstore.getRequestPrivKey(), payPassword);
		let key = new DeterministicKey(DeterministicKey.ELASTOS_VERSIONS)
		key.privateKey = bytes
		return key;
	}

  public masterPubKey(): HDKey {
    return this._xpub;
  }

  bitcoinMasterPubKey(): HDKey {
    return this._btcMasterPubKey;
  }

  public getxPrvKeyString(payPasswd: string): string {
    if (this._localstore.readonly()) {
      ErrorChecker.throwLogicException(
        Error.Code.UnsupportOperation,
        "Readonly wallet can not export private key"
      );
    }

    if (this._localstore.getxPubKeyBitcoin().length === 0) {
      // TODO
      // this.regenerateKey(payPasswd);
      this.init();
    }

    return AESDecrypt(this._localstore.getxPrivKey(), payPasswd);
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

  changePassword(oldPasswd: string, newPasswd: string) {
    if (!this._localstore.readonly()) {
      ErrorChecker.checkPassword(newPasswd, "New");

      if (this._localstore.getxPubKeyBitcoin().length === 0) {
        this.regenerateKey(oldPasswd);
        this.init();
      }

      this._localstore.changePasswd(oldPasswd, newPasswd);

      this._localstore.save();
    }
  }

  /*
	void Account::ResetPassword(const std::string &mnemonic, const std::string &passphrase, const std::string &newPassword) {
		if (!_localstore->Readonly()) {
			ErrorChecker::CheckPassword(newPassword, "New");

			uint512 seed = Mnemonic::DeriveSeed(mnemonic, passphrase);
			HDSeed hdseed(seed.bytes());
			HDKeychain rootkey(CTElastos, hdseed.getExtendedKey(CTElastos, true));
			HDKeychain stdrootkey(CTBitcoin, hdseed.getExtendedKey(CTBitcoin, true));
							HDKeychain ethkey = stdrootkey.getChild("44'/60'/0'/0/0");
			std::string xPubKey = Base58::CheckEncode(rootkey.getChild("44'/0'/0'").getPublic().extkey());
			if (xPubKey != _localstore->GetxPubKey())
				ErrorChecker::ThrowParamException(Error::InvalidArgument, "xpub not match");

			std::string encryptedSinglePrivateKey = AES::EncryptCCM(ethkey.privkey(), newPassword);
			std::string encryptedSeed = AES::EncryptCCM(bytes_t(seed.begin(), seed.size()), newPassword);
			std::string encryptedMnemonic = AES::EncryptCCM(bytes_t(mnemonic.data(), mnemonic.size()), newPassword);
			std::string encryptedxPrvKey = AES::EncryptCCM(rootkey.extkey(), newPassword);
			HDKeychain requestKey = rootkey.getChild("1'/0");
			std::string encryptedRequestPrvKey = AES::EncryptCCM(requestKey.privkey(), newPassword);

			_localstore->SetSeed(encryptedSeed);
			_localstore->SetMnemonic(encryptedMnemonic);
			_localstore->SetxPrivKey(encryptedxPrvKey);
			_localstore->SetRequestPrivKey(encryptedRequestPrvKey);
			_localstore->SetSinglePrivateKey(encryptedSinglePrivateKey);

			_localstore->Save();
		}
	}*/

  public getBasicInfo(): json {
    let j = {};

    if (this.getSignType() == SignType.MultiSign) j["Type"] = "MultiSign";
    else j["Type"] = "Standard";

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
		

		if (this._xpub == null && account.masterPubKey() != null ||
			this._xpub != null && account.masterPubKey() == null) {
				return false;
			}
			

		if (this._xpub == null && account.masterPubKey() == null) {
			return this.getETHSCPubKey() == account.getETHSCPubKey();
		}
			
		if (this.getSignType() == SignType.MultiSign) {
			if (this._allMultiSigners.length != account.multiSignCosigner().length)
				return false;

			for (let i = 0; i < this._allMultiSigners.length; ++i) {
				if (this._allMultiSigners[i] != account.multiSignCosigner()[i])
					return false;
			}

			return true;
		}

		return this._xpub == account.masterPubKey();
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

	/*
	nlohmann::json Account::GetPubKeyInfo() const {
		nlohmann::json j, jCosigners;

		j["m"] = _localstore->GetM();
		j["n"] = _localstore->GetN();
		j["derivationStrategy"] = _localstore->DerivationStrategy();

		if (_localstore->GetN() > 1 && _localstore->Readonly()) {
			j["xPubKey"] = nlohmann::json();
			j["xPubKeyHDPM"] = nlohmann::json();
		} else {
			j["xPubKey"] = _localstore->GetxPubKey();
			j["xPubKeyHDPM"] = _localstore->GetxPubKeyHDPM();
		}

		for (size_t i = 0; i < _localstore->GetPublicKeyRing().size(); ++i)
			jCosigners.push_back(_localstore->GetPublicKeyRing()[i].GetxPubKey());

		j["publicKeyRing"] = jCosigners;

		return j;
	}*/

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

	std::string Account::ExportMnemonic(const std::string &payPasswd) const {
		if (_localstore->Readonly()) {
			ErrorChecker::ThrowLogicException(Error::UnsupportOperation, "Readonly wallet can not export mnemonic");
		}

					if (_localstore->GetxPubKeyBitcoin().empty()) {
							RegenerateKey(payPasswd);
							Init();
					}

					std::string m;

		std::string encryptedMnemonic = _localstore->GetMnemonic();
					if (!encryptedMnemonic.empty()) {
							bytes_t bytes = AES::DecryptCCM(encryptedMnemonic, payPasswd);
							m = std::string((char *) bytes.data(), bytes.size());
					}

		return m;
	}

			void Account::RegenerateKey(const std::string &payPasswd) const {
					Log::info("Doing regenerate pubkey...");
					std::vector<PublicKeyRing> pubkeyRing = _localstore->GetPublicKeyRing();

					HDKeychain rootkey, stdrootkey;
					bytes_t bytes;
					uint512 seed;
					std::string tmpstr;
					bool haveSeed = false, haveRootkey = false, havestdrootkey = false;

					if (_localstore->GetSeed().empty() && !_localstore->GetMnemonic().empty() &&
							(!_localstore->HasPassPhrase() || (_localstore->HasPassPhrase() && !_localstore->GetPassPhrase().empty()))) {

							bytes = AES::DecryptCCM(_localstore->GetMnemonic(), payPasswd);
							std::string mnemonic = std::string((char *) &bytes[0], bytes.size());
							bytes = AES::DecryptCCM(_localstore->GetPassPhrase(), payPasswd);
							std::string passphrase = std::string((char *)&bytes[0], bytes.size());
							seed = Mnemonic::DeriveSeed(mnemonic, passphrase);
							_localstore->SetSeed(AES::EncryptCCM(seed.bytes(), payPasswd));
							haveSeed = true;

							if (!_localstore->GetPassPhrase().empty())
									_localstore->SetHasPassPhrase(true);
							_localstore->SetPassPhrase("");
					} else if (!_localstore->GetSeed().empty()) {
							bytes = AES::DecryptCCM(_localstore->GetSeed(), payPasswd);
							seed = bytes;
							haveSeed = true;
					}

					if (_localstore->GetxPrivKey().empty() && haveSeed) {
							HDSeed hdseed(seed.bytes());
							rootkey = HDKeychain(CTElastos, hdseed.getExtendedKey(CTElastos, true));
							// encrypt private key
							_localstore->SetxPrivKey(AES::EncryptCCM(rootkey.extkey(), payPasswd));
							haveRootkey = true;
					} else if (!_localstore->GetxPrivKey().empty()) {
							bytes = AES::DecryptCCM(_localstore->GetxPrivKey(), payPasswd);
							rootkey = HDKeychain(CTElastos, bytes);
							haveRootkey = true;
					}

					if (_localstore->GetRequestPrivKey().empty() && haveRootkey) {
							HDKeychain requestKey = rootkey.getChild("1'/0");
							bytes = requestKey.privkey();
							_localstore->SetRequestPrivKey(AES::EncryptCCM(bytes, payPasswd));
							_localstore->SetRequestPubKey(requestKey.pubkey().getHex());
					}

					// master public key
					if (_localstore->GetxPubKey().empty() && haveRootkey) {
							HDKeychain xpub = rootkey.getChild("44'/0'/0'").getPublic();
							_localstore->SetxPubKey(Base58::CheckEncode(xpub.extkey()));
					}

					if (!havestdrootkey && haveSeed) {
							HDSeed hdseed(seed.bytes());
							stdrootkey = HDKeychain(CTBitcoin, hdseed.getExtendedKey(CTBitcoin, true));
							havestdrootkey = true;
					}
					// bitcoin master public key
					if (_localstore->GetxPubKeyBitcoin().empty() && havestdrootkey) {
							tmpstr = Base58::CheckEncode(stdrootkey.getChild("44'/0'/0'").getPublic().extkey());
							_localstore->SetxPubKeyBitcoin(tmpstr);
					}
					// eth primary public key
					if ((_localstore->GetETHSCPrimaryPubKey().empty() || _localstore->GetSinglePrivateKey().empty()) && havestdrootkey) {
							HDKeychain ethkey = stdrootkey.getChild("44'/60'/0'/0/0");
							tmpstr = ethkey.uncompressed_pubkey().getHex();
							_localstore->SetETHSCPrimaryPubKey(tmpstr);
							_localstore->SetSinglePrivateKey(AES::EncryptCCM(ethkey.privkey(), payPasswd));
					}
					// ripple primary public key
					if (_localstore->GetRipplePrimaryPubKey().empty() && havestdrootkey) {
							HDKeychain ripplekey = stdrootkey.getChild("44'/144'/0'/0/0");
							_localstore->SetRipplePrimaryPubKey(ripplekey.pubkey().getHex());
					}

					if (_localstore->GetxPubKeyHDPM().empty() && haveRootkey) {
							HDKeychain xpubHDPM = rootkey.getChild("45'").getPublic();
							_localstore->SetxPubKeyHDPM(Base58::CheckEncode(xpubHDPM.extkey()));
					}

					// 44'/coinIndex'/account'/change/index
					if (_localstore->GetOwnerPubKey().empty() && haveRootkey) {
							bytes = rootkey.getChild("44'/0'/1'/0/0").pubkey();
							_localstore->SetOwnerPubKey(bytes.getHex());
					}

					if (_localstore->GetN() > 1 && !_localstore->GetxPubKey().empty()) {
							for (auto it = pubkeyRing.begin(); it != pubkeyRing.end(); ++it) {
									if (_localstore->GetxPubKey() == (*it).GetxPubKey() ||
											_localstore->GetxPubKeyHDPM() == (*it).GetxPubKey()) {
											pubkeyRing.erase(it);
											break;
									}
							}

							if (_localstore->DerivationStrategy() == "BIP44") {
									pubkeyRing.emplace_back(_localstore->GetRequestPubKey(), _localstore->GetxPubKey());
							} else {
									pubkeyRing.emplace_back(_localstore->GetRequestPubKey(), _localstore->GetxPubKeyHDPM());
							}
							_localstore->SetPublicKeyRing(pubkeyRing);
					}

					_localstore->Save();
			}

	uint512 Account::GetSeed(const std::string &payPasswd) const {
		uint512 seed;
		bytes_t bytes = AES::DecryptCCM(_localstore->GetSeed(), payPasswd);
		memcpy(seed.begin(), bytes.data(), MIN(bytes.size(), seed.size()));
		return seed;
	}

	bytes_t Account::GetETHSCPubKey() const {
		bytes_t pubkey;
		pubkey.setHex(_localstore->GetETHSCPrimaryPubKey());
		return pubkey;
	}

			bytes_t Account::GetRipplePubKey() const {
					bytes_t pubkey;
					pubkey.setHex(_localstore->GetRipplePrimaryPubKey());
					return pubkey;
	}

			bytes_t Account::GetSinglePrivateKey(const std::string &passwd) const {
			return AES::DecryptCCM(_localstore->GetSinglePrivateKey(), passwd);
	}

			bool Account::HasMnemonic() const {
		return !_localstore->GetMnemonic().empty();
	}

	bool Account::HasPassphrase() const {
		return _localstore->HasPassPhrase();
	}

	bool Account::VerifyPrivateKey(const std::string &mnemonic, const std::string &passphrase) const {
		if (!_localstore->Readonly() && _xpub != nullptr) {
			HDSeed seed(Mnemonic::DeriveSeed(mnemonic, passphrase).bytes());
			HDKeychain rootkey = HDKeychain(CTElastos, seed.getExtendedKey(CTElastos, true));

			HDKeychain xpub = rootkey.getChild("44'/0'/0'").getPublic();
			if (xpub.pubkey() == _xpub->pubkey())
				return true;
		}

		return false;
	}

	bool Account::VerifyPassPhrase(const std::string &passphrase, const std::string &payPasswd) const {
		if (!_localstore->Readonly() && _xpub != nullptr) {
							if (_localstore->GetxPubKeyBitcoin().empty()) {
									RegenerateKey(payPasswd);
									Init();
							}
			bytes_t bytes = AES::DecryptCCM(_localstore->GetMnemonic(), payPasswd);
			std::string mnemonic((char *) &bytes[0], bytes.size());

			uint512 seed = Mnemonic::DeriveSeed(mnemonic, passphrase);
			HDSeed hdseed(seed.bytes());
			HDKeychain rootkey(CTElastos, hdseed.getExtendedKey(CTElastos, true));

			HDKeychain xpub = rootkey.getChild("44'/0'/0'").getPublic();
			if (xpub.pubkey() != _xpub->pubkey())
				return false;

			return true;
		}

		return false;
	}

	bool Account::VerifyPayPassword(const std::string &payPasswd) const {
		if (!_localstore->Readonly()) {
							if (_localstore->GetxPubKeyBitcoin().empty()) {
									RegenerateKey(payPasswd);
									Init();
							}

							if (!_localstore->GetRequestPrivKey().empty())
									AES::DecryptCCM(_localstore->GetRequestPrivKey(), payPasswd);
							else if (!_localstore->GetSeed().empty()) {
									AES::DecryptCCM(_localstore->GetSeed(), payPasswd);
							} else if (!_localstore->GetMnemonic().empty()) {
									AES::DecryptCCM(_localstore->GetMnemonic(), payPasswd);
							} else if (!_localstore->GetSinglePrivateKey().empty()) {
									AES::DecryptCCM(_localstore->GetSinglePrivateKey(), payPasswd);
							} else if (!_localstore->GetxPrivKey().empty()) {
									AES::DecryptCCM(_localstore->GetxPrivKey(), payPasswd);
							}

			return true;
		}

		return false;
	}
*/
  save(): void {
    this._localstore.save();
  }

  remove() {
    this._localstore.remove();
  }

  /*
	std::string Account::GetDataPath() const {
		return _localstore->GetDataPath();
	}*/
}
