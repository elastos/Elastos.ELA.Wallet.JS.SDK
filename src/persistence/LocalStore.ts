// Copyright (c) 2012-2018 The Elastos Open Source Project

import { Error, ErrorChecker } from "../common/ErrorChecker";
import { json, JSONArray } from "../types";
import { AESDecrypt, AESEncrypt } from "../walletcore/aes";
import { CoinInfo } from "../walletcore/CoinInfo";
import { PublicKeyRing } from "../walletcore/publickeyring";
import { WalletStorage } from "./WalletStorage";

const MASTER_WALLET_STORE_FILE = "MasterWalletStore.json";
const LOCAL_STORE_FILE = "LocalStore.json";

export class LocalStore {
  // encrypted
  private _xPrivKey: string;
  private _requestPrivKey: string;
  private _mnemonic: string;
  // only old version keystore and localstore of spvsdk contain this. will remove later
  // std::string _passphrase __attribute__((deprecated));
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
  //private _path: string; // rootPath + masterWalletID
  private _walletStorage: WalletStorage;

  private toJson(): json {
    let j: json = {};

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

  private fromJson(j: json) {
    try {
      //if (j.find("publicKeyRing") != j.end()) {
      // new version of localstore
      this._xPrivKey = j["xPrivKey"] as string;
      this._mnemonic = j["mnemonic"] as string;
      this._xPubKey = j["xPubKey"] as string;
      this._requestPrivKey = j["requestPrivKey"] as string;
      this._requestPubKey = j["requestPubKey"] as string;
      this._publicKeyRing = (j["publicKeyRing"] as JSONArray).map((pkr) =>
        new PublicKeyRing().fromJson(pkr as json)
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

      this._subWalletsInfoList = (j["coinInfo"] as JSONArray).map((j) =>
        new CoinInfo().fromJson(j as json)
      );
      /* } else {
					// old version of localstore
					bytes_t bytes;
				nlohmann::json mpk = j["MasterPubKey"];

				_derivationStrategy = "BIP44";
				_account = 0;
				_xPrivKey.clear();
				_requestPubKey.clear();
				_requestPrivKey.clear();
				_ownerPubKey.clear();
				_xPubKey.clear();
				_xPubKeyHDPM.clear();
				_seed.clear();
				_ethscPrimaryPubKey.clear();
				_ripplePrimaryPubKey.clear();

				if (mpk.is_object()) {
					bytes.setHex(mpk["ELA"]);
					if (!bytes.isZero()) {
							ByteStream stream(bytes);
						stream.Skip(4);
							bytes_t pubKey, chainCode;
						stream.ReadBytes(chainCode, 32);
						stream.ReadBytes(pubKey, 33);

						bytes = HDKeychain(CTElastos, pubKey, chainCode).extkey();
						_xPubKey = Base58:: CheckEncode(bytes);
					}
				}

				nlohmann::json jaccount = j["Account"];

				if (j.find("SubWallets") != j.end()) {
					_subWalletsInfoList = j["SubWallets"].get < std:: vector < CoinInfoPtr >> ();
				}


				if (jaccount.find("CoSigners") != jaccount.end()) {
					// 1. multi sign
					ErrorChecker:: ThrowLogicException(Error:: InvalidLocalStore, "Localstore too old, re-import please");
				} else {
					// 2. standard hd
					_readonly = false;
					_mnemonic = jaccount["Mnemonic"].get < std:: string > ();
					_passphrase = jaccount["PhrasePassword"].get < std:: string > ();

					bytes.setBase64(_passphrase);
					if (bytes.size() <= 8) {
						_mnemonicHasPassphrase = false;
						_passphrase.clear();
					} else {
						_mnemonicHasPassphrase = true;
					}

					_m = _n = 1;
					_requestPubKey = jaccount["PublicKey"].get < std:: string > ();
					if (!_xPubKey.empty())
						_publicKeyRing.emplace_back(_requestPubKey, _xPubKey);

					nlohmann::json votePubkey = j["VotePublicKey"];
					if (votePubkey.is_object() && votePubkey["ELA"].get < std:: string > () != "") {
						_ownerPubKey = votePubkey["ELA"].get < std:: string > ();
					}
					_singleAddress = j["IsSingleAddress"].get<bool>();
				}
			} */
    } catch (e) {
      ErrorChecker.throwLogicException(
        Error.Code.InvalidLocalStore,
        "Invalid localstore: " + e
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

  constructor(walletStorage: WalletStorage) {
    this._walletStorage = walletStorage;
    this._account = 0;
    //_path(path),
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

  public load(id: string): boolean {
    let j = this._walletStorage.loadStore(id);

    ErrorChecker.checkLogic(
      !j || j === {},
      Error.Code.InvalidLocalStore,
      "local store file is empty"
    );

    this.fromJson(j);

    return true;
  }

  public save() {
    this._walletStorage.saveStore(this.toJson());
  }

  remove() {
    /*
		boost:: filesystem::path path(_path);
		if (boost:: filesystem:: exists(path))
      boost:: filesystem:: remove_all(path);
    */
  }

  getDataPath(): string {
    return this._walletStorage.currentMasterWalletID;
  }

  /*
	void LocalStore:: SaveTo(const std:: string & path) {
		_path = path;
		Save();
	}*/

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
