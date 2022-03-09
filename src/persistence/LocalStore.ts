// Copyright (c) 2012-2018 The Elastos Open Source Project

import { Error, ErrorChecker } from "../common/ErrorChecker";
import { json, JSONArray } from "../types";
import { CoinInfo } from "../walletcore/CoinInfo";
import { WalletStorage } from "./WalletStorage";

const MASTER_WALLET_STORE_FILE = "MasterWalletStore.json";
const LOCAL_STORE_FILE = "LocalStore.json";

export class LocalStore {
	// encrypted
	private _xPrivKey: string;
	private _requestPrivKey: string;
	private _mnemonic: string;
	// only old version keystore and localstore of spvsdk contain this. will remove later
	//			std::string _passphrase __attribute__((deprecated));
	private _passphrase: string;
	private _singlePrivateKey: string;
	private _seed: string;

	// plain text
	private _xPubKey: string;
	private _xPubKeyHDPM: string; // BIP45 / BIP44 (compatible with web wallet)
	private _requestPubKey: string;
	private _ownerPubKey: string;
	private _derivationStrategy: string;

	// TODO private _publicKeyRing: PublicKeyRing[];

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
	//private _ripplePrimaryPubKey: string;

	// for btc
	//private  _xPubKeyBitcoin: string;

	private _subWalletsInfoList: CoinInfo[];
	//private _path: string; // rootPath + masterWalletID
	private _walletStorage: WalletStorage;

	private toJson(): json {
		let j: json = {};

		j["xPrivKey"] = this._xPrivKey;
		j["xPubKey"] = this._xPubKey;
		j["xPubKeyHDPM"] = this._xPubKeyHDPM;
		j["requestPrivKey"] = this._requestPrivKey;
		j["requestPubKey"] = this._requestPubKey;
		// TODO j["publicKeyRing"] = this._publicKeyRing;
		j["m"] = this._m;
		j["n"] = this._n;
		j["mnemonicHasPassphrase"] = this._mnemonicHasPassphrase;
		j["derivationStrategy"] = this._derivationStrategy;
		j["account"] = this._account;
		j["mnemonic"] = this._mnemonic;
		j["passphrase"] = this._passphrase;
		j["ownerPubKey"] = this._ownerPubKey;
		j["singleAddress"] = this._singleAddress;
		j["readonly"] = this._readonly;
		j["coinInfo"] = this._subWalletsInfoList.map(c => c.toJson());
		j["seed"] = this._seed;
		j["ethscPrimaryPubKey"] = this._ethscPrimaryPubKey;
		// TODO j["ripplePrimaryPubKey"] = this._ripplePrimaryPubKey;
		// TODO j["xPubKeyBitcoin"] = this._xPubKeyBitcoin;
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
			// TODO this._publicKeyRing = j["publicKeyRing"].get < std:: vector < PublicKeyRing >> ();
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
					if (this._ethscPrimaryPubKey[i] != '0') {
						isEmpty = false;
						break;
					}
				}
				if (isEmpty || this._ethscPrimaryPubKey[0] != '0' || this._ethscPrimaryPubKey[1] != '4')
					this._ethscPrimaryPubKey = null;
			} else {
				this._ethscPrimaryPubKey = null;
			}

			/* TODO if ("ripplePrimaryPubKey" in j) {
				this._ripplePrimaryPubKey = j["ripplePrimaryPubKey"].get < std:: string > ();
			} else {
				this._ripplePrimaryPubKey.clear();
			} */

			// support btc
			/* TODO if ("xPubKeyBitcoin" in j) {
				this._xPubKeyBitcoin = j["xPubKeyBitcoin"].get < std:: string > ();
			} else {
				this._xPubKeyBitcoin.clear();
			} */

			this._subWalletsInfoList = (j["coinInfo"] as JSONArray).map(j => new CoinInfo().fromJson(j as json));
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
			ErrorChecker.ThrowLogicException(Error.Code.InvalidLocalStore, "Invalid localstore: " + e);
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

	/* void LocalStore:: ChangePasswd(const std:: string & oldPasswd, const std:: string & newPasswd) {
				bytes_t bytes = AES:: DecryptCCM(_mnemonic, oldPasswd);
		_mnemonic = AES:: EncryptCCM(bytes, newPasswd);

		bytes = AES:: DecryptCCM(_xPrivKey, oldPasswd);
		_xPrivKey = AES:: EncryptCCM(bytes, newPasswd);

		bytes = AES:: DecryptCCM(_requestPrivKey, oldPasswd);
		_requestPrivKey = AES:: EncryptCCM(bytes, newPasswd);

		bytes = AES:: DecryptCCM(_seed, oldPasswd);
		_seed = AES:: EncryptCCM(bytes, newPasswd);

		bytes = AES:: DecryptCCM(_singlePrivateKey, oldPasswd);
		_singlePrivateKey = AES:: EncryptCCM(bytes, newPasswd);

		bytes.clean();
	} */

	public load(): boolean {
		/* TODO fs::path filepath = _path;
		filepath /= LOCAL_STORE_FILE;
		if (!fs:: exists(filepath)) {
			filepath = _path;
			filepath /= MASTER_WALLET_STORE_FILE;
			if (!fs:: exists(filepath)) {
				ErrorChecker:: ThrowLogicException(Error:: MasterWalletNotExist, "master wallet " +
					filepath.parent_path().filename().string() + " not exist");
			}
		}

		std::ifstream is(filepath.string());
		nlohmann::json j;
		is >> j;

		ErrorChecker:: CheckLogic(j.is_null() || j.empty(), Error:: InvalidLocalStore, "local store file is empty");

		FromJson(j);
 */
		return true;
	}

	public save() {

		/* TODO nlohmann::json j = ToJson();

		if (!j.is_null() && !j.empty() && !_path.empty()) {
			boost:: filesystem::path path = _path;
			if (!boost:: filesystem:: exists(path))
			boost:: filesystem:: create_directory(path);

			path /= LOCAL_STORE_FILE;
			std::ofstream o(path.string());
			o << j;
			o.flush();
		} */
	}

	/* void LocalStore:: Remove() {
		boost:: filesystem::path path(_path);
		if (boost:: filesystem:: exists(path))
		boost:: filesystem:: remove_all(path);
	}

	const std:: string & LocalStore:: GetDataPath() const {
		return _path;
			}

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

	/* const std:: vector<PublicKeyRing> & LocalStore:: GetPublicKeyRing() const {
		return this._publicKeyRing;
				}

				public AddPublicKeyRing(const PublicKeyRing & ring) {
	this._publicKeyRing.push_back(ring);
}

		public SetPublicKeyRing(const std:: vector<PublicKeyRing> & pubKeyRing) {
	this._publicKeyRing = pubKeyRing;
} */

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

	/*void LocalStore:: RemoveSubWalletInfo(const std:: string & chainID) {
		for (std:: vector<CoinInfoPtr>:: iterator it = _subWalletsInfoList.begin(); it != _subWalletsInfoList.end(); ++it) {
			if (chainID == (* it) -> GetChainID()) {
				_subWalletsInfoList.erase(it);
				break;
			}
		}
	}

	void LocalStore:: SetSubWalletInfoList(const std:: vector<CoinInfoPtr> & infoList) {
		_subWalletsInfoList = infoList;
	}

	void LocalStore:: ClearSubWalletInfoList() {
		_subWalletsInfoList.clear();
	}

	void LocalStore:: SetSeed(const std:: string & seed) {
		_seed = seed;
	}

	const std:: string & LocalStore:: GetSeed() const {
		return _seed;
			}

	void LocalStore:: SetETHSCPrimaryPubKey(const std:: string & pubkey) {
		_ethscPrimaryPubKey = pubkey;
	}

	const std:: string & LocalStore:: GetETHSCPrimaryPubKey() const {
		return _ethscPrimaryPubKey;
			}

	void LocalStore:: SetxPubKeyBitcoin(const std:: string & xpub) {
		_xPubKeyBitcoin = xpub;
	}

	const std:: string & LocalStore:: GetxPubKeyBitcoin() const {
		return _xPubKeyBitcoin;
					}

	void LocalStore:: SetSinglePrivateKey(const std:: string & prvkey) {
		_singlePrivateKey = prvkey;
	}

	const std:: string & LocalStore:: GetSinglePrivateKey() const {
		return _singlePrivateKey;
			}

	void LocalStore:: SetRipplePrimaryPubKey(const std:: string & pubkey) {
		_ripplePrimaryPubKey = pubkey;
	}

	const std:: string & LocalStore:: GetRipplePrimaryPubKey() const {
		return _ripplePrimaryPubKey;
			}

		} */
}
