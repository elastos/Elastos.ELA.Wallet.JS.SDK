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
import { Lockable } from "../common/Lockable";
import { Log } from "../common/Log";
import {
  Config,
  CONFIG_MAINNET,
  CONFIG_PRVNET,
  CONFIG_REGTEST,
  CONFIG_TESTNET
} from "../Config";
import { WalletStorage } from "../persistence/WalletStorage";
import { json } from "../types";
import { HDKey } from "../walletcore/hdkey";
import { MasterWallet } from "./MasterWallet";

const MASTER_WALLET_STORE_FILE = "MasterWalletStore.json"; // TODO: move to store
const LOCAL_STORE_FILE = "LocalStore.json"; //  TODO: move to store

/* type MasterWalletMap = {
	[walletID: string]: MasterWallet
} */

type MasterWalletMap = Map<string, MasterWallet>;

export class MasterWalletManager {
  protected _lock: Lockable;
  protected _config: Config;
  protected _rootPath: string;
  protected _dataPath: string;
  protected _masterWalletMap: MasterWalletMap;
  private _storage: WalletStorage;

  constructor(
    storage: WalletStorage,
    /* const std::string &rootPath; */
    netType: string,
    config: json /* , dataPath: string */
  ) {
    // TODO _rootPath(rootPath),
    // TODO _dataPath(dataPath),
    this._lock = new Lockable();

    // TODO if (_dataPath.empty())
    // TODO 	_dataPath = _rootPath;

    // TODO ErrorChecker.CheckPathExists(_rootPath, false);
    // TODO ErrorChecker::CheckPathExists(_dataPath, false);

    // TODO Log.registerMultiLogger(_dataPath);

    // TODO Log.setLevel(spdlog:: level:: level_enum(SPVLOG_LEVEL));
    // TODO Log.info("spvsdk version {}", SPVSDK_VERSION_MESSAGE);

    this._storage = storage;

    if (
      netType != CONFIG_MAINNET &&
      netType != CONFIG_TESTNET &&
      netType != CONFIG_REGTEST &&
      netType != CONFIG_PRVNET
    ) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "invalid NetType"
      );
    }

    this._config = Config.newFromParams(netType, config);
    if (this._config.getNetType() == CONFIG_MAINNET) {
      /* TODO
      HDKeychain.setVersions(
        ExtKeyVersionMap["bip32"]["mainnet"]["prv"],
        ExtKeyVersionMap["bip32"]["mainnet"]["pub"]
      );
			*/
    } else {
      /* TODO
      HDKeychain.setVersions(
        ExtKeyVersionMap["bip32"]["testnet"]["prv"],
        ExtKeyVersionMap["bip32"]["testnet"]["pub"]
      );
			*/
      /* TODO- DONT DEPEND ON PATHS, USE WALLETSTORAGE METHODS ONLY
			this._dataPath = this._dataPath + "/" + this._config.getNetType();
			if (!boost:: filesystem:: exists(_dataPath))
				boost:: filesystem:: create_directory(_dataPath); */
    }

    this.loadMasterWalletID();
  }

  /*MasterWalletManager::~MasterWalletManager() {
		for (MasterWalletMap::iterator it = _masterWalletMap.begin(); it != _masterWalletMap.end();) {
			MasterWallet *masterWallet = static_cast<MasterWallet *>(it->second);
			if (masterWallet != nullptr) {
				std::string id = masterWallet->GetID();
				Log::info("closing master wallet (ID = {})...", id);
				masterWallet->CloseAllSubWallets();
				it = _masterWalletMap.erase(it);

				delete masterWallet;
				masterWallet = nullptr;
				Log::info("closed master wallet (ID = {})", id);
			} else {
				++it;
			}
		}
		delete _config;
		_config = nullptr;
		delete _lock;
		_lock = nullptr;
	}*/

  protected loadMasterWalletID() {
    /* 
			boost::filesystem::path rootpath(_dataPath);
			for (directory_iterator it(rootpath); it != directory_iterator(); ++it) {

				path temp = *it;
				if (!exists(temp) || !is_directory(temp)) {
					continue;
				}

				std::string masterWalletID = temp.filename().string();
				if (exists((*it) / LOCAL_STORE_FILE) || exists((*it) / MASTER_WALLET_STORE_FILE)) {
					_masterWalletMap[masterWalletID] = nullptr;
				}
			}
		*/
  }

  loadMasterWallet(storage: WalletStorage): MasterWallet {
    const masterWalletID = storage.masterWalletID;
    Log.info("loading wallet: {} ...", masterWalletID);

    let masterWallet: MasterWallet;
    try {
      masterWallet = MasterWallet.newFromStorage(storage, this._config);
      masterWallet.initSubWallets();
      this._masterWalletMap[masterWalletID] = masterWallet;
    } catch (error) {
      Log.error("load master wallet '{}' failed: {}", masterWalletID, error);
      masterWallet = null;
    }

    return masterWallet;
  }

  generateMnemonic(language: string, wordCount?: any): string {
    // ArgInfo("{}", GetFunName());
    // ArgInfo("language: {}", language);
    // ArgInfo("wordCount: {}", wordCount);
    const mnemonic: string = MasterWallet.generateMnemonic(language);
    // ArgInfo("r => *");
    return mnemonic;
  }

  createMasterWallet(
    // storage: WalletStorage,
    mnemonic: string,
    passphrase: string,
    passwd: string,
    singleAddress: boolean
  ): MasterWallet {
    const masterWalletID = this._storage.masterWalletID;

    // ArgInfo("{}", GetFunName());
    // ArgInfo("masterWalletID: {}", masterWalletID);
    // ArgInfo("mnemonic: *");
    // ArgInfo("passphrase: *, empty: {}", passphrase.empty());
    // ArgInfo("passwd: *");
    // ArgInfo("singleAddress: {}", singleAddress);

    // boost::mutex::scoped_lock scoped_lock(_lock->GetLock());

    // ErrorChecker.checkParamNotEmpty(masterWalletID, "Master wallet ID");
    // ErrorChecker.checkParamNotEmpty(mnemonic, "mnemonic");
    // ErrorChecker.checkPassword(passwd, "Pay");
    // ErrorChecker.checkPasswordWithNullLegal(passphrase, "Phrase");

    if (this._masterWalletMap.has(masterWalletID)) {
      // ArgInfo("r => already exist");
      return this._masterWalletMap[masterWalletID];
    }

    // ErrorChecker.checkLogic(!Mnemonic::Validate(mnemonic), Error.Code.Mnemonic, "Invalid mnemonic");

    const masterWallet = MasterWallet.newFromSingleAddress(
      this._storage,
      mnemonic,
      passphrase,
      passwd,
      singleAddress,
      this._config
      // _dataPath
    );

    // this.checkRedundant(masterWallet);
    this._masterWalletMap[masterWalletID] = masterWallet;

    // ArgInfo("r => create master wallet done");

    return masterWallet;
  }

  /*
				IMasterWallet *MasterWalletManager::CreateMasterWallet(const std::string &masterWalletID,
																															 const std::string &singlePrivateKey,
																															 const std::string &passwd) {
						ArgInfo("{}", GetFunName());
						ArgInfo("masterWalletID: {}", masterWalletID);
						ArgInfo("singlePrivateKey: *");
						ArgInfo("passwd: *");

						ErrorChecker::CheckParamNotEmpty(masterWalletID, "Master wallet ID");
						ErrorChecker::CheckPassword(passwd, "Pay");
						if (_masterWalletMap.find(masterWalletID) != _masterWalletMap.end()) {
								ArgInfo("r => already exist");
								return _masterWalletMap[masterWalletID];
						}

						MasterWallet *masterWallet = new MasterWallet(masterWalletID, singlePrivateKey, passwd, ConfigPtr(new Config(*_config)), _dataPath);
						checkRedundant(masterWallet);
						_masterWalletMap[masterWalletID] = masterWallet;

						ArgInfo("r => create master wallet done");
						return masterWallet;
				}

		IMasterWallet *MasterWalletManager::CreateMultiSignMasterWallet(const std::string &masterWalletID,
																		const nlohmann::json &cosigners,
																		uint32_t m,
																		bool singleAddress,
																		bool compatible,
																		time_t timestamp) {
			ArgInfo("{}", GetFunName());
			ArgInfo("masterWalletID: {}", masterWalletID);
			ArgInfo("cosigners: {}", cosigners.dump());
			ArgInfo("m: {}", m);
			ArgInfo("singleAddress: {}", singleAddress);
			ArgInfo("compatible: {}", compatible);
			ArgInfo("timestamp: {}", timestamp);

			boost::mutex::scoped_lock scoped_lock(_lock->GetLock());

			ErrorChecker::CheckParamNotEmpty(masterWalletID, "Master wallet ID");
			ErrorChecker::CheckParam(!cosigners.is_array(), Error::PubKeyFormat, "cosigners should be JOSN array");
			ErrorChecker::CheckParam(cosigners.size() < 2, Error::PubKeyFormat,
									 "cosigners should at least contain 2 elements");
			ErrorChecker::CheckParam(m < 1, Error::InvalidArgument, "Invalid m");

			std::vector<PublicKeyRing> pubKeyRing;
			bytes_t bytes;
			for (nlohmann::json::const_iterator it = cosigners.begin(); it != cosigners.end(); ++it) {
				ErrorChecker::CheckCondition(!(*it).is_string(), Error::Code::PubKeyFormat,
											 "cosigners should be string");
				std::string xpub = (*it).get<std::string>();
				for (int i = 0; i < pubKeyRing.size(); ++i) {
					if (pubKeyRing[i].GetxPubKey() == xpub) {
						ErrorChecker::ThrowParamException(Error::PubKeyFormat, "Contain same xpub");
					}
				}
				pubKeyRing.emplace_back("", xpub);
			}

			if (_masterWalletMap.find(masterWalletID) != _masterWalletMap.end()) {
				ArgInfo("r => already exist");
				return _masterWalletMap[masterWalletID];
			}

			MasterWallet *masterWallet = new MasterWallet(masterWalletID, pubKeyRing, m,
															ConfigPtr(new Config(*_config)), _dataPath,
															singleAddress, compatible);
			checkRedundant(masterWallet);
			_masterWalletMap[masterWalletID] = masterWallet;

			ArgInfo("r => create multi sign wallet");

			return masterWallet;
		}

		IMasterWallet *MasterWalletManager::CreateMultiSignMasterWallet(const std::string &masterWalletID,
																		const std::string &xprv,
																		const std::string &payPassword,
																		const nlohmann::json &cosigners,
																		uint32_t m,
																		bool singleAddress,
																		bool compatible,
																		time_t timestamp) {
			ArgInfo("{}", GetFunName());
			ArgInfo("masterWalletID: {}", masterWalletID);
			ArgInfo("xprv: *");
			ArgInfo("payPasswd: *");
			ArgInfo("cosigners: {}", cosigners.dump());
			ArgInfo("m: {}", m);
			ArgInfo("singleAddress: {}", singleAddress);
			ArgInfo("compatible: {}", compatible);
			ArgInfo("timestamp: {}", timestamp);

			boost::mutex::scoped_lock scoped_lock(_lock->GetLock());

			ErrorChecker::CheckParamNotEmpty(masterWalletID, "Master wallet ID");
			ErrorChecker::CheckPassword(payPassword, "Pay");
			ErrorChecker::CheckParam(!cosigners.is_array(), Error::PubKeyFormat, "cosigners should be JOSN array");
			ErrorChecker::CheckParam(cosigners.empty(), Error::PubKeyFormat,
									 "cosigners should at least contain 1 elements");
			ErrorChecker::CheckParam(m < 1, Error::InvalidArgument, "Invalid m");

			std::vector<PublicKeyRing> pubKeyRing;
			bytes_t bytes;
			for (nlohmann::json::const_iterator it = cosigners.begin(); it != cosigners.end(); ++it) {
				ErrorChecker::CheckCondition(!(*it).is_string(), Error::Code::PubKeyFormat,
											 "cosigners should be string");
				std::string xpub = (*it).get<std::string>();
				for (int i = 0; i < pubKeyRing.size(); ++i) {
					if (pubKeyRing[i].GetxPubKey() == xpub) {
						ErrorChecker::ThrowParamException(Error::PubKeyFormat, "Contain same xpub");
					}
				}
				pubKeyRing.emplace_back("", xpub);
			}

			if (_masterWalletMap.find(masterWalletID) != _masterWalletMap.end()) {
				ArgInfo("r => already exist");
				return _masterWalletMap[masterWalletID];
			}

			MasterWallet *masterWallet = new MasterWallet(masterWalletID, xprv, payPassword, pubKeyRing,
															m, ConfigPtr(new Config(*_config)), _dataPath,
															singleAddress,
															compatible);
			checkRedundant(masterWallet);
			_masterWalletMap[masterWalletID] = masterWallet;

			ArgInfo("r => create multi sign wallet");

			return masterWallet;
		}

		IMasterWallet *MasterWalletManager::CreateMultiSignMasterWallet(
			const std::string &masterWalletID,
			const std::string &mnemonic,
			const std::string &passphrase,
			const std::string &payPassword,
			const nlohmann::json &cosigners,
			uint32_t m,
			bool singleAddress,
			bool compatible,
			time_t timestamp) {

			ArgInfo("{}", GetFunName());
			ArgInfo("masterWalletID: {}", masterWalletID);
			ArgInfo("mnemonic: *");
			ArgInfo("passphrase: *, empty: {}", passphrase.empty());
			ArgInfo("payPasswd: *");
			ArgInfo("cosigners: {}", cosigners.dump());
			ArgInfo("m: {}", m);
			ArgInfo("singleAddress: {}", singleAddress);
			ArgInfo("compatible: {}", compatible);
			ArgInfo("timestamp: {}", timestamp);

			boost::mutex::scoped_lock scoped_lock(_lock->GetLock());

			ErrorChecker::CheckParamNotEmpty(masterWalletID, "Master wallet ID");
			ErrorChecker::CheckParamNotEmpty(mnemonic, "Mnemonic");
			ErrorChecker::CheckPassword(payPassword, "Pay");
			ErrorChecker::CheckPasswordWithNullLegal(passphrase, "Phrase");
			ErrorChecker::CheckParam(!cosigners.is_array(), Error::PubKeyFormat, "cosigners should be JOSN array");
			ErrorChecker::CheckParam(m < 1, Error::InvalidArgument, "Invalid m");

			if (_masterWalletMap.find(masterWalletID) != _masterWalletMap.end()) {
				ArgInfo("r => already exist");
				return _masterWalletMap[masterWalletID];
			}

			std::vector<PublicKeyRing> pubKeyRing;
			bytes_t bytes;
			for (nlohmann::json::const_iterator it = cosigners.begin(); it != cosigners.end(); ++it) {
				ErrorChecker::CheckCondition(!(*it).is_string() || !Base58::CheckDecode(*it, bytes),
											 Error::Code::PubKeyFormat, "cosigners format error");
				std::string xpub = (*it).get<std::string>();
				for (int i = 0; i < pubKeyRing.size(); ++i) {
					if (pubKeyRing[i].GetxPubKey() == xpub) {
						ErrorChecker::ThrowParamException(Error::PubKeyFormat, "Contain same xpub");
					}
				}
				pubKeyRing.emplace_back("", xpub);
			}

			MasterWallet *masterWallet = new MasterWallet(masterWalletID, mnemonic, passphrase, payPassword,
															pubKeyRing, m, ConfigPtr(new Config(*_config)), _dataPath,
															singleAddress, compatible);
			checkRedundant(masterWallet);
			_masterWalletMap[masterWalletID] = masterWallet;
			return masterWallet;
		}

		std::vector<IMasterWallet *> MasterWalletManager::GetAllMasterWallets() const {
			ArgInfo("{}", GetFunName());

			boost::mutex::scoped_lock scoped_lock(_lock->GetLock());

			std::vector<IMasterWallet *> result;
			for (MasterWalletMap::const_iterator it = _masterWalletMap.cbegin(); it != _masterWalletMap.cend(); ++it) {
				if (it->second) {
					result.push_back(it->second);
				} else {
					result.push_back(LoadMasterWallet(it->first));
				}
			}

			ArgInfo("r => all master wallet count: {}", result.size());

			return result;
		};

		void MasterWalletManager::DestroyWallet(const std::string &masterWalletID) {
			ArgInfo("{}", GetFunName());
			ArgInfo("masterWalletID: {}", masterWalletID);

			boost::mutex::scoped_lock scoped_lock(_lock->GetLock());

			if (_masterWalletMap.find(masterWalletID) != _masterWalletMap.end()) {
				MasterWallet *masterWallet = static_cast<MasterWallet *>(_masterWalletMap[masterWalletID]);
				if (masterWallet) {
					masterWallet->RemoveLocalStore();

					masterWallet->CloseAllSubWallets();
					_masterWalletMap.erase(masterWallet->GetWalletID());
					delete masterWallet;
				}
				masterWallet = nullptr;
			} else {
				Log::warn("Master wallet is not exist");
			}

			ArgInfo("r => {} done", GetFunName());
		}

		IMasterWallet *
		MasterWalletManager::ImportWalletWithKeystore(const std::string &masterWalletID,
														const nlohmann::json &keystoreContent,
														const std::string &backupPassword,
														const std::string &payPassword) {
			ArgInfo("{}", GetFunName());
			ArgInfo("masterWalletID: {}", masterWalletID);
			ArgInfo("keystore: *");
			ArgInfo("backupPasswd: *");
			ArgInfo("payPasswd: *");

			boost::mutex::scoped_lock scoped_lock(_lock->GetLock());

			ErrorChecker::CheckParamNotEmpty(masterWalletID, "Master wallet ID");
			ErrorChecker::CheckParam(!keystoreContent.is_object(), Error::KeyStore, "key store should be json object");
			ErrorChecker::CheckPassword(backupPassword, "Backup");

			if (_masterWalletMap.find(masterWalletID) != _masterWalletMap.end()) {
				ArgInfo("r => already exist");
				return _masterWalletMap[masterWalletID];
			}


			MasterWallet *masterWallet = new MasterWallet(masterWalletID, keystoreContent, backupPassword,
															payPassword, ConfigPtr(new Config(*_config)), _dataPath);
			checkRedundant(masterWallet);
			_masterWalletMap[masterWalletID] = masterWallet;
			masterWallet->InitSubWallets();

			ArgInfo("r => import with keystore");

			return masterWallet;
		}

		IMasterWallet *MasterWalletManager::ImportWalletWithMnemonic(const std::string &masterWalletID,
																	 const std::string &mnemonic,
																	 const std::string &phrasePassword,
																	 const std::string &payPassword,
																	 bool singleAddress, time_t timestamp) {
			ArgInfo("{}", GetFunName());
			ArgInfo("masterWalletID: {}", masterWalletID);
			ArgInfo("mnemonic: *");
			ArgInfo("passphrase: *, empty: {}", phrasePassword.empty());
			ArgInfo("payPasswd: *");
			ArgInfo("singleAddr: {}", singleAddress);
			ArgInfo("timestamp: {}", timestamp);

			boost::mutex::scoped_lock scoped_lock(_lock->GetLock());

			ErrorChecker::CheckParamNotEmpty(masterWalletID, "Master wallet ID");
			ErrorChecker::CheckParamNotEmpty(mnemonic, "Mnemonic");
			ErrorChecker::CheckPasswordWithNullLegal(phrasePassword, "Phrase");
			ErrorChecker::CheckPassword(payPassword, "Pay");

			if (_masterWalletMap.find(masterWalletID) != _masterWalletMap.end()) {
				ArgInfo("r => already exist");
				return _masterWalletMap[masterWalletID];
			}

			ErrorChecker::CheckLogic(!Mnemonic::Validate(mnemonic), Error::Mnemonic, "Invalid mnemonic");

			MasterWallet *masterWallet = new MasterWallet(masterWalletID, mnemonic, phrasePassword, payPassword,
															singleAddress, ConfigPtr(new Config(*_config)),
															_dataPath);
			checkRedundant(masterWallet);
			_masterWalletMap[masterWalletID] = masterWallet;

			ArgInfo("r => import with mnemonic");

			return masterWallet;
		}

//		IMasterWallet *MasterWalletManager::ImportReadonlyWallet(
//			const std::string &masterWalletID,
//			const nlohmann::json &walletJson) {
//			ArgInfo("{}", GetFunName());
//			ArgInfo("masterWalletID: {}", masterWalletID);
//			ArgInfo("walletJson: {}", walletJson.dump());
//
//			boost::mutex::scoped_lock scoped_lock(_lock->GetLock());
//
//			ErrorChecker::CheckParam(!walletJson.is_object(), Error::KeyStore, "wallet json should be json object");
//
//			if (_masterWalletMap.find(masterWalletID) != _masterWalletMap.end()) {
//				ArgInfo("r => already exist");
//				return _masterWalletMap[masterWalletID];
//			}
//
//			MasterWallet *masterWallet = new MasterWallet(masterWalletID, walletJson, ConfigPtr(new Config(*_config)),
//														  _dataPath);
//
//			checkRedundant(masterWallet);
//			_masterWalletMap[masterWalletID] = masterWallet;
//			masterWallet->InitSubWallets();
//			ArgInfo("r => import read-only");
//
//			return masterWallet;
//		}

		std::string MasterWalletManager::GetVersion() const {
			ArgInfo("{}", GetFunName());
			ArgInfo("r => {}", SPVSDK_VERSION_MESSAGE);
			return SPVSDK_VERSION_MESSAGE;
		}

		void MasterWalletManager::FlushData() {

			boost::mutex::scoped_lock scoped_lock(_lock->GetLock());

			std::for_each(_masterWalletMap.begin(), _masterWalletMap.end(),
							[](const MasterWalletMap::value_type &item) {
								if (item.second != nullptr) {
									MasterWallet *masterWallet = dynamic_cast<MasterWallet *>(item.second);
									masterWallet->FlushData();
								}
							});
		}

		void MasterWalletManager::SetLogLevel(const std::string &level) {
			ArgInfo("{}", GetFunName());
			ArgInfo("level: {}", level);

			if (level != "trace" &&
				level != "debug" &&
				level != "info" &&
				level != "warning" &&
				level != "error" &&
				level != "critical" &&
				level != "off") {
				ErrorChecker::ThrowParamException(Error::InvalidArgument, "invalid level");
			}

			Log::setLevel(spdlog::level::from_str(level));
		}

		std::vector<std::string> MasterWalletManager::GetAllMasterWalletID() const {
			ArgInfo("{}", GetFunName());

			boost::mutex::scoped_lock scoped_lock(_lock->GetLock());

			std::vector<std::string> result;
			std::for_each(_masterWalletMap.begin(), _masterWalletMap.end(),
							[&result](const MasterWalletMap::value_type &item) {
								result.push_back(item.first);
							});

			std::string chainID = "";
			for (size_t i = 0; i < result.size(); ++i)
				chainID += result[i] + ", ";

			ArgInfo("r => {}: {}", GetFunName(), chainID);

			return result;
		}

		bool MasterWalletManager::WalletLoaded(const std::string &masterWalletID) const {
			ArgInfo("{}", GetFunName());
			ArgInfo("masterWalletID: {}", masterWalletID);

			boost::mutex::scoped_lock scoped_lock(_lock->GetLock());

			if (_masterWalletMap.find(masterWalletID) == _masterWalletMap.end()) {
				Log::error("master wallet {} not found", masterWalletID);
				return false;
			}

			return _masterWalletMap[masterWalletID] != nullptr;
		}*/

  public getMasterWallet(masterWalletID: string): MasterWallet {
    //ArgInfo("{}", GetFunName());
    //ArgInfo("masterWalletID: {}", masterWalletID);

    if (
      this._masterWalletMap.has(masterWalletID) &&
      this._masterWalletMap[masterWalletID] != null
    ) {
      return this._masterWalletMap[masterWalletID];
    }

    return this.loadMasterWallet(masterWalletID);
  }

  /*void MasterWalletManager::checkRedundant(IMasterWallet *wallet) const {

		MasterWallet *masterWallet = static_cast<MasterWallet *>(wallet);

		bool hasRedundant = false;
		std::for_each(_masterWalletMap.begin(), _masterWalletMap.end(),
						[masterWallet, &hasRedundant](const MasterWalletMap::value_type &item) {
							if (item.second != nullptr) {
								const MasterWallet *createdWallet = static_cast<const MasterWallet *>(item.second);
								if (!hasRedundant)
									hasRedundant = masterWallet->IsEqual(*createdWallet);
							}
						});

		if (hasRedundant) {
			Log::info("{} Destroying redundant wallet", masterWallet->GetWalletID());

			masterWallet->CloseAllSubWallets();
							Log::info("Clearing local", masterWallet->GetID());
							masterWallet->RemoveLocalStore();

			delete masterWallet;
			masterWallet = nullptr;
		}

		ErrorChecker::CheckCondition(hasRedundant, Error::CreateMasterWalletError,
									 "Master wallet already exist.");
	} */
}
