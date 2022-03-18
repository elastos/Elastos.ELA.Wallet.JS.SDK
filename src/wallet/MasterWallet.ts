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

import { Account } from "../account/Account";
import { Config, ChainConfig } from "../config";
import { WalletStorage } from "../persistence/WalletStorage";
import { CoinInfo } from "../walletcore/CoinInfo";
import { SubWallet } from "./SubWallet";
import { ISubWallet } from "./ISubWallet";
import { Error, ErrorChecker } from "../common/ErrorChecker";
import { Log } from "../common/Log";
import { Mnemonic } from "../walletcore/mnemonic";

type WalletMap = {
  [id: string]: SubWallet;
};

export class MasterWallet {
  protected _createdWallets: WalletMap;
  protected _account: Account;
  protected _id: string;
  protected _config: Config;

  private constructor() {}

  public static newFromStorage(
    storage: WalletStorage,
    config: Config
    // dataPath: string
  ) {
    let masterWallet = new MasterWallet();
    masterWallet._id = storage.masterWalletID;
    masterWallet._config = config;
    masterWallet._account = Account.newFromAccount(storage);
    // this.setupNetworkParameters();
    return masterWallet;
  }

  public static newFromMnemonic(
    storage: WalletStorage,
    mnemonic: string,
    passphrase: string,
    passwd: string,
    singleAddress: boolean,
    config: Config
    // dataPath: string
  ) {
    let masterWallet = new MasterWallet();
    masterWallet._id = storage.masterWalletID;
    masterWallet._config = config;

    masterWallet._account = Account.newFromMnemonicAndPassphrase(
      storage, // original code: `${dataPath}/${this._id}`
      mnemonic,
      passphrase,
      passwd,
      singleAddress
    );

    masterWallet._account.save();
    // this.setupNetworkParameters();
    return masterWallet;
  }

  /*

			MasterWallet::MasterWallet(const std::string &id,
																 const std::string &singlePrivateKey,
																 const std::string &passwd,
																 const ConfigPtr &config,
																 const std::string &dataPath) :
																 _id(id),
																 _config(config) {
					_account = AccountPtr(new Account(dataPath + "/" + _id, singlePrivateKey, passwd));
					_account->Save();
					SetupNetworkParameters();
	}

	MasterWallet::MasterWallet(const std::string &id,
								 const nlohmann::json &keystoreContent,
								 const std::string &backupPassword,
								 const std::string &payPasswd,
								 const ConfigPtr &config,
								 const std::string &dataPath) :
			_id(id),
			_config(config) {

		KeyStore keystore;
		keystore.Import(keystoreContent, backupPassword);

		_account = AccountPtr(new Account(dataPath + "/" + _id, keystore, payPasswd));
		_account->Save();
					SetupNetworkParameters();
	}

	MasterWallet::MasterWallet(const std::string &id,
								 const std::vector<PublicKeyRing> &pubKeyRings,
								 uint32_t m,
								 const ConfigPtr &config,
								 const std::string &dataPath,
								 bool singleAddress,
								 bool compatible) :
			_id(id),
			_config(config) {
		ErrorChecker::CheckParam(pubKeyRings.size() < m, Error::InvalidArgument, "Invalid M");

		_account = AccountPtr(new Account(dataPath + "/" + _id, pubKeyRings, m, singleAddress, compatible));
		_account->Save();
					SetupNetworkParameters();
	}

	MasterWallet::MasterWallet(const std::string &id,
								 const std::string &xprv,
								 const std::string &payPassword,
								 const std::vector<PublicKeyRing> &cosigners,
								 uint32_t m,
								 const ConfigPtr &config,
								 const std::string &dataPath,
								 bool singleAddress,
								 bool compatible) :
			_id(id),
			_config(config) {

		ErrorChecker::CheckParam(cosigners.size() + 1 < m, Error::InvalidArgument, "Invalid M");

		_account = AccountPtr(new Account(dataPath + "/" + _id, xprv, payPassword, cosigners, m, singleAddress, compatible));
		_account->Save();
					SetupNetworkParameters();
	}

	MasterWallet::MasterWallet(const std::string &id,
								 const std::string &mnemonic,
								 const std::string &passphrase,
								 const std::string &payPasswd,
								 const std::vector<PublicKeyRing> &cosigners,
								 uint32_t m,
								 const ConfigPtr &config,
								 const std::string &dataPath,
								 bool singleAddress,
								 bool compatible) :
			_id(id),
			_config(config) {

		ErrorChecker::CheckParam(cosigners.size() + 1 < m, Error::InvalidArgument, "Invalid M");

		_account = AccountPtr(new Account(dataPath + "/" + _id, mnemonic, passphrase, payPasswd, cosigners, m, singleAddress, compatible));
		_account->Save();
					SetupNetworkParameters();
	} */

  destroy() {}

  public static generateMnemonic(language: string, wordCount?: any): string {
    const mnemonicObj = Mnemonic.getInstance(language);
    const mnemonic = mnemonicObj.generate();
    return mnemonic;
  }

  removeLocalStore() {
    this._account.remove();
  }

  public getID(): string {
    return this._id;
  }

  public getWalletID(): string {
    return this._id;
  }

  public getAllSubWallets(): SubWallet[] {
    //ArgInfo("{} {}", _id, GetFunName());

    let subWallets: SubWallet[] = Object.values(this._createdWallets);

    let result;
    for (let i = 0; i < subWallets.length; ++i)
      result += subWallets[i].getChainID() + ",";

    //ArgInfo("r => {}", result);
    return subWallets;
  }

  public getSubWallet(chainID: string): SubWallet {
    //ArgInfo("{} {}", _id, GetFunName());
    //ArgInfo("chainID: {}", chainID);

    if (chainID in this._createdWallets) {
      return this._createdWallets[chainID];
    }

    return null;
  }

  public createSubWallet(chainID: string) {
    //ArgInfo("{} {}", _id, GetFunName());
    //ArgInfo("chainID: {}", chainID);

    ErrorChecker.checkParamNotEmpty(chainID, "Chain ID");
    ErrorChecker.checkParam(
      chainID.length > 128,
      Error.Code.InvalidArgument,
      "Chain ID sould less than 128"
    );

    if (this._createdWallets[chainID]) {
      const subWallet = this._createdWallets[chainID];
      // ArgInfo("r => already created");
      return subWallet;
    }

    const chainConfig = this._config.getChainConfig(chainID);
    ErrorChecker.checkLogic(
      chainConfig == null,
      Error.Code.InvalidArgument,
      "Unsupport chain ID: " + chainID
    );

    const info = new CoinInfo();

    info.setChainID(chainID);

    let subWallet = this.subWalletFactoryMethod(
      info,
      chainConfig,
      this,
      this._config.getNetType()
    );
    this._createdWallets[chainID] = subWallet;
    this._account.addSubWalletInfoList(info);
    this._account.save();

    return subWallet;
  }

  /*bool MasterWallet::VerifyPrivateKey(const std::string &mnemonic, const std::string &passphrase) const {
		ArgInfo("{} {}", _id, GetFunName());
		ArgInfo("mnemonic: *");
		ArgInfo("passphrase: *");
		bool r = _account->VerifyPrivateKey(mnemonic, passphrase);
		ArgInfo("r => {}", r);
		return r;
	}

	bool MasterWallet::VerifyPassPhrase(const std::string &passphrase, const std::string &payPasswd) const {
		ArgInfo("{} {}", _id, GetFunName());
		ArgInfo("passphrase: *");
		ArgInfo("payPasswd: *");
		bool r = _account->VerifyPassPhrase(passphrase, payPasswd);
		ArgInfo("r => {}", r);
		return r;
	}

	bool MasterWallet::VerifyPayPassword(const std::string &payPasswd) const {
		ArgInfo("{} {}", _id, GetFunName());
		ArgInfo("payPasswd: *");
		bool r = _account->VerifyPayPassword(payPasswd);
		ArgInfo("r => {}", r);
		return r;
	}

	void MasterWallet::CloseAllSubWallets() {
		for (WalletMap::iterator it = _createdWallets.begin(); it != _createdWallets.end(); ) {
			ISubWallet *subWallet = it->second;
			std::string id = _id + ":" + subWallet->GetChainID();
			Log::info("{} closing...", id);

			it = _createdWallets.erase(it);

			delete subWallet;
			subWallet = nullptr;
			Log::info("{} closed", id);
		}
	}

			void MasterWallet::SetupNetworkParameters() {
					const std::map<std::string, ChainConfigPtr> configs = _config->GetConfigs();

					for (std::map<std::string, ChainConfigPtr>::const_iterator it = configs.begin(); it != configs.end(); ++it)
							if (!it->second->Name().empty())
									InsertEthereumNetwork(it->second->Name().c_str(), it->second->ChainID(), it->second->NetworkID());
			}

	void MasterWallet::DestroyWallet(const std::string &chainID) {
		ArgInfo("{} {}", _id, GetFunName());
		ArgInfo("chainID: {}", chainID);

		if (_createdWallets.find(chainID) == _createdWallets.end())
			ErrorChecker::ThrowParamException(Error::InvalidArgument, "chainID not found");

		ISubWallet *subWallet = _createdWallets[chainID];
		_account->RemoveSubWalletInfo(subWallet->GetChainID());
		_account->Save();

		_createdWallets.erase(chainID);

		delete subWallet;
		subWallet = nullptr;

		ArgInfo("r => {} {} done", _id, GetFunName());
	}

	nlohmann::json MasterWallet::GetPubKeyInfo() const {
		ArgInfo("{} {}", _id, GetFunName());

		nlohmann::json j = _account->GetPubKeyInfo();

		ArgInfo("r => {}", j.dump());
		return j;
	}

#if 0
	nlohmann::json MasterWallet::ExportReadonlyWallet() const {
		ArgInfo("{} {}", _id, GetFunName());

		nlohmann::json j = _account->ExportReadonlyWallet();

		ArgInfo("r => {}", j.dump());
		return j;
	}
#endif

	nlohmann::json MasterWallet::ExportKeystore(const std::string &backupPassword, const std::string &payPassword) const {
		ArgInfo("{} {}", _id, GetFunName());
		ArgInfo("backupPassword: *");
		ArgInfo("payPassword: *");
		ErrorChecker::CheckPassword(backupPassword, "Backup");

		std::vector<CoinInfoPtr> coinInfo = _account->SubWalletInfoList();
		_account->SetSubWalletInfoList(coinInfo);
		_account->Save();

		KeyStore keyStore = _account->ExportKeystore(payPassword);
		nlohmann::json j = keyStore.Export(backupPassword, true);

		ArgInfo("r => *");
		return j;
	}

	std::string MasterWallet::ExportMnemonic(const std::string &payPassword) const {
		ArgInfo("{} {}", _id, GetFunName());
		ArgInfo("payPassword: *");

		std::string mnemonic = _account->ExportMnemonic(payPassword);

		ArgInfo("r => *");
		return mnemonic;
	}

	std::string MasterWallet::ExportPrivateKey(const std::string &payPasswd) const {
		ArgInfo("{} {}", _id, GetFunName());
		ArgInfo("payPsswd: *");

		ErrorChecker::CheckLogic(_account->Readonly(), Error::UnsupportOperation,
								 "Unsupport operation: read-only wallet do not contain xprv");

		std::string xprv = _account->GetxPrvKeyString(payPasswd);

		ArgInfo("r => *");
		return xprv;
	}

	std::string MasterWallet::ExportMasterPublicKey() const {
		ArgInfo("{} {}", _id, GetFunName());

		std::string mpk = _account->MasterPubKeyString();

		ArgInfo("r => {}", mpk);
		return mpk;
	}*/

  initSubWallets() {
    const info: CoinInfo[] = this._account.subWalletInfoList();
    for (let i = 0; i < info.length; ++i) {
      let chainConfig: ChainConfig = this._config.getChainConfig(
        info[i].getChainID()
      );
      if (chainConfig == null) {
        Log.error("Can not find config of chain ID: " + info[i].getChainID());
        continue;
      }

      let subWallet: ISubWallet = this.subWalletFactoryMethod(
        info[i],
        chainConfig,
        this,
        this._config.getNetType()
      );

      ErrorChecker.checkCondition(
        subWallet == null,
        Error.Code.CreateSubWalletError,
        "Recover sub wallet error"
      );
      this._createdWallets[subWallet.getChainID()] = subWallet;
    }
  }

  /*
	ISubWallet *MasterWallet::SubWalletFactoryMethod(const CoinInfoPtr &info, const ChainConfigPtr &config,
													MasterWallet *parent, const std::string &netType) {

		if (info->GetChainID() == "ELA") {
			return new MainchainSubWallet(info, config, parent, netType);
		} else if (info->GetChainID() == "IDChain") {
							return new IDChainSubWallet(info, config, parent, netType);
					} else if (info->GetChainID() == "BTC") {
				return new BTCSubWallet(info, config, parent, netType);
		} else if (info->GetChainID().find("ETH") !=  std::string::npos) {
							return new EthSidechainSubWallet(info, config, parent, netType);
//            } else if (info->GetChainID() == "XRP") {
//			    return new RippleSubWallet(info, config, parent, netType);
		} else {
			ErrorChecker::ThrowLogicException(Error::InvalidChainID, "Invalid chain ID: " + info->GetChainID());
		}

		return nullptr;
	}

	std::string MasterWallet::GetDataPath() const {
		return _account->GetDataPath();
	}*/

  public getAccount(): Account {
    return this._account;
  }

  /*	bool MasterWallet::IsAddressValid(const std::string &address) const {
			ArgInfo("{} {}", _id, GetFunName());
			ArgInfo("addr: {}", address);

			bool valid = Address(address).Valid();
			if (!valid) {
				valid = addressValidateString(address.c_str()) == ETHEREUM_BOOLEAN_TRUE;
			}

			ArgInfo("r => {}", valid);
			return valid;
		}

		bool MasterWallet::IsSubWalletAddressValid(const std::string &chainID, const std::string &address) const {
			ArgInfo("{} {}", _id, GetFunName());
			ArgInfo("chainID: {}", chainID);
			ArgInfo("address: {}", address);

						bool valid = false;
						if (chainID == CHAINID_MAINCHAIN || chainID == CHAINID_IDCHAIN || chainID == CHAINID_TOKENCHAIN) {
								valid = Address(address).Valid();
						} else if (chainID == "BTC") {
								BRAddressParams addrParams;
								if (_config->GetNetType() == CONFIG_MAINNET) {
										addrParams = BITCOIN_ADDRESS_PARAMS;
								} else {
										addrParams = BITCOIN_TEST_ADDRESS_PARAMS;
								}
								valid = BRAddressIsValid(addrParams, address.c_str());
						} else if (chainID.find("ETH") != std::string::npos) {
								valid = addressValidateString(address.c_str()) == ETHEREUM_BOOLEAN_TRUE;
						}

			ArgInfo("r => {}", valid);
			return valid;
		}

		std::vector<std::string> MasterWallet::GetSupportedChains() const {
			ArgInfo("{} {}", _id, GetFunName());

			std::vector<std::string> chainIDs = _config->GetAllChainIDs();

			std::string result;
			for (size_t i = 0; i < chainIDs.size(); ++i) {
				result += chainIDs[i] + ", ";
			}

			ArgInfo("r => {}", result);
			return chainIDs;
		}

		void MasterWallet::ChangePassword(const std::string &oldPassword, const std::string &newPassword) {
			ArgInfo("{} {}", _id, GetFunName());
			ArgInfo("old: *");
			ArgInfo("new: *");

			_account->ChangePassword(oldPassword, newPassword);
		}

		void MasterWallet::ResetPassword(const std::string &mnemonic, const std::string &passphrase,
										 const std::string &newPassword) {
			ArgInfo("{} {}", _id, GetFunName());
			ArgInfo("m: *");
			ArgInfo("passphrase: *");
			ArgInfo("passwd: *");

			_account->ResetPassword(mnemonic, passphrase, newPassword);

			ArgInfo("r => ");
		}

		nlohmann::json MasterWallet::GetBasicInfo() const {
			ArgInfo("{} {}", _id, GetFunName());

			nlohmann::json info = _account->GetBasicInfo();

			ArgInfo("r => {}", info.dump());
			return info;
		}

		bool MasterWallet::IsEqual(const MasterWallet &wallet) const {
			return _account->Equal(wallet._account);
		}

		void MasterWallet::FlushData() {
			for (WalletMap::const_iterator it = _createdWallets.cbegin(); it != _createdWallets.cend(); ++it) {
				SubWallet *subWallet = dynamic_cast<SubWallet*>(it->second);
				if (subWallet)
					subWallet->FlushData();
			}
		}

		ChainConfigPtr MasterWallet::GetChainConfig(const std::string &chainID) const {
			return _config->GetChainConfig(chainID);
		} */
}
