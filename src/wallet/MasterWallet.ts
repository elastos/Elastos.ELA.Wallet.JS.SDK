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
import {
  Account,
  AccountBasicInfo,
  AccountPubKeyInfo
} from "../account/Account";
import { Error, ErrorChecker } from "../common/ErrorChecker";
import { Log } from "../common/Log";
import { ChainConfig, Config, ConfigMap, CONFIG_MAINNET } from "../config";
import { WalletStorage } from "../persistence/WalletStorage";
import { JSONObject, uint32_t } from "../types";
import {
  CHAINID_IDCHAIN,
  CHAINID_MAINCHAIN,
  CHAINID_TOKENCHAIN
} from "../wallet/WalletCommon";
import { Address } from "../walletcore/Address";
import { CoinInfo } from "../walletcore/CoinInfo";
import { Mnemonic } from "../walletcore/mnemonic";
import { PublicKeyRing } from "../walletcore/publickeyring";
// import { EthSidechainSubWallet } from "./EthSidechainSubWallet";
import { EthereumNetworks } from "./EthereumNetwork";
import { MainchainSubWallet } from "./MainchainSubWallet";
import { SubWallet } from "./SubWallet";

type WalletMap = {
  [id: string]: SubWallet;
};

export class MasterWallet {
  protected _createdWallets: WalletMap = {};
  protected _account: Account;
  protected _id: string;
  protected _config: Config;

  private constructor() {}

  public static async newFromStorage(
    id: string,
    config: Config,
    storage: WalletStorage
  ) {
    let masterWallet = new MasterWallet();
    masterWallet._id = id;
    masterWallet._config = config;
    masterWallet._account = await Account.newFromAccount(id, storage);
    masterWallet.setupNetworkParameters();
    return masterWallet;
  }

  public static async newFromMnemonic(
    id: string, // masterWalletID
    mnemonic: string,
    passphrase: string,
    passwd: string,
    singleAddress: boolean,
    config: Config,
    storage: WalletStorage
  ) {
    let masterWallet = new MasterWallet();
    masterWallet._id = id;
    masterWallet._config = config;

    masterWallet._account = Account.newFromMnemonicAndPassphrase(
      id,
      storage,
      mnemonic,
      passphrase,
      passwd,
      singleAddress
    );

    await masterWallet._account.save();
    masterWallet.setupNetworkParameters();
    return masterWallet;
  }

  public static async newFromSeed(
    id: string,
    seed: Buffer,
    payPasswd: string,
    singleAddress: boolean,
    mnemonic: string, // can be empty
    passphrase: string, // can be empty
    config: Config,
    storage: WalletStorage
  ) {
    let masterWallet = new MasterWallet();
    masterWallet._id = id;
    masterWallet._config = config;
    masterWallet._account = Account.newFromSeed(
      id,
      storage,
      seed,
      payPasswd,
      singleAddress,
      mnemonic,
      passphrase
    );
    await masterWallet._account.save();
    masterWallet.setupNetworkParameters();
    return masterWallet;
  }

  public static async newFromSinglePrivateKey(
    id: string,
    singlePrivateKey: string,
    passwd: string,
    config: Config,
    storage: WalletStorage
  ) {
    let masterWallet = new MasterWallet();
    masterWallet._id = id;
    masterWallet._config = config;
    masterWallet._account = Account.newFromSinglePrivateKey(
      id,
      storage,
      singlePrivateKey,
      passwd
    );
    await masterWallet._account.save();
    masterWallet.setupNetworkParameters();
    return masterWallet;
  }

  public static newFromKeystore(
    id: string,
    keystoreContent: JSONObject,
    backupPassword: string,
    payPasswd: string,
    config: Config,
    storage: WalletStorage
  ) {
    // TODO
    // KeyStore keystore;
    // keystore.Import(keystoreContent, backupPassword);

    let masterWallet = new MasterWallet();
    masterWallet._id = id;
    masterWallet._config = config;

    // TODO
    // masterWallet._account = Account.newFromKeyStore(
    //   id,
    //   storage,
    //   keystore,
    //   payPasswd
    // );
    // masterWallet._account.save();
    masterWallet.setupNetworkParameters();
    return masterWallet;
  }

  public static async newFromPublicKeyRings(
    id: string,
    pubKeyRings: PublicKeyRing[],
    m: uint32_t,
    config: Config,
    storage: WalletStorage,
    singleAddress: boolean,
    compatible: boolean
  ): Promise<MasterWallet> {
    ErrorChecker.checkParam(
      pubKeyRings.length < m,
      Error.Code.InvalidArgument,
      "Invalid M"
    );
    let masterWallet = new MasterWallet();
    masterWallet._id = id;
    masterWallet._config = config;
    masterWallet._account = Account.newFromPublicKeyRings(
      id,
      storage,
      pubKeyRings,
      m,
      singleAddress,
      compatible
    );
    await masterWallet._account.save();
    masterWallet.setupNetworkParameters();
    return masterWallet;
  }

  public static async newFromXPrivateKey(
    id: string,
    xprv: string,
    payPassword: string,
    cosigners: PublicKeyRing[],
    m: uint32_t,
    config: Config,
    storage: WalletStorage,
    singleAddress: boolean,
    compatible: boolean
  ) {
    ErrorChecker.checkParam(
      cosigners.length + 1 < m,
      Error.Code.InvalidArgument,
      "Invalid M"
    );
    let masterWallet = new MasterWallet();
    masterWallet._id = id;
    masterWallet._config = config;
    masterWallet._account = Account.newFromXPrivateKey(
      id,
      storage,
      xprv,
      payPassword,
      cosigners,
      m,
      singleAddress,
      compatible
    );
    await masterWallet._account.save();
    masterWallet.setupNetworkParameters();
    return masterWallet;
  }

  public static async newFromMultisignSeed(
    id: string,
    seed: Buffer,
    payPassword: string,
    cosigners: PublicKeyRing[],
    m: uint32_t,
    config: Config,
    storage: WalletStorage,
    singleAddress: boolean,
    compatible: boolean
  ) {
    ErrorChecker.checkParam(
      cosigners.length + 1 < m,
      Error.Code.InvalidArgument,
      "Invalid M"
    );
    let masterWallet = new MasterWallet();
    masterWallet._id = id;
    masterWallet._config = config;
    masterWallet._account = Account.newFromMultisignSeed(
      id,
      storage,
      seed,
      payPassword,
      cosigners,
      m,
      singleAddress,
      compatible
    );
    await masterWallet._account.save();
    masterWallet.setupNetworkParameters();
    return masterWallet;
  }

  public static async newFromMnemonicAndPublicKeyRings(
    id: string,
    mnemonic: string,
    passphrase: string,
    payPasswd: string,
    cosigners: PublicKeyRing[],
    m: uint32_t,
    config: Config,
    storage: WalletStorage,
    singleAddress: boolean,
    compatible: boolean
  ) {
    ErrorChecker.checkParam(
      cosigners.length + 1 < m,
      Error.Code.InvalidArgument,
      "Invalid M"
    );
    let masterWallet = new MasterWallet();
    masterWallet._id = id;
    masterWallet._config = config;
    masterWallet._account = Account.newFromMultiSignMnemonic(
      id,
      storage,
      mnemonic,
      passphrase,
      payPasswd,
      cosigners,
      m,
      singleAddress,
      compatible
    );
    await masterWallet._account.save();
    masterWallet.setupNetworkParameters();
    return masterWallet;
  }

  destroy() {}

  public static generateMnemonic(language: string): string {
    const mnemonicObj = Mnemonic.getInstance(language);
    const mnemonic = mnemonicObj.generate();
    return mnemonic;
  }

  async removeLocalStore() {
    await this._account.remove();
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

    let result = "";
    for (let i = 0; i < subWallets.length; ++i)
      result += subWallets[i].getChainID() + ",";

    Log.info("getting all subwallet chainIDs...", result);
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

  public async createSubWallet(chainID: string) {
    //ArgInfo("{} {}", _id, GetFunName());
    //ArgInfo("chainID: {}", chainID);

    ErrorChecker.checkParamNotEmpty(chainID, "Chain ID");
    ErrorChecker.checkParam(
      chainID.length > 128,
      Error.Code.InvalidArgument,
      "Chain ID should less than 128"
    );

    if (this._createdWallets && this._createdWallets[chainID]) {
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
    await this._account.save();

    return subWallet;
  }

  verifyPrivateKey(mnemonic: string, passphrase: string): boolean {
    // ArgInfo("{} {}", _id, GetFunName());
    // ArgInfo("mnemonic: *");
    // ArgInfo("passphrase: *");
    const r: boolean = this._account.verifyPrivateKey(mnemonic, passphrase);
    // ArgInfo("r => {}", r);
    return r;
  }

  async verifyPassPhrase(
    passphrase: string,
    payPasswd: string
  ): Promise<boolean> {
    // ArgInfo("{} {}", _id, GetFunName());
    // ArgInfo("passphrase: *");
    // ArgInfo("payPasswd: *");
    const r: boolean = await this._account.verifyPassPhrase(
      passphrase,
      payPasswd
    );
    // ArgInfo("r => {}", r);
    return r;
  }

  async verifyPayPassword(payPasswd: string): Promise<boolean> {
    // ArgInfo("{} {}", _id, GetFunName());
    // ArgInfo("payPasswd: *");
    const r: boolean = await this._account.verifyPayPassword(payPasswd);
    // ArgInfo("r => {}", r);
    return r;
  }

  closeAllSubWallets() {
    this._createdWallets = {};
  }

  setupNetworkParameters() {
    const configs: ConfigMap = this._config.getConfigs();
    const keys = Object.keys(configs);
    for (let i = 0; i < keys.length; i++) {
      const value = configs[keys[i]];
      if (value.name() && value.name().length !== 0) {
        EthereumNetworks.insertEthereumNetwork(
          value.name(),
          value.chainID(),
          value.networkID()
        );
      }
    }
  }

  async destroyWallet(chainID: string): Promise<void> {
    // ArgInfo("{} {}", _id, GetFunName());
    // ArgInfo("chainID: {}", chainID);
    const keys = Object.keys(this._createdWallets);
    if (chainID in keys) {
      const subWallet = this._createdWallets[chainID];
      this._account.removeSubWalletInfo(subWallet.getChainID());
      await this._account.save();
      this._createdWallets[chainID] = null;
      // ArgInfo("r => {} {} done", this._id, GetFunName());
    } else {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "chainID not found"
      );
    }
  }

  getPubKeyInfo(): AccountPubKeyInfo {
    // ArgInfo("{} {}",this._id, GetFunName());
    const j = this._account.getPubKeyInfo();

    // ArgInfo("r => {}", j.dump());
    return j;
  }

  /*
#if 0
  nlohmann::json MasterWallet::ExportReadonlyWallet() const {
    ArgInfo("{} {}", _id, GetFunName());

    nlohmann::json j = _account->ExportReadonlyWallet();

    ArgInfo("r => {}", j.dump());
    return j;
  }
#endif
*/

  async exportKeystore(
    backupPassword: string,
    payPassword: string
  ): Promise<JSONObject> {
    // ArgInfo("{} {}", _id, GetFunName());
    // ArgInfo("backupPassword: *");
    // ArgInfo("payPassword: *");
    ErrorChecker.checkPassword(backupPassword, "Backup");

    const coinInfo: CoinInfo[] = this._account.subWalletInfoList();
    this._account.setSubWalletInfoList(coinInfo);
    await this._account.save();

    let j: JSONObject = {};
    // TODO
    // const keyStore: KeyStore = this._account.exportKeystore(payPassword);
    // j = keyStore.Export(backupPassword, true);

    // ArgInfo("r => *");
    return j;
  }

  async exportMnemonic(payPassword: string): Promise<string> {
    // ArgInfo("{} {}", _id, GetFunName());
    // ArgInfo("payPassword: *");

    const mnemonic = await this._account.exportMnemonic(payPassword);

    // ArgInfo("r => *");
    return mnemonic;
  }

  async exportPrivateKey(payPasswd: string): Promise<string> {
    // ArgInfo("{} {}", _id, GetFunName());
    // ArgInfo("payPsswd: *");

    ErrorChecker.checkLogic(
      this._account.readonly(),
      Error.Code.UnsupportOperation,
      "Unsupport operation: read-only wallet do not contain xprv"
    );

    const xprv: string = await this._account.getxPrvKeyString(payPasswd);

    // ArgInfo("r => *");
    return xprv;
  }

  exportMasterPublicKey(): string {
    // ArgInfo("{} {}", _id, GetFunName());

    const mpk: string = this._account.masterPubKeyString();

    // ArgInfo("r => {}", mpk);
    return mpk;
  }

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

      let subWallet: SubWallet = this.subWalletFactoryMethod(
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

  subWalletFactoryMethod(
    info: CoinInfo,
    config: ChainConfig,
    parent: MasterWallet,
    netType: string
  ) {
    if (info.getChainID() == "ELA") {
      return new MainchainSubWallet(info, config, parent, netType);
    } else if (info.getChainID() == "IDChain") {
      // TODO
      // return new IDChainSubWallet(info, config, parent, netType);
    } else if (info.getChainID() == "BTC") {
      // TODO
      // return new BTCSubWallet(info, config, parent, netType);
    } else if (info.getChainID().indexOf("ETH") !== -1) {
      // TODO
      // return new EthSidechainSubWallet(info, config, parent, netType);
      // } else if (info.getChainID() == "XRP") {
      // return new RippleSubWallet(info, config, parent, netType);
    } else {
      ErrorChecker.throwLogicException(
        Error.Code.InvalidChainID,
        "Invalid chain ID: " + info.getChainID()
      );
    }

    return null;
  }

  getDataPath(): Promise<string> {
    return this._account.getDataPath();
  }

  public getAccount(): Account {
    return this._account;
  }

  isAddressValid(address: string): boolean {
    // ArgInfo("{} {}", _id, GetFunName());
    // ArgInfo("addr: {}", address);

    let valid: boolean = Address.newFromAddressString(address).valid();
    if (!valid) {
      // TODO: valid = addressValidateString(address) == ETHEREUM_BOOLEAN_TRUE;
    }

    // ArgInfo("r => {}", valid);
    return valid;
  }

  isSubWalletAddressValid(chainID: string, address: string): boolean {
    // ArgInfo("{} {}", _id, GetFunName());
    // ArgInfo("chainID: {}", chainID);
    // ArgInfo("address: {}", address);

    let valid = false;
    if (
      chainID === CHAINID_MAINCHAIN ||
      chainID === CHAINID_IDCHAIN ||
      chainID === CHAINID_TOKENCHAIN
    ) {
      valid = Address.newFromAddressString(address).valid();
    } else if (chainID === "BTC") {
      // TODO: BRAddressParams addrParams;

      if (this._config.getNetType() === CONFIG_MAINNET) {
        // TODO: addrParams = BITCOIN_ADDRESS_PARAMS;
      } else {
        // TODO: addrParams = BITCOIN_TEST_ADDRESS_PARAMS;
      }
      // TODO: valid = BRAddressIsValid(addrParams, address);
    } else if (chainID.indexOf("ETH") !== -1) {
      // TODO:  valid = addressValidateString(address) == ETHEREUM_BOOLEAN_TRUE;
    }

    // ArgInfo("r => {}", valid);
    return valid;
  }

  getSupportedChains(): string[] {
    // ArgInfo("{} {}", _id, GetFunName());

    let chainIDs: string[] = this._config.getAllChainIDs();

    let result: string;
    for (let i = 0; i < chainIDs.length; ++i) {
      result += chainIDs[i] + ", ";
    }

    // ArgInfo("r => {}", result);
    return chainIDs;
  }

  async changePassword(
    oldPassword: string,
    newPassword: string
  ): Promise<void> {
    // ArgInfo("{} {}", _id, GetFunName());
    // ArgInfo("old: *");
    // ArgInfo("new: *");

    await this._account.changePassword(oldPassword, newPassword);
  }

  async resetPassword(
    mnemonic: string,
    passphrase: string,
    newPassword: string
  ): Promise<void> {
    // ArgInfo("{} {}", _id, GetFunName());
    // ArgInfo("m: *");
    // ArgInfo("passphrase: *");
    // ArgInfo("passwd: *");

    await this._account.resetPassword(mnemonic, passphrase, newPassword);

    // ArgInfo("r => ");
  }

  getBasicInfo(): AccountBasicInfo {
    // ArgInfo("{} {}", _id, GetFunName());

    const info: AccountBasicInfo = this._account.getBasicInfo();

    // ArgInfo("r => {}", info.dump());
    return info;
  }

  isEqual(wallet: MasterWallet): boolean {
    return this._account.equal(wallet._account);
  }

  flushData() {
    this._createdWallets = {};
    const keys = Object.keys(this._createdWallets);
    for (let i = 0; i < keys.length; i++) {
      const subWallet = this._createdWallets[keys[i]];
      if (subWallet !== null) {
        // TODO
        // subWallet.flushData();
      }
    }
  }

  getChainConfig(chainID: string): ChainConfig {
    return this._config.getChainConfig(chainID);
  }
}
