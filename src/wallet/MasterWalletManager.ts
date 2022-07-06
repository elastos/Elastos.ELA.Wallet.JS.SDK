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
import { Lockable } from "../common/Lockable";
import { Log } from "../common/Log";
import {
  Config,
  CONFIG_MAINNET,
  CONFIG_PRVNET,
  CONFIG_REGTEST,
  CONFIG_TESTNET,
  ConfigInfo
} from "../config";
import { WalletStorage } from "../persistence/WalletStorage";
import { time_t, uint32_t } from "../types";
import { Base58Check } from "../walletcore/base58";
import { KeyStoreInfo } from "../walletcore/keystore";
import { Mnemonic } from "../walletcore/mnemonic";
import { PublicKeyRing } from "../walletcore/publickeyring";
import { MasterWallet } from "./MasterWallet";

export class MasterWalletManager {
  protected _lock: Lockable;
  protected _config: Config;
  protected _masterWalletMap: Map<string, MasterWallet> = new Map();
  private _storage: WalletStorage;

  private constructor(
    storage: WalletStorage,
    netType: string,
    config: ConfigInfo
  ) {
    this._lock = new Lockable();

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
  }

  private async init(): Promise<void> {
    await this.loadMasterWalletID(this._storage);
  }

  public static async create(
    storage: WalletStorage,
    netType: string,
    config: ConfigInfo
  ): Promise<MasterWalletManager> {
    let manager = new MasterWalletManager(storage, netType, config);
    await manager.init();
    return manager;
  }

  destroy() {}

  protected async loadMasterWalletID(storage: WalletStorage) {
    const masterWalletIDs = await storage.getMasterWalletIDs();
    if (!masterWalletIDs) return;

    for (let i = 0; i < masterWalletIDs.length; i++) {
      let masterWalletID = masterWalletIDs[i];
      this._masterWalletMap.set(masterWalletID, null);
    }
  }

  protected async loadMasterWallet(
    masterWalletID: string
  ): Promise<MasterWallet> {
    Log.info("loading wallet: {} ...", masterWalletID);

    let masterWallet: MasterWallet;
    try {
      masterWallet = await MasterWallet.newFromStorage(
        masterWalletID,
        this._config,
        this._storage
      );
      masterWallet.initSubWallets();
      this._masterWalletMap.set(masterWalletID, masterWallet);
    } catch (error) {
      Log.error(
        `load master wallet ${masterWalletID} failed: {}`,
        error.message
      );
      masterWallet = null;
    }

    return Promise.resolve(masterWallet);
  }

  /**
   * Generate a mnemonic by random entropy.
   * @param language specify mnemonic language. We support language below
   *   chinese_simplified,
   *   chinese_traditional",
   *   czech,
   *   english,
   *   french,
   *   italian,
   *   japanese,
   *   korean,
   *   spanish
   * @return a random mnemonic.
   */
  generateMnemonic(language: string): string {
    // ArgInfo("{}", GetFunName());
    // ArgInfo("language: {}", language);
    // ArgInfo("wordCount: {}", wordCount);
    const mnemonic: string = MasterWallet.generateMnemonic(language);
    // ArgInfo("r => *");
    return mnemonic;
  }

  /**
   * Create a new master wallet by mnemonic and phrase password, or return existing master wallet if current master wallet manager has the master wallet id.
   * @param masterWalletID is the unique identification of a master wallet object.
   * @param mnemonic use to generate seed which deriving the master private key and chain code.
   * @param passphrase combine with random seed to generate root key and chain code. Phrase password can be empty or between 8 and 128, otherwise will throw invalid argument exception.
   * @param passwd use to encrypt important things(such as private key) in memory. Pay password should between 8 and 128, otherwise will throw invalid argument exception.
   * @param singleAddress if true, the created wallet will only contain one address, otherwise wallet will manager a chain of addresses.
   * @return If success will return a pointer of master wallet interface.
   */
  async createMasterWallet(
    masterWalletID: string,
    mnemonic: string,
    passphrase: string,
    passwd: string,
    singleAddress: boolean
  ): Promise<MasterWallet> {
    // ArgInfo("{}", GetFunName());
    // ArgInfo("masterWalletID: {}", masterWalletID);
    // ArgInfo("mnemonic: *");
    // ArgInfo("passphrase: *, empty: {}", passphrase.empty());
    // ArgInfo("passwd: *");
    // ArgInfo("singleAddress: {}", singleAddress);

    // boost::mutex::scoped_lock scoped_lock(_lock->GetLock());

    ErrorChecker.checkParamNotEmpty(masterWalletID, "Master wallet ID");
    ErrorChecker.checkParamNotEmpty(mnemonic, "mnemonic");
    ErrorChecker.checkPassword(passwd, "Pay");
    ErrorChecker.checkPasswordWithNullLegal(passphrase, "Phrase");

    if (this._masterWalletMap.has(masterWalletID)) {
      // ArgInfo("r => already exist");
      return this._masterWalletMap[masterWalletID];
    }

    const lang: string = Mnemonic.getLanguage(mnemonic);
    const mnemonicObj = Mnemonic.getInstance(lang);
    ErrorChecker.checkLogic(
      !mnemonicObj.isValid(mnemonic),
      Error.Code.Mnemonic,
      "Invalid mnemonic"
    );

    const masterWallet = await MasterWallet.newFromMnemonic(
      masterWalletID,
      mnemonic,
      passphrase,
      passwd,
      singleAddress,
      this._config,
      this._storage
    );

    await this.checkRedundant(masterWallet);
    this._masterWalletMap.set(masterWalletID, masterWallet);

    // ArgInfo("r => create master wallet done");
    return masterWallet;
  }

  /**
   * Create master wallet with single private key (for eth side-chain single private key)
   * @masterWalletID unique ID of master wallet
   * @singlePrivateKey uint256 hex string of private key
   * @passwd pay password
   */
  async createMasterWalletWithPrivateKey(
    masterWalletID: string,
    singlePrivateKey: string,
    passwd: string
  ): Promise<MasterWallet> {
    // ArgInfo("{}", GetFunName());
    // ArgInfo("masterWalletID: {}", masterWalletID);
    // ArgInfo("singlePrivateKey: *");
    // ArgInfo("passwd: *");

    ErrorChecker.checkParamNotEmpty(masterWalletID, "Master wallet ID");
    ErrorChecker.checkPassword(passwd, "Pay");
    if (this._masterWalletMap.has(masterWalletID)) {
      // ArgInfo("r => already exist");
      return this._masterWalletMap.get(masterWalletID);
    }

    const masterWallet = await MasterWallet.newFromSinglePrivateKey(
      masterWalletID,
      singlePrivateKey,
      passwd,
      this._config,
      this._storage
    );
    await this.checkRedundant(masterWallet);
    this._masterWalletMap.set(masterWalletID, masterWallet);

    // ArgInfo("r => create master wallet done");
    return Promise.resolve(masterWallet);
  }

  /**
   * Create a multi-sign master wallet by related co-signers, or return existing master wallet if current master wallet manager has the master wallet id. Note this creating method generate an readonly multi-sign account which can not append sign into a transaction.
   * @param masterWalletID is the unique identification of a master wallet object.
   * @param cosigners string array of signer's extend public key. Such as: ["xpub6CLgvYFxzqHDJCWyGDCRQzc5cwCFp4HJ6QuVJsAZqURxmW9QKWQ7hVKzZEaHgCQWCq1aNtqmE4yQ63Yh7frXWUW3LfLuJWBtDtsndGyxAQg", "xpub6CWEYpNZ3qLG1z2dxuaNGz9QQX58wor9ax8AiKBvRytdWfEifXXio1BgaVcT4t7ouP34mnabcvpJLp9rPJPjPx2m6izpHmjHkZAHAHZDyrc"]
   * @param m specify minimum count of signature to accomplish related transaction.
   * @param singleAddress if true, the created wallet will only contain one address, otherwise wallet will manager a chain of addresses.
   * @param compatible if true, will compatible with web multi-sign wallet. false: BIP45, true: BIP44
   * @param timestamp the value of time in seconds since 1970-01-01 00:00:00. It means the time when the wallet contains the first transaction.
   * @return If success will return a pointer of master wallet interface.
   */
  async createMultiSignMasterWallet(
    masterWalletID: string,
    cosigners: string[],
    m: uint32_t,
    singleAddress: boolean,
    compatible = false,
    timestamp: time_t = 0
  ): Promise<MasterWallet> {
    // ArgInfo("{}", GetFunName());
    // ArgInfo("masterWalletID: {}", masterWalletID);
    // ArgInfo("cosigners: {}", cosigners.dump());
    // ArgInfo("m: {}", m);
    // ArgInfo("singleAddress: {}", singleAddress);
    // ArgInfo("compatible: {}", compatible);
    // ArgInfo("timestamp: {}", timestamp);

    // boost::mutex::scoped_lock scoped_lock(_lock->GetLock());

    ErrorChecker.checkParamNotEmpty(masterWalletID, "Master wallet ID");
    ErrorChecker.checkParam(
      !Array.isArray(cosigners),
      Error.Code.PubKeyFormat,
      "cosigners should be string array"
    );
    ErrorChecker.checkParam(
      cosigners.length < 2,
      Error.Code.PubKeyFormat,
      "cosigners should at least contain 2 elements"
    );
    ErrorChecker.checkParam(m < 1, Error.Code.InvalidArgument, "Invalid m");

    let pubKeyRing: PublicKeyRing[] = [];

    for (let i = 0; i < cosigners.length; i++) {
      ErrorChecker.checkCondition(
        !typeof cosigners[i],
        Error.Code.PubKeyFormat,
        "cosigners should be string"
      );

      let xpub: string = cosigners[i];
      for (let i = 0; i < pubKeyRing.length; ++i) {
        if (pubKeyRing[i].getxPubKey() == xpub) {
          ErrorChecker.throwParamException(
            Error.Code.PubKeyFormat,
            "Contain same xpub"
          );
        }
      }
      pubKeyRing.push(new PublicKeyRing("", xpub));
    }

    if (this._masterWalletMap.has(masterWalletID)) {
      // ArgInfo("r => already exist");
      return this._masterWalletMap.get(masterWalletID);
    }
    const masterWallet = await MasterWallet.newFromPublicKeyRings(
      masterWalletID,
      pubKeyRing,
      m,
      this._config,
      this._storage,
      singleAddress,
      compatible
    );
    await this.checkRedundant(masterWallet);
    this._masterWalletMap.set(masterWalletID, masterWallet);

    // ArgInfo("r => create multi sign wallet");

    return masterWallet;
  }

  /**
   * Create a multi-sign master wallet by private key and related co-signers, or return existing master wallet if current master wallet manager has the master wallet id.
   * @param masterWalletID is the unique identification of a master wallet object.
   * @param xprv root extend private key of wallet.
   * @param payPassword use to encrypt important things(such as private key) in memory. Pay password should between 8 and 128, otherwise will throw invalid argument exception.
   * @param cosigners string array of signer's extend public key. Such as: ["xpub6CLgvYFxzqHDJCWyGDCRQzc5cwCFp4HJ6QuVJsAZqURxmW9QKWQ7hVKzZEaHgCQWCq1aNtqmE4yQ63Yh7frXWUW3LfLuJWBtDtsndGyxAQg", "xpub6CWEYpNZ3qLG1z2dxuaNGz9QQX58wor9ax8AiKBvRytdWfEifXXio1BgaVcT4t7ouP34mnabcvpJLp9rPJPjPx2m6izpHmjHkZAHAHZDyrc"]
   * @param m specify minimum count of signature to accomplish related transaction.
   * @param singleAddress if true, the created wallet will only contain one address, otherwise wallet will manager a chain of addresses.
   * @param compatible if true, will compatible with web multi-sign wallet. false: BIP45, true: BIP44
   * @param timestamp the value of time in seconds since 1970-01-01 00:00:00. It means the time when the wallet contains the first transaction.
   * @return If success will return a pointer of master wallet interface.
   */
  async createMultiSignMasterWalletWithPrivateKey(
    masterWalletID: string,
    xprv: string,
    payPassword: string,
    cosigners: string[],
    m: uint32_t,
    singleAddress: boolean,
    compatible = false,
    timestamp: time_t = 0
  ) {
    // ArgInfo("{}", GetFunName());
    // ArgInfo("masterWalletID: {}", masterWalletID);
    // ArgInfo("xprv: *");
    // ArgInfo("payPasswd: *");
    // ArgInfo("cosigners: {}", cosigners.dump());
    // ArgInfo("m: {}", m);
    // ArgInfo("singleAddress: {}", singleAddress);
    // ArgInfo("compatible: {}", compatible);
    // ArgInfo("timestamp: {}", timestamp);

    // boost::mutex::scoped_lock scoped_lock(_lock->GetLock());

    ErrorChecker.checkParamNotEmpty(masterWalletID, "Master wallet ID");
    ErrorChecker.checkPassword(payPassword, "Pay");
    ErrorChecker.checkParam(
      !Array.isArray(cosigners),
      Error.Code.PubKeyFormat,
      "cosigners should be string array"
    );
    ErrorChecker.checkParam(
      cosigners.length === 0,
      Error.Code.PubKeyFormat,
      "cosigners should at least contain 1 elements"
    );
    ErrorChecker.checkParam(m < 1, Error.Code.InvalidArgument, "Invalid m");

    let pubKeyRing: PublicKeyRing[] = [];
    for (let i = 0; i < cosigners.length; i++) {
      ErrorChecker.checkCondition(
        !(typeof cosigners[i] === "string"),
        Error.Code.PubKeyFormat,
        "cosigners should be string"
      );
      let xpub: string = cosigners[i];
      for (let i = 0; i < pubKeyRing.length; ++i) {
        if (pubKeyRing[i].getxPubKey() === xpub) {
          ErrorChecker.throwParamException(
            Error.Code.PubKeyFormat,
            "Contain same xpub"
          );
        }
      }
      pubKeyRing.push(new PublicKeyRing("", xpub));
    }

    if (this._masterWalletMap.has(masterWalletID)) {
      // ArgInfo("r => already exist");
      return this._masterWalletMap.get(masterWalletID);
    }

    const masterWallet = await MasterWallet.newFromXPrivateKey(
      masterWalletID,
      xprv,
      payPassword,
      pubKeyRing,
      m,
      this._config,
      this._storage,
      singleAddress,
      compatible
    );
    await this.checkRedundant(masterWallet);
    this._masterWalletMap.set(masterWalletID, masterWallet);

    // ArgInfo("r => create multi sign wallet");

    return masterWallet;
  }

  /**
   * Create a multi-sign master wallet by seed and related co-signers, or return existing master wallet if current master wallet manager has the master wallet id.
   * @param masterWalletID is the unique identification of a master wallet object.
   * @param seed seed hex-string of uint512
   * @param payPassword use to encrypt important things(such as private key) in memory. Pay password should between 8 and 128, otherwise will throw invalid argument exception.
   * @param cosigners string array of signer's extend public key. Such as: ["xpub6CLgvYFxzqHDJCWyGDCRQzc5cwCFp4HJ6QuVJsAZqURxmW9QKWQ7hVKzZEaHgCQWCq1aNtqmE4yQ63Yh7frXWUW3LfLuJWBtDtsndGyxAQg", "xpub6CWEYpNZ3qLG1z2dxuaNGz9QQX58wor9ax8AiKBvRytdWfEifXXio1BgaVcT4t7ouP34mnabcvpJLp9rPJPjPx2m6izpHmjHkZAHAHZDyrc"]
   * @param m specify minimum count of signature to accomplish related transaction.
   * @param singleAddress if true, the created wallet will only contain one address, otherwise wallet will manager a chain of addresses.
   * @param compatible if true, will compatible with web multi-sign wallet. false: BIP45, true: BIP44
   * @param timestamp the value of time in seconds since 1970-01-01 00:00:00. It means the time when the wallet contains the first transaction.
   * @return If success will return a pointer of master wallet interface.
   */
  async createMultiSignMasterWalletWithSeed(
    masterWalletID: string,
    seed: string,
    payPassword: string,
    cosigners: string[],
    m: uint32_t,
    singleAddress: boolean,
    compatible = false,
    timestamp: time_t = 0
  ) {
    ErrorChecker.checkParamNotEmpty(masterWalletID, "Master wallet ID");
    ErrorChecker.checkParamNotEmpty(seed, "seed");
    ErrorChecker.checkPassword(payPassword, "Pay");
    ErrorChecker.checkParam(
      !Array.isArray(cosigners),
      Error.Code.PubKeyFormat,
      "cosigners should be string array"
    );
    ErrorChecker.checkParam(
      cosigners.length === 0,
      Error.Code.PubKeyFormat,
      "cosigners should at least contain 1 elements"
    );
    ErrorChecker.checkParam(m < 1, Error.Code.InvalidArgument, "Invalid m");

    let pubKeyRing: PublicKeyRing[] = [];
    for (let i = 0; i < cosigners.length; i++) {
      ErrorChecker.checkCondition(
        !(typeof cosigners[i] === "string"),
        Error.Code.PubKeyFormat,
        "cosigners should be string"
      );
      let xpub: string = cosigners[i];
      for (let i = 0; i < pubKeyRing.length; ++i) {
        if (pubKeyRing[i].getxPubKey() === xpub) {
          ErrorChecker.throwParamException(
            Error.Code.PubKeyFormat,
            "Contain same xpub"
          );
        }
      }
      pubKeyRing.push(new PublicKeyRing("", xpub));
    }

    if (this._masterWalletMap.has(masterWalletID)) {
      // ArgInfo("r => already exist");
      return this._masterWalletMap.get(masterWalletID);
    }

    let seedBytes = Buffer.from(seed, "hex");
    const masterWallet = await MasterWallet.newFromMultisignSeed(
      masterWalletID,
      seedBytes,
      payPassword,
      pubKeyRing,
      m,
      this._config,
      this._storage,
      singleAddress,
      compatible
    );
    await this.checkRedundant(masterWallet);
    this._masterWalletMap.set(masterWalletID, masterWallet);

    // ArgInfo("r => create multi sign wallet");

    return masterWallet;
  }

  /**
   * Create a multi-sign master wallet by private key and related co-signers, or return existing master wallet if current master wallet manager has the master wallet id.
   * @param masterWalletID is the unique identification of a master wallet object.
   * @param mnemonic use to generate seed which deriving the master private key and chain code.
   * @param passphrase combine with random seed to generate root key and chain code. Phrase password can be empty or between 8 and 128, otherwise will throw invalid argument exception.
   * @param payPassword use to encrypt important things(such as private key) in memory. Pay password should between 8 and 128, otherwise will throw invalid argument exception.
   * @param cosigners JSON array of signer's extend public key. Such as: ["xpub6CLgvYFxzqHDJCWyGDCRQzc5cwCFp4HJ6QuVJsAZqURxmW9QKWQ7hVKzZEaHgCQWCq1aNtqmE4yQ63Yh7frXWUW3LfLuJWBtDtsndGyxAQg", "xpub6CWEYpNZ3qLG1z2dxuaNGz9QQX58wor9ax8AiKBvRytdWfEifXXio1BgaVcT4t7ouP34mnabcvpJLp9rPJPjPx2m6izpHmjHkZAHAHZDyrc"]
   * @param m specify minimum count of signature to accomplish related transactions.
   * @param singleAddress if true, the created wallet will only contain one address, otherwise wallet will manager a chain of addresses.
   * @param compatible if true, will compatible with web multi-sign wallet. false: BIP45, true: BIP44
   * @param timestamp the value of time in seconds since 1970-01-01 00:00:00. It means the time when the wallet contains the first transaction.
   * @return If success will return a pointer of master wallet interface.
   */
  async createMultiSignMasterWalletWithMnemonic(
    masterWalletID: string,
    mnemonic: string,
    passphrase: string,
    payPassword: string,
    cosigners: string[],
    m: uint32_t,
    singleAddress: boolean,
    compatible = false,
    timestamp: time_t = 0
  ): Promise<MasterWallet> {
    // ArgInfo("{}", GetFunName());
    // ArgInfo("masterWalletID: {}", masterWalletID);
    // ArgInfo("mnemonic: *");
    // ArgInfo("passphrase: *, empty: {}", passphrase.empty());
    // ArgInfo("payPasswd: *");
    // ArgInfo("cosigners: {}", cosigners.dump());
    // ArgInfo("m: {}", m);
    // ArgInfo("singleAddress: {}", singleAddress);
    // ArgInfo("compatible: {}", compatible);
    // ArgInfo("timestamp: {}", timestamp);

    // boost::mutex::scoped_lock scoped_lock(_lock->GetLock());

    ErrorChecker.checkParamNotEmpty(masterWalletID, "Master wallet ID");
    ErrorChecker.checkParamNotEmpty(mnemonic, "Mnemonic");
    ErrorChecker.checkPassword(payPassword, "Pay");
    ErrorChecker.checkPasswordWithNullLegal(passphrase, "Phrase");
    ErrorChecker.checkParam(
      !Array.isArray(cosigners),
      Error.Code.PubKeyFormat,
      "cosigners should be string array"
    );
    ErrorChecker.checkParam(m < 1, Error.Code.InvalidArgument, "Invalid m");

    if (this._masterWalletMap.has(masterWalletID)) {
      // ArgInfo("r => already exist");
      return this._masterWalletMap.get(masterWalletID);
    }

    let pubKeyRing: PublicKeyRing[] = [];
    for (let i = 0; i < cosigners.length; i++) {
      ErrorChecker.checkCondition(
        !(
          typeof cosigners[i] === "string" || !Base58Check.decode(cosigners[i])
        ),
        Error.Code.PubKeyFormat,
        "cosigners format error"
      );
      let xpub = cosigners[i];
      for (let i = 0; i < pubKeyRing.length; ++i) {
        if (pubKeyRing[i].getxPubKey() === xpub) {
          ErrorChecker.throwParamException(
            Error.Code.PubKeyFormat,
            "Contain same xpub"
          );
        }
      }
      pubKeyRing.push(new PublicKeyRing("", xpub));
    }

    const masterWallet = await MasterWallet.newFromMnemonicAndPublicKeyRings(
      masterWalletID,
      mnemonic,
      passphrase,
      payPassword,
      pubKeyRing,
      m,
      this._config,
      this._storage,
      singleAddress,
      compatible
    );
    await this.checkRedundant(masterWallet);
    this._masterWalletMap.set(masterWalletID, masterWallet);
    return masterWallet;
  }

  /**
   * Get manager existing master wallets.
   * @return existing master wallet array.
   */
  async getAllMasterWallets(): Promise<MasterWallet[]> {
    // ArgInfo("{}", GetFunName());
    // boost::mutex::scoped_lock scoped_lock(_lock->GetLock());

    let result: MasterWallet[] = [];
    for (let [key, value] of this._masterWalletMap.entries()) {
      if (value) {
        result.push(value);
      } else {
        result.push(await this.loadMasterWallet(key));
      }
    }

    // ArgInfo("r => all master wallet count: {}", result.length);
    return Promise.resolve(result);
  }

  /**
   * Destroy a master wallet.
   * @param masterWalletID A pointer of master wallet interface create or imported by wallet factory object.
   */
  async destroyWallet(masterWalletID: string) {
    // ArgInfo("{}", GetFunName());
    // ArgInfo("masterWalletID: {}", masterWalletID);

    // boost::mutex::scoped_lock scoped_lock(_lock->GetLock());

    if (this._masterWalletMap.has(masterWalletID)) {
      const masterWallet = this._masterWalletMap.get(masterWalletID);
      if (masterWallet !== null) {
        await masterWallet.removeLocalStore();
        masterWallet.closeAllSubWallets();
        this._masterWalletMap.delete(masterWallet.getWalletID());
      }
    } else {
      Log.warn("Master wallet is not exist");
    }

    // ArgInfo("r => {} done", GetFunName());
  }

  /**
   * Import master wallet by key store file.
   * @param masterWalletId is the unique identification of a master wallet object.
   * @param keystoreContent specify key store content in json format.
   * @param backupPassword use to encrypt key store file. Backup password should between 8 and 128, otherwise will throw invalid argument exception.
   * @param payPassword use to encrypt important things(such as private key) in memory. Pay password should between 8 and 128, otherwise will throw invalid argument exception.
   * @param phrasePassword combine with random seed to generate root key and chain code. Phrase password can be empty or between 8 and 128, otherwise will throw invalid argument exception.
   * @return If success will return a pointer of master wallet interface.
   */
  async importWalletWithKeystore(
    masterWalletID: string,
    keystoreContent: KeyStoreInfo,
    backupPassword: string,
    payPassword: string
  ) {
    // ArgInfo("{}", GetFunName());
    // ArgInfo("masterWalletID: {}", masterWalletID);
    // ArgInfo("keystore: *");
    // ArgInfo("backupPasswd: *");
    // ArgInfo("payPasswd: *");

    // boost::mutex::scoped_lock scoped_lock(_lock->GetLock());

    ErrorChecker.checkParamNotEmpty(masterWalletID, "Master wallet ID");
    ErrorChecker.checkParam(
      !(typeof keystoreContent === "object" && keystoreContent !== null),
      Error.Code.KeyStore,
      "key store should be json object"
    );
    ErrorChecker.checkPassword(backupPassword, "Backup");

    if (this._masterWalletMap.has(masterWalletID)) {
      // ArgInfo("r => already exist");
      return this._masterWalletMap.get(masterWalletID);
    }
    const masterWallet = await MasterWallet.newFromKeystore(
      masterWalletID,
      keystoreContent,
      backupPassword,
      payPassword,
      this._config,
      this._storage
    );
    await this.checkRedundant(masterWallet);
    this._masterWalletMap.set(masterWalletID, masterWallet);
    masterWallet.initSubWallets();

    // ArgInfo("r => import with keystore");

    return masterWallet;
  }

  /**
   * Import master wallet by mnemonic.
   * @param masterWalletID is the unique identification of a master wallet object.
   * @param mnemonic for importing the master wallet.
   * @param phrasePassword combine with mnemonic to generate root key and chain code. Phrase password can be empty or between 8 and 128, otherwise will throw invalid argument exception.
   * @param payPassword use to encrypt important things(such as private key) in memory. Pay password should between 8 and 128, otherwise will throw invalid argument exception.
   * @param singleAddress singleAddress if true created wallet will have only one address inside, otherwise sub wallet will manager a chain of addresses for security.
   * @param timestamp the value of time in seconds since 1970-01-01 00:00:00. It means the time when the wallet contains the first transaction.
   * @return If success will return a pointer of master wallet interface.
   */
  async importWalletWithMnemonic(
    masterWalletID: string,
    mnemonic: string,
    phrasePassword: string,
    payPassword: string,
    singleAddress: boolean,
    timestamp: time_t
  ): Promise<MasterWallet> {
    // ArgInfo("{}", GetFunName());
    // ArgInfo("masterWalletID: {}", masterWalletID);
    // ArgInfo("mnemonic: *");
    // ArgInfo("passphrase: *, empty: {}", phrasePassword.empty());
    // ArgInfo("payPasswd: *");
    // ArgInfo("singleAddr: {}", singleAddress);
    // ArgInfo("timestamp: {}", timestamp);

    // boost::mutex::scoped_lock scoped_lock(_lock->GetLock());

    ErrorChecker.checkParamNotEmpty(masterWalletID, "Master wallet ID");
    ErrorChecker.checkParamNotEmpty(mnemonic, "Mnemonic");
    ErrorChecker.checkPasswordWithNullLegal(phrasePassword, "Phrase");
    ErrorChecker.checkPassword(payPassword, "Pay");

    if (this._masterWalletMap.has(masterWalletID)) {
      // ArgInfo("r => already exist");
      return this._masterWalletMap.get(masterWalletID);
    }

    const lang = Mnemonic.getLanguage(mnemonic);
    const mnemonicObj = Mnemonic.getInstance(lang);
    ErrorChecker.checkLogic(
      !mnemonicObj.isValid(mnemonic),
      Error.Code.Mnemonic,
      "Invalid mnemonic"
    );

    const masterWallet = await MasterWallet.newFromMnemonic(
      masterWalletID,
      mnemonic,
      phrasePassword,
      payPassword,
      singleAddress,
      this._config,
      this._storage
    );

    await this.checkRedundant(masterWallet);
    this._masterWalletMap.set(masterWalletID, masterWallet);

    // ArgInfo("r => import with mnemonic");

    return masterWallet;
  }

  /**
   * Import master wallet by seed
   * Node: If the mnemonic is not empty, verify that the seed matches mnemonic + passphrase.
   *  If the mnemonic is empty, IMasterWallet::ExportMnemonic() will return empty.
   * @param masterWalletID is the unique identification of a master wallet object
   * @param seed hex-string of uint512
   * @param payPassword use to encrypt important things(such as private key) in memory. Pay password should between 8 and 128, otherwise will throw invalid argument exception
   * @param singleAddress if true created wallet will have only one address inside, otherwise sub wallet will manager a chain of addresses for security
   * @param mnemonic mnemonic words string separated by spaces
   * @param passphrase combine with mnemonic to generate seed
   * @return If success will return a pointer of master wallet interface
   */
  async importWalletWithSeed(
    masterWalletID: string,
    seed: string,
    payPassword: string,
    singleAddress: boolean,
    mnemonic: string,
    passphrase: string
  ) {
    // ArgInfo("{}", GetFunName());
    // ArgInfo("masterWalletID: {}", masterWalletID);
    // ArgInfo("seed: *");
    // ArgInfo("payPassword: *");
    // ArgInfo("singleAddr: {}", singleAddress);
    // ArgInfo("mnemonic: *, empty: {}", mnemonic.empty());
    // ArgInfo("passphrase: *, empty: {}", passphrase.empty());

    // boost::mutex::scoped_lock scoped_lock(_lock->GetLock());

    ErrorChecker.checkParamNotEmpty(masterWalletID, "Master wallet ID");
    ErrorChecker.checkPassword(payPassword, "Pay");

    let seedBytes = Buffer.from(seed, "hex");

    if (mnemonic) {
      const lang = Mnemonic.getLanguage(mnemonic);
      const mnemonicObj = Mnemonic.getInstance(lang);
      ErrorChecker.checkParam(
        !mnemonicObj.isValid(mnemonic),
        Error.Code.Mnemonic,
        "Invalid mnemonic"
      );
      let stmp = Mnemonic.toSeed(mnemonic, passphrase);
      ErrorChecker.checkParam(
        seed != stmp.toString("hex"),
        Error.Code.Mnemonic,
        "seed not matches [mnemonic+passphrase]"
      );
    }

    if (this._masterWalletMap.has(masterWalletID)) {
      // ArgInfo("r => already exist");
      return this._masterWalletMap.get(masterWalletID);
    }

    let masterWallet = await MasterWallet.newFromSeed(
      masterWalletID,
      seedBytes,
      payPassword,
      singleAddress,
      mnemonic,
      passphrase,
      this._config,
      this._storage
    );
    await this.checkRedundant(masterWallet);
    this._masterWalletMap.set(masterWalletID, masterWallet);

    // ArgInfo("r => import with seed + [mnemonic:passphrase]");

    return masterWallet;
  }

  /* TODO
  getVersion(): string {
    ArgInfo("{}", GetFunName());
    ArgInfo("r => {}", SPVSDK_VERSION_MESSAGE);
    return SPVSDK_VERSION_MESSAGE;
  }
  */

  /**
   * Flush data into disk before destructions
   */
  flushData() {
    // boost::mutex::scoped_lock scoped_lock(_lock->GetLock());
    this._masterWalletMap.forEach((value) => {
      if (value !== null) {
        value.flushData(); // TODO
      }
    });
  }

  setLogLevel(level) {
    // ArgInfo("{}", GetFunName());
    // ArgInfo("level: {}", level);

    if (
      level != "trace" &&
      level != "debug" &&
      level != "info" &&
      level != "warning" &&
      level != "error" &&
      level != "critical" &&
      level != "off"
    ) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "invalid level"
      );
    }

    // TODO
    // Log.setLevel(spdlog::level::from_str(level));
  }

  /**
   * Get manager available master wallet ID
   * @return available id array
   */
  getAllMasterWalletID(): string[] {
    // ArgInfo("{}", GetFunName());
    // boost::mutex::scoped_lock scoped_lock(_lock->GetLock());

    let result: string[] = [];

    this._masterWalletMap.forEach((value, key) => result.push(key));

    let chainID = "";
    for (let i = 0; i < result.length; ++i) chainID += result[i] + ", ";

    // ArgInfo("r => {}: {}", GetFunName(), chainID);

    return result;
  }

  /**
   * Get status indicating whether wallet loaded
   * @return return true or false
   */
  walletLoaded(masterWalletID: string): boolean {
    // ArgInfo("{}", GetFunName());
    // ArgInfo("masterWalletID: {}", masterWalletID);

    // boost::mutex::scoped_lock scoped_lock(_lock->GetLock());

    if (!this._masterWalletMap.has(masterWalletID)) {
      Log.error("master wallet {} not found", masterWalletID);
      return false;
    }

    return this._masterWalletMap.get(masterWalletID) != null;
  }

  /**
   * Get a master wallet object by id.
   * @param masterWalletID master wallet id.
   * @return master wallet object.
   */
  getMasterWallet(masterWalletID: string): Promise<MasterWallet> {
    //ArgInfo("{}", GetFunName());
    //ArgInfo("masterWalletID: {}", masterWalletID);

    if (
      this._masterWalletMap.has(masterWalletID) &&
      this._masterWalletMap.get(masterWalletID) != null
    ) {
      return Promise.resolve(this._masterWalletMap.get(masterWalletID));
    }

    return this.loadMasterWallet(masterWalletID);
  }

  protected async checkRedundant(wallet: MasterWallet) {
    let masterWallet: MasterWallet = wallet;
    let hasRedundant = false;
    this._masterWalletMap.forEach((value, key) => {
      if (value !== null && !hasRedundant) {
        hasRedundant = masterWallet.isEqual(value);
        if (hasRedundant) return;
      }
    });

    if (hasRedundant) {
      Log.info("{} Destroying redundant wallet", masterWallet.getWalletID());

      masterWallet.closeAllSubWallets();
      Log.info("Clearing local", masterWallet.getID());
      await masterWallet.removeLocalStore();
      masterWallet = null;
    }

    ErrorChecker.checkCondition(
      hasRedundant,
      Error.Code.CreateMasterWalletError,
      "Master wallet already exist."
    );
  }
}
