// Copyright (c) 2012-2022 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

import BigNumber from "bignumber.js";
import { Buffer } from "buffer";
import randomInteger from "random-int";
import {
  AccountBasicInfo,
  SignType as AccountSignType,
} from "../account/Account";
import { PublickeysInfo, SubAccount } from "../account/SubAccount";
import { Error, ErrorChecker } from "../common/ErrorChecker";
import { Lockable } from "../common/Lockable";
import { Attribute, Usage } from "../transactions/Attribute";
import { Payload } from "../transactions/payload/Payload";
import { Program } from "../transactions/Program";
import { Transaction, TxVersion } from "../transactions/Transaction";
import { TransactionInput } from "../transactions/TransactionInput";
import {
  OutputArray,
  TransactionOutput,
} from "../transactions/TransactionOutput";
import { bytes_t, size_t, uint32_t, uint8_t } from "../types";
import { Address, AddressArray, Prefix } from "../walletcore/Address";
import { EcdsaSigner } from "../walletcore/ecdsasigner";
import { SHA256 } from "../walletcore/sha256";
import { UTXOSet } from "./UTXO";
import { CHAINID_MAINCHAIN } from "./WalletCommon";

export class Wallet extends Lockable {
  protected _walletID: string;
  protected _chainID: string;
  protected _subAccount: SubAccount;

  constructor(walletID: string, chainID: string, subAccount: SubAccount) {
    super();
    this._walletID = walletID + ":" + chainID;
    this._chainID = chainID;
    this._subAccount = subAccount;

    this.loadUsedAddress();
  }

  public createTransaction(
    type: uint8_t,
    payload: Payload,
    utxo: UTXOSet,
    outputs: OutputArray,
    memo: string,
    fee: BigNumber,
    changeBack2FirstInput = false,
    useRawMemo = false
  ): Transaction {
    let totalOutputAmount: BigNumber = new BigNumber(0);
    let totalInputAmount: BigNumber = new BigNumber(0);

    let tx = Transaction.newFromParams(type, payload);
    if (memo) {
      let finalMemo = useRawMemo ? memo : "type:text,msg:" + memo;
      tx.addAttribute(new Attribute(Usage.Memo, Buffer.from(finalMemo)));
    }

    const noneData = Buffer.from(randomInteger(0xffffffff).toString(10));
    tx.addAttribute(new Attribute(Usage.Nonce, noneData));

    for (let o of outputs) {
      totalOutputAmount = totalOutputAmount.plus(o.amount());
    }

    if (outputs) tx.setOutputs(outputs);

    for (let u of utxo) {
      tx.addInput(TransactionInput.newFromParams(u.hash(), u.index()));
      // For standard wallets, a code consists of the length of a public key, the public key itself and the standard sign type.
      let code = this._subAccount.getCode(u.getAddress());
      if (code === null) {
        ErrorChecker.throwParamException(
          Error.Code.Address,
          "Can't found code and path for input"
        );
      }
      tx.addUniqueProgram(Program.newFromParams(code, Buffer.alloc(0)));

      totalInputAmount = totalInputAmount.plus(u.getAmount());
    }

    if (totalInputAmount.lt(totalOutputAmount.plus(fee))) {
      ErrorChecker.throwLogicException(
        Error.Code.BalanceNotEnough,
        "Available balance is not enough"
      );
    } else if (totalInputAmount.gt(totalOutputAmount.plus(fee))) {
      // change
      let changeAmount: BigNumber = totalInputAmount
        .minus(totalOutputAmount)
        .minus(fee);
      let changeAddress: Address;
      if (changeBack2FirstInput) {
        changeAddress = utxo[0].getAddress();
      } else {
        let addresses: AddressArray = this._subAccount.getAddresses(
          0,
          1,
          false
        );
        changeAddress = addresses[0];
      }
      ErrorChecker.checkParam(
        !changeAddress.valid(),
        Error.Code.Address,
        "invalid change address"
      );
      tx.addOutput(
        TransactionOutput.newFromParams(changeAmount, changeAddress)
      );
    }

    ErrorChecker.checkLogic(
      tx.getOutputs().length == 0,
      Error.Code.InvalidArgument,
      "outputs empty or input amount not enough"
    );

    tx.setFee(fee);
    if (this._chainID == CHAINID_MAINCHAIN) tx.setVersion(TxVersion.V09);

    return tx;
  }

  public getChainAddressCachedAmount(chain: number): number {
    return this._subAccount.getChainAddressCachedAmount(chain);
  }

  public getPublickeys(index: uint32_t, count: size_t, internal: boolean) {
    const pubkeys: string[] | PublickeysInfo = this._subAccount.getPublickeys(
      index,
      count,
      internal
    );
    return pubkeys;
  }

  public getAddresses(
    index: uint32_t,
    count: uint32_t,
    internal: boolean
  ): AddressArray {
    return this._subAccount.getAddresses(index, count, internal);
  }

  getCID(cid: AddressArray, index: uint32_t, count: size_t, internal: boolean) {
    // boost::mutex::scoped_lock scopedLock(lock);
    this._subAccount.getCID(cid, index, count, false);
  }

  getOwnerDepositAddress(): Address {
    // boost::mutex::scoped_lock scopedLock(lock);
    return Address.newWithPubKey(
      Prefix.PrefixDeposit,
      this._subAccount.ownerPubKey()
    );
  }

  getOwnerStakeAddress(): Address {
    let info = this._subAccount.getBasicInfo();
    let publicKeys: string[] | PublickeysInfo;
    if (info["Account"]["Type"] === "Standard") {
      publicKeys = this._subAccount.getPublickeys(0, 1, false) as string[];
      return Address.newWithPubKey(
        Prefix.PrefixDPoSV2,
        Buffer.from(publicKeys[0], "hex")
      );
    }

    publicKeys = this._subAccount.getPublickeys(0, 1, false) as PublickeysInfo;
    let pubKeys = [];
    let keys = publicKeys["pubkeys"][0]["all"];
    for (let i = 0; i < keys.length; i++) {
      pubKeys.push(Buffer.from(keys[i], "hex"));
    }

    return Address.newWithPubKeys(
      Prefix.PrefixDPoSV2,
      pubKeys,
      publicKeys["m"]
    );
  }

  getCROwnerDepositAddress(): Address {
    // boost::mutex::scoped_lock scopedLock(lock);
    return Address.newWithPubKey(
      Prefix.PrefixDeposit,
      this._subAccount.didPubKey()
    );
  }

  getOwnerAddress(): Address {
    // boost::mutex::scoped_lock scopedLock(lock);
    return Address.newWithPubKey(
      Prefix.PrefixStandard,
      this._subAccount.ownerPubKey()
    );
  }

  getAllSpecialAddresses(): AddressArray {
    let result: AddressArray;
    // boost::mutex::scoped_lock scopedLock(lock);
    if (this._subAccount.parent().getSignType() !== AccountSignType.MultiSign) {
      // Owner address
      result.push(
        Address.newWithPubKey(
          Prefix.PrefixStandard,
          this._subAccount.ownerPubKey()
        )
      );
      // Owner deposit address
      result.push(
        Address.newWithPubKey(
          Prefix.PrefixDeposit,
          this._subAccount.ownerPubKey()
        )
      );
      // CR Owner deposit address
      result.push(
        Address.newWithPubKey(
          Prefix.PrefixDeposit,
          this._subAccount.didPubKey()
        )
      );
    }

    return result;
  }

  getOwnerPublilcKey(): bytes_t {
    // boost::mutex::scoped_lock scopedLock(lock);
    return this._subAccount.ownerPubKey();
  }

  isDepositAddress(addr: Address): boolean {
    // boost::mutex::scoped_lock scopedLock(lock);
    if (this._subAccount.isProducerDepositAddress(addr)) {
      return true;
    }
    return this._subAccount.isCRDepositAddress(addr);
  }

  public getBasicInfo(): { Account: AccountBasicInfo } {
    return this._subAccount.getBasicInfo();
  }

  public getWalletID(): string {
    return this._walletID;
  }

  async signTransaction(tx: Transaction, payPassword: string) {
    await this._subAccount.signTransaction(tx, payPassword);
  }

  async signWithAddress(
    addr: Address,
    msg: string,
    payPasswd: string
  ): Promise<string> {
    // boost::mutex::scoped_lock scopedLock(lock);
    const privateKey: bytes_t | null = await this._subAccount.getKeyWithAddress(
      addr,
      payPasswd
    );

    if (privateKey) {
      let digest = SHA256.encodeToBuffer(Buffer.from(msg)).toString("hex");
      const signature = EcdsaSigner.sign(
        privateKey,
        Buffer.from(digest, "hex")
      );
      return signature.toString("hex");
    }
  }

  async signDigestWithAddress(
    addr: Address,
    digest: string,
    payPasswd: string
  ): Promise<string> {
    // boost::mutex::scoped_lock scopedLock(lock);
    const privateKey = await this._subAccount.getKeyWithAddress(
      addr,
      payPasswd
    );

    if (privateKey) {
      const signature = EcdsaSigner.sign(
        privateKey,
        Buffer.from(digest, "hex")
      );
      return signature.toString("hex");
    }
  }

  async signDigestWithCosignerIndex(
    index: number,
    digest: string,
    payPasswd: string
  ): Promise<string> {
    const privateKey = await this._subAccount.getPrivateKeyWithCosingerIndex(
      index,
      payPasswd
    );

    if (privateKey) {
      const signature = EcdsaSigner.sign(
        privateKey,
        Buffer.from(digest, "hex")
      );
      return signature.toString("hex");
    }
  }

  async signDigestWithPublicKeys(
    publicKeys: string[],
    digest: string,
    payPasswd: string
  ): Promise<string> {
    const privateKey = await this._subAccount.getPrivateKeyWithPublicKeys(
      publicKeys,
      payPasswd
    );

    if (privateKey) {
      const signature = EcdsaSigner.sign(
        privateKey,
        Buffer.from(digest, "hex")
      );
      return signature.toString("hex");
    }
  }

  async signWithOwnerKey(msg: bytes_t, payPasswd: string) {
    // boost::mutex::scoped_lock scopedLock(lock);
    const key = await this._subAccount.deriveOwnerKey(payPasswd);
    const digest = SHA256.encodeToBuffer(msg).toString("hex");

    return EcdsaSigner.sign(
      key.getPrivateKeyBytes(),
      Buffer.from(digest, "hex")
    );
  }

  async signDigestWithOwnerKey(digest: string, payPasswd: string) {
    const key = await this._subAccount.deriveOwnerKey(payPasswd);
    return EcdsaSigner.sign(
      key.getPrivateKeyBytes(),
      Buffer.from(digest, "hex")
    ).toString("hex");
  }

  protected loadUsedAddress() {}

  clearData() {
    // _database->ClearData();
  }
}
