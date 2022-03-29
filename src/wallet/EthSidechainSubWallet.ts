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

import { BigNumber, ethers } from "ethers";
import { MasterWallet } from "./MasterWallet";
import { CoinInfo } from "../walletcore/CoinInfo";
import { Log } from "../common/Log";
import {
  IEthSidechainSubWallet,
  EthereumAmountUnit,
  EthereumAmountType
} from "./IEthSidechainSubWallet";
import { SubWallet } from "./SubWallet";
import { uint64_t, json, uint32_t, JSONArray } from "../types";
import { ErrorChecker, Error } from "../common/ErrorChecker";
import { DeterministicKey } from "../walletcore/deterministickey";
import { HDKey, KeySpec } from "../walletcore/hdkey";
import { ChainConfig } from "../Config";
import { Account } from "../account/Account";
import {
  EthereumNetwork,
  EthereumNetworks,
  EthereumNetworkRecord
} from "./EthereumNetwork";
import { EthereumWallet } from "./EthereumWallet";

namespace EthereumAmount {
  export enum Unit {
    // TOKEN_DECIMAL = 0,
    // TOKEN_INTEGER = 1,

    ETHER_WEI = 0,
    ETHER_GWEI = 3,
    ETHER_ETHER = 6
  }
}

export class EthSidechainSubWallet
  extends SubWallet
  implements IEthSidechainSubWallet
{
  private _wallet: EthereumWallet;

  constructor(
    info: CoinInfo,
    config: ChainConfig,
    parent: MasterWallet,
    netType: string
  ) {
    super();
    let account: Account = this._parent.getAccount();
    let pubkey = account.getETHSCPubKey();
    if (pubkey.length === 0) {
      if (!account.hasMnemonic() || account.readonly()) {
        ErrorChecker.throwParamException(
          Error.Code.UnsupportOperation,
          "unsupport operation: ethsc pubkey is empty"
        );
      } else {
        ErrorChecker.throwParamException(
          Error.Code.Other,
          "need to call IMasterWallet::VerifyPayPassword() or re-import wallet first"
        );
      }
    }

    const netName: string = info.getChainID() + "-" + netType;
    const net: EthereumNetworkRecord | null =
      EthereumNetworks.findEthereumNetwork(netName);
    ErrorChecker.checkParam(
      net === null,
      Error.Code.InvalidArgument,
      "network config not found"
    );

    // EthereumNetworkPtr network(new EthereumNetwork(net));
    // this._client = new EthereumClient(network, parent->GetDataPath(), pubkey);
    // this._client->_ewm->getWallet()->setDefaultGasPrice(5000000000);

    this._wallet = new EthereumWallet(net, pubkey);
    this._wallet.setDefaultGasPrice(BigNumber.from("5000000000"));
  }

  destroy() {}

  createTransfer(
    targetAddress: string,
    amount: string,
    amountUnit: EthereumAmountUnit,
    gasPrice: string,
    gasPriceUnit: EthereumAmountUnit,
    gasLimit: string,
    nonce: uint64_t
  ) {
    // ArgInfo("{} {}", GetSubWalletID(), GetFunName());
    // ArgInfo("target: {}", targetAddress);
    // ArgInfo("amount: {}", amount);
    // ArgInfo("amountUnit: {}", amountUnit);
    // ArgInfo("nonce: {}", nonce);

    if (
      amountUnit != EthereumAmountUnit.ETHER_WEI &&
      amountUnit != EthereumAmountUnit.ETHER_GWEI &&
      amountUnit != EthereumAmountUnit.ETHER_ETHER
    ) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "invalid amount amtUnit"
      );
    }

    let amtUnit: EthereumAmountUnit = amountUnit;
    let gasUnit: EthereumAmountUnit = gasPriceUnit;
    let j: json;

    // EthereumTransferPtr tx = _client->_ewm->getWallet()->createTransfer(targetAddress, amount, amtUnit, gasPrice, gasUnit, gasLimit, nonce);

    // let rawtx: string = tx->RlpEncode(_client->_ewm->getNetwork()->getRaw(), RLP_TYPE_TRANSACTION_UNSIGNED);

    // j["TxUnsigned"] = rawtx;
    // j["Fee"] = tx->getFee(amtUnit);
    // j["Unit"] = tx->getDefaultUnit();

    // ArgInfo("r => {}", j.dump());

    // return j;
    return {};
  }

  createTransferGeneric(
    targetAddress: string,
    amount: string,
    amountUnit: EthereumAmountUnit,
    gasPrice: string,
    gasPriceUnit: EthereumAmountUnit,
    gasLimit: string,
    data: string,
    nonce: uint64_t
  ): json {
    // ArgInfo("{} {}", GetSubWalletID(), GetFunName());
    // ArgInfo("target: {}", targetAddress);
    // ArgInfo("amount: {}", amount);
    // ArgInfo("amountUnit: {}", amountUnit);
    // ArgInfo("gasPrice: {}", gasPrice);
    // ArgInfo("gasPriceUnit: {}", gasPriceUnit);
    // ArgInfo("gasLimit: {}", gasLimit);
    // ArgInfo("data: {}", data);
    // ArgInfo("nonce: {}", nonce);

    if (
      amountUnit != EthereumAmountUnit.ETHER_WEI &&
      amountUnit != EthereumAmountUnit.ETHER_GWEI &&
      amountUnit != EthereumAmountUnit.ETHER_ETHER
    ) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "invalid amount unit"
      );
    }

    let unit: EthereumAmountUnit = amountUnit;
    let gasUnit: EthereumAmountUnit = gasPriceUnit;
    let j: json;
    // EthereumTransferPtr tx = _client->_ewm->getWallet()->createTransferGeneric(targetAddress,amount,unit,gasPrice,gasUnit,gasLimit,data,nonce);

    // std::string rawtx = tx->RlpEncode(_client->_ewm->getNetwork()->getRaw(), RLP_TYPE_TRANSACTION_UNSIGNED);

    // j["TxUnsigned"] = rawtx;
    // j["Fee"] = tx->getFee(unit);
    // j["Unit"] = tx->getDefaultUnit();

    // ArgInfo("r => {}", j.dump());

    return j;
  }

  exportPrivateKey(payPassword: string) {
    // ArgInfo("{} {}", GetSubWalletID(), GetFunName());
    // ArgInfo("payPasswd: *");
    let k: HDKey = this.getPrivateKey(payPassword);
    const prvkeystring: string = k.getPrivateKeyBytes().toString();
    // ArgInfo("r => *");
    return prvkeystring;
  }

  getBasicInfo(): json {
    let j: json;
    let jinfo: json;

    jinfo["Symbol"] = this._wallet.getSymbol();
    jinfo["GasLimit"] = this._wallet.getDefaultGasLimit().toString();
    jinfo["GasPrice"] = this._wallet.getDefaultGasPrice().toString();
    jinfo["Account"] = this._wallet.getPrimaryAddress();
    jinfo["HoldsEther"] = this._wallet.walletHoldsEther();

    j["Info"] = jinfo;
    j["ChainID"] = this._wallet.getChainID();

    return j;
  }

  getAddresses(index: uint32_t, count: uint32_t, internal: boolean): JSONArray {
    let addr: string = this._wallet.getPrimaryAddress();
    let j: JSONArray;
    j.push(addr);
    return j;
  }

  getPublicKeys(
    index: uint32_t,
    count: uint32_t,
    internal: boolean
  ): JSONArray {
    let pubkey: string = this._wallet.getPrimaryAddressPublicKey();
    let j: JSONArray;
    j.push(pubkey);
    return j;
  }

  signTransaction(tx: json, passwd: string): json {
    // ArgInfo("{} {}", GetSubWalletID(), GetFunName());
    // ArgInfo("tx: {}", tx.dump());
    // ArgInfo("passwd: *");
    /*
			let rlptx: string;
			EthereumTransferPtr transfer;
      let amountUnit: EthereumAmount.Unit;

			try {
				rlptx = tx["TxUnsigned"] as string;
        amountUnit = EthereumAmount::Unit(tx["Unit"].get<int>());

        BREthereumTransaction transaction = transactionRlpHexDecode (_client->_ewm->getNetwork()->getRaw(), RLP_TYPE_TRANSACTION_UNSIGNED, rlptx.c_str());
        BREthereumTransfer brtransfer = transferCreateWithTransactionOriginating (
          transaction,
          (_client->_ewm->getWallet()->walletHoldsEther()
            ? TRANSFER_BASIS_TRANSACTION
            : TRANSFER_BASIS_LOG)
        );
        transfer = EthereumTransferPtr(new EthereumTransfer(_client->_ewm.get(), brtransfer, amountUnit));
			} catch (const std::exception &e) {
				ErrorChecker::ThrowParamException(Error::InvalidArgument, "get 'ID' of json failed");
			}

      BRKey prvkey = GetBRPrivateKey(passwd);
			_client->_ewm->getWallet()->signWithPrivateKey(transfer, prvkey);

      std::string rawtx = transfer->RlpEncode(_client->_ewm->getNetwork()->getRaw(), RLP_TYPE_TRANSACTION_SIGNED);
			nlohmann::json j;
			j["Hash"] = transfer->getOriginationTransactionHash();
			j["Fee"] = transfer->getFee(amountUnit);
			j["Unit"] = amountUnit;
      j["TxSigned"] = rawtx;

			ArgInfo("r => {}", j.dump());
			return j;
    */
  }

  signDigest(address: string, digest: string, passwd: string): string {
    const addr: string = this._wallet.getPrimaryAddress();
    ErrorChecker.checkParam(
      addr != address,
      Error.Code.InvalidArgument,
      "Invalid address"
    );

    // Key k = GetPrivateKey(passwd);
    // std::string sig = k.SignDER(uint256(digest)).getHex();

    // return sig;
  }

  verifyDigest(pubkey: string, digest: string, signature: string): boolean {
    // Key k(CTBitcoin, pubkey);
    // bool r = k.VerifyDER(uint256(digest), signature);
    // ArgInfo("r => {}", r);
    // return r;
  }

  private getPrivateKey(passwd: string): HDKey {
    let k: HDKey;
    let seed: Buffer = this._parent.getAccount().getSeed(passwd);
    if (seed.length !== 0) {
      seed = this._parent.getAccount().getSeed(passwd);
      let masterKey: HDKey = HDKey.fromMasterSeed(
        seed,
        KeySpec.Bitcoin
      ).deriveWithPath("44'/60'/0'/0/0");
      k = masterKey;
    } else {
      let ethprvkey: Buffer = this._parent
        .getAccount()
        .getSinglePrivateKey(passwd);
      ErrorChecker.checkParam(
        ethprvkey.length != 32,
        Error.Code.Sign,
        "private key not found"
      );
      k = HDKey.deserialize(ethprvkey, KeySpec.Bitcoin);
    }
    return k;
  }
}
