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
import { Provider } from "@ethersproject/abstract-provider";
import { UnsignedTransaction } from "@ethersproject/transactions";
import { Buffer } from "buffer";
import { BigNumber, ethers } from "ethers";
import { Account } from "../account/Account";
import { Error, ErrorChecker } from "../common/ErrorChecker";
import { ChainConfig } from "../config";
import { json, JSONArray, uint32_t, uint64_t } from "../types";
import { CoinInfo } from "../walletcore/CoinInfo";
import { HDKey, KeySpec } from "../walletcore/hdkey";
import { Secp256 } from "../walletcore/secp256";
import { EthereumNetworkRecord, EthereumNetworks } from "./EthereumNetwork";
import { EthereumWallet } from "./EthereumWallet";
import {
  EthereumAmountUnit, IEthSidechainSubWallet
} from "./IEthSidechainSubWallet";
import { MasterWallet } from "./MasterWallet";
import { SubWallet } from "./SubWallet";

export class EthSidechainSubWallet
  extends SubWallet
  implements IEthSidechainSubWallet {
  private _wallet: EthereumWallet;
  private _provider: Provider;

  constructor(
    info: CoinInfo,
    config: ChainConfig,
    parent: MasterWallet,
    netType: string,
    jsonRPC: string
  ) {
    super(info, config, parent);
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

    this._wallet = new EthereumWallet(net, pubkey);
    this._wallet.setDefaultGasPrice(BigNumber.from("5000000000"));

    // Must create a provider otherwise we cann't use the 'populateTransaction' api of ethers.js
    // The RPC of ETHSidechain testnet: https://api-testnet.trinity-tech.io/esc
    this._provider = new ethers.providers.JsonRpcProvider(jsonRPC);
  }

  destroy() { }

  private async getRawTx(transaction) {
    const wallet = ethers.Wallet.createRandom();
    const signer = wallet.connect(this._provider);

    const unsignedTx = (await signer.populateTransaction(
      transaction
    )) as UnsignedTransaction;

    const rawtx = ethers.utils.serializeTransaction(unsignedTx);
    return rawtx;
  }

  private getUnit(etherUnit: EthereumAmountUnit) {
    switch (etherUnit) {
      case EthereumAmountUnit.ETHER_GWEI:
        return "gwei";
      case EthereumAmountUnit.ETHER_ETHER:
        return "ether";
      default:
        return "wei";
    }
  }

  async createTransfer(
    targetAddress: string,
    amount: string,
    amountUnit: EthereumAmountUnit,
    gasPrice: string,
    gasPriceUnit: EthereumAmountUnit,
    gasLimit: string,
    nonce: uint64_t
  ): Promise<json> {
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

    let amtUnit: string = this.getUnit(amountUnit);
    let gasUnit: string = this.getUnit(gasPriceUnit);
    let j: json;

    let transaction = {
      to: targetAddress,
      value: ethers.utils.parseUnits(amount, amtUnit),
      gasLimit,
      gasPrice: ethers.utils.parseUnits(gasPrice, gasUnit),
      nonce: nonce.toNumber(),
      type: 1 // pre-eip-1559 transaction
    };
    const rawtx = await this.getRawTx(transaction);

    j["TxUnsigned"] = rawtx;
    const gasAmount = BigNumber.from(gasLimit).mul(gasPrice).toString();
    // The Fee unit is wei
    j["Fee"] = ethers.utils.parseUnits(gasAmount, gasUnit).toString();
    j["Unit"] = amountUnit;

    return j;
  }

  async createTransferGeneric(
    targetAddress: string,
    amount: string,
    amountUnit: EthereumAmountUnit,
    gasPrice: string,
    gasPriceUnit: EthereumAmountUnit,
    gasLimit: string,
    data: string,
    nonce: uint64_t
  ): Promise<json> {
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

    let unit: string = this.getUnit(amountUnit);
    let gasUnit: string = this.getUnit(gasPriceUnit);
    let j: json;

    let transaction = {
      to: targetAddress,
      value: ethers.utils.parseUnits(amount, unit),
      gasLimit,
      gasPrice: ethers.utils.parseUnits(gasPrice, gasUnit),
      nonce: nonce.toNumber(),
      type: 1, // pre-eip-1559 transaction
      data
    };
    const rawtx = await this.getRawTx(transaction);

    j["TxUnsigned"] = rawtx;
    const gasAmount = BigNumber.from(gasLimit).mul(gasPrice).toString();
    // the Fee unit is wei
    j["Fee"] = ethers.utils.parseUnits(gasAmount, gasUnit).toString();
    j["Unit"] = EthereumAmountUnit.ETHER_WEI;
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

  getAddresses(index: uint32_t, count: uint32_t, internal: boolean): string[] {
    let addr: string = this._wallet.getPrimaryAddress();
    let j: string[] = [];
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

  async signTransaction(tx: json, passwd: string) {
    let rlptx: string;
    let amountUnit: EthereumAmountUnit;
    let transaction: UnsignedTransaction;
    try {
      rlptx = tx["TxUnsigned"] as string;
      amountUnit = tx["Unit"] as EthereumAmountUnit;

      // get the unsigned transaction
      transaction = ethers.utils.parseTransaction(rlptx);
      console.log("unsigned transaction", transaction);
    } catch (e) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "get 'ID' of json failed"
      );
    }

    const key: HDKey = this.getPrivateKey(passwd);
    // use private key to create a wallet
    let privateKey = key.getPrivateKeyBytes().toString();
    const wallet = new ethers.Wallet(privateKey);
    const rawtx = await wallet.signTransaction(transaction);

    let j: json;
    j["Hash"] = rlptx;
    const gasAmount = BigNumber.from(transaction.gasLimit)
      .mul(transaction.gasPrice)
      .toString();
    j["Fee"] = ethers.utils
      .parseUnits(gasAmount, this.getUnit(amountUnit))
      .toString();
    j["Unit"] = amountUnit;
    j["TxSigned"] = rawtx;
    return j;
  }

  signDigest(address: string, digest: string, passwd: string): Promise<string> {
    const addr: string = this._wallet.getPrimaryAddress();
    ErrorChecker.checkParam(
      addr != address,
      Error.Code.InvalidArgument,
      "Invalid address"
    );

    const k = this.getPrivateKey(passwd);
    const curve = new Secp256(Secp256.CURVE_K1);
    const sig = curve.sign(Buffer.from(digest), k.getPrivateKeyBytes());
    return Promise.resolve(sig.signature.toString("hex"));
  }

  verifyDigest(pubkey: string, digest: string, signature: string): boolean {
    const curve = new Secp256(Secp256.CURVE_K1);
    return curve.verify(
      Buffer.from(digest),
      Buffer.from(signature),
      Buffer.from(pubkey)
    );
  }

  private getPrivateKey(passwd: string): HDKey {
    let k: HDKey;
    let seed: Buffer = this._parent.getAccount().getSeed(passwd);
    if (seed.length !== 0) {
      seed = this._parent.getAccount().getSeed(passwd);
      let masterKey: HDKey = HDKey.fromMasterSeed(
        seed,
        KeySpec.Ethereum
      ).deriveWithPath("m/44'/60'/0'/0/0");
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
      k = HDKey.deserialize(ethprvkey, KeySpec.Ethereum);
    }
    return k;
  }
}
