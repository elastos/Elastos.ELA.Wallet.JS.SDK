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

import { UTXOInput, UTXOSet } from "./UTXO";
import { CoinInfo } from "../walletcore/CoinInfo";
import { ChainConfig } from "../config";
import { MasterWallet } from "./MasterWallet";
import { ElastosBaseSubWallet } from "./ElastosBaseSubWallet";
import { ErrorChecker, Error } from "../common/ErrorChecker";
import { BigNumber } from "bignumber.js";
import { EncodedTx } from "./IElastosBaseSubWallet";
import {
  OutputArray,
  TransactionOutput
} from "../transactions/TransactionOutput";
import { Payload } from "../transactions/payload/Payload";
import {
  TransferInfo,
  TransferCrossChainAsset
} from "../transactions/payload/TransferCrossChainAsset";
import { TransactionType } from "../transactions/Transaction";
import { DEPOSIT_MIN_ELA } from "./MainchainSubWallet";
import { ELA_SIDECHAIN_DESTROY_ADDR, Address } from "../walletcore/Address";
import { DEPOSIT_OR_WITHDRAW_FEE } from "./SubWallet";

export class SidechainSubWallet extends ElastosBaseSubWallet {
  constructor(
    info: CoinInfo,
    config: ChainConfig,
    parent: MasterWallet,
    netType?: string
  ) {
    super(info, config, parent, netType);
  }

  createWithdrawTransaction(
    inputs: UTXOInput[],
    amount: string,
    mainChainAddress: string,
    fee: string,
    memo: string
  ) {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", wallet->GetWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputsJson.dump());
    // ArgInfo("amount: {}", amount);
    // ArgInfo("mainChainAddr: {}", mainChainAddress);
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo = new UTXOSet();
    this.UTXOFromJson(utxo, inputs);

    ErrorChecker.checkBigIntAmount(amount);
    let bgAmount = new BigNumber(amount);
    let minAmount = new BigNumber(DEPOSIT_MIN_ELA);
    let feeAmount = new BigNumber(fee);

    let payload: Payload;
    try {
      let info = TransferInfo.newFromParams(mainChainAddress, 0, bgAmount);
      payload = TransferCrossChainAsset.newFromParams([info]);
    } catch (e) {
      ErrorChecker.throwParamException(
        Error.Code.JsonFormatError,
        "main chain message error: " + e
      );
    }

    let outputs: OutputArray = [];
    outputs.push(
      TransactionOutput.newFromParams(
        bgAmount.plus(DEPOSIT_OR_WITHDRAW_FEE),
        Address.newFromAddressString(ELA_SIDECHAIN_DESTROY_ADDR)
      )
    );

    let tx = wallet.createTransaction(
      TransactionType.transferCrossChainAsset,
      payload,
      utxo,
      outputs,
      memo,
      feeAmount
    );

    let result = <EncodedTx>{};
    this.encodeTx(result, tx);

    // ArgInfo("r => {}", result.dump());
    return result;
  }
}
