// Copyright (c) 2012-2018 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
import BigNumber from "bignumber.js";
import { TransactionInput } from "../transactions/TransactionInput";
import { INT32_MAX, uint16_t, uint256 } from "../types";
import { Address } from "../walletcore/Address";

export type UTXOArray = UTXO[];

const TX_UNCONFIRMED = INT32_MAX;

export class UTXO {
  protected _address: Address;
  protected _amount: BigNumber;
  protected _hash: uint256;
  protected _n: uint16_t = 0;

  public static newFromUTXO(u: UTXO): UTXO {
    let utxo = new UTXO();
    utxo._address = u._address;
    utxo._amount = u._amount;
    utxo._hash = u._hash;
    utxo._n = u._n;
    return utxo;
  }

  public static newFromParams(
    hash: uint256,
    n: uint16_t,
    address: Address,
    amount: BigNumber
  ): UTXO {
    let utxo = new UTXO();
    utxo._hash = hash;
    utxo._n = n;
    utxo._address = address;
    utxo._amount = amount;
    return utxo;
  }

  public hash(): uint256 {
    return this._hash;
  }

  public setHash(hash: uint256) {
    this._hash = hash;
  }

  public index(): uint16_t {
    return this._n;
  }

  public setIndex(index: uint16_t) {
    this._n = index;
  }

  public getAddress(): Address {
    return this._address;
  }

  public setAddress(address: Address) {
    this._address = address;
  }

  public getAmount(): BigNumber {
    return this._amount;
  }

  public setAmount(amount: BigNumber) {
    this._amount = amount;
  }

  public equalsInput(input: TransactionInput): boolean {
    // WAS Equal(InputPtr)
    return this._hash.eq(input.txHash()) && this._n == input.index();
  }

  public equals(hash: uint256, index: uint16_t): boolean {
    // WAS Equals
    return this._hash.eq(hash) && index == this._n;
  }

  public equalsUTXO(utxo: UTXO): boolean {
    return this.equals(utxo.hash(), utxo.index());
  }
}

/**
 * Array of UTXO, always sorted
 */
export class UTXOSet extends Array<UTXO> {
  public sortUTXOs() {
    this.sort((x, y) => {
      if (x.hash().eq(y.hash())) {
        return x.index() - y.index();
      } else {
        return x.hash().minus(y.hash()).toNumber();
      }
    });
  }
}
