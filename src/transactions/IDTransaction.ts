// Copyright (c) 2012-2019 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
import { Log } from "../common/Log";
import { Payload } from "./payload/Payload";
import { Transaction, TxVersion } from "./Transaction";
import { ByteStream } from "../common/bytestream";
import { uint8_t } from "../types";

export const registerIdentification = 0x09; // deprecated
export const didTransaction = 0x0a;

export class IDTransaction extends Transaction {
  constructor() {
    super();
  }

  newFromParams(type: uint8_t, payload: Payload) {
    Transaction.newFromParams(type, payload);
  }

  newFromIDTransaction(tx: IDTransaction): IDTransaction {
    Transaction.newFromTransaction(tx);
    return this;
  }

  initPayload(type: uint8_t): Payload {
    let payload: Payload;

    if (registerIdentification == type) {
      // deprecated
      // payload = new RegisterIdentification();
    } else if (didTransaction == type) {
      // TODO
      // payload = new DIDInfo();
    } else {
      const transaction = new Transaction();
      payload = transaction.initPayload(type);
    }

    return payload;
  }

  deserializeType(istream: ByteStream): boolean {
    this._type = istream.readByte();
    if (this._type === null) {
      Log.error("deserialize flag byte error");
      return false;
    }
    this._version = TxVersion.Default;

    return true;
  }

  getIDTxTypes() {
    return { didTransaction };
  }
}
