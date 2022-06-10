// Copyright (c) 2012-2022 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

import { ByteStream } from "../../common/bytestream";
import { Log } from "../../common/Log";
import { size_t, uint8_t } from "../../types";
import { Payload } from "./Payload";

export class ReturnDepositCoin extends Payload {
  newFromPayload(payload: ReturnDepositCoin) {
    this.copyReturnDepositCoin(payload);
  }

  destroy() {}

  estimateSize(version: uint8_t): size_t {
    return 0;
  }

  serialize(ostream: ByteStream, version: uint8_t) {}

  deserialize(istream: ByteStream, version: uint8_t): boolean {
    return true;
  }

  toJson(version: uint8_t) {
    return {};
  }

  fromJson(j, version: uint8_t) {}

  copyPayload(payload: Payload) {
    try {
      const payloadReturnDepositCoin = payload as ReturnDepositCoin;
      this.copyReturnDepositCoin(payloadReturnDepositCoin);
    } catch (e) {
      Log.error("payload is not instance of ReturnDepositCoin");
    }

    return this;
  }

  copyReturnDepositCoin(payload: ReturnDepositCoin) {
    return this;
  }

  equals(payload: Payload, version: uint8_t): boolean {
    try {
      const p = payload as ReturnDepositCoin;
      return true;
    } catch (e) {
      Log.error("payload is not instance of ReturnDepositCoin");
    }

    return false;
  }
}
