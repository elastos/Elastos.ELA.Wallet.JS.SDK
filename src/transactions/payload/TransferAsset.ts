// Copyright (c) 2012-2022 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

import { ByteStream } from "../../common/bytestream";
import { json, size_t, uint8_t } from "../../types";
import { Payload } from "./Payload";
import { Log } from "../../common/Log";

export class TransferAsset extends Payload {
  newFromTransferAsset(payload: TransferAsset) {
    return this.copyTransferAsset(payload);
  }

  public estimateSize(version: uint8_t): size_t {
    return 0;
  }

  public serialize(ostream: ByteStream, version: uint8_t) {}

  public eserialize(istream: ByteStream, version: uint8_t): boolean {
    return true;
  }

  public toJson(version: uint8_t): json {
    return {};
  }

  public fromJson(j: json, version: uint8_t) {}

  copyPayload(payload: Payload) {
    try {
      const payloadTransferAsset = payload as TransferAsset;
      this.copyTransferAsset(payloadTransferAsset);
    } catch (e) {
      Log.error("payload is not instance of TransferAsset");
    }

    return this;
  }

  copyTransferAsset(payload: TransferAsset): TransferAsset {
    return this;
  }

  public equals(payload: Payload, version: uint8_t): boolean {
    return payload instanceof TransferAsset;
  }
}
