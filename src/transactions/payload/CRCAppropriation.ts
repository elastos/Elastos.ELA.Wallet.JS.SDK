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

import { ByteStream } from "../../common/bytestream";
import { Log } from "../../common/Log";
import { uint8_t } from "../../types";
import { Payload } from "./Payload";

export class CRCAppropriation extends Payload {
  newFromCRCAppropriation(payload: CRCAppropriation) {
    const rs = new CRCAppropriation();
    return rs.copyCRCAppropriation(payload);
  }

  estimateSize(version: uint8_t) {
    return 0;
  }

  serialize(ostream: ByteStream, version: uint8_t) {}

  deserialize(istream: ByteStream, version: uint8_t): boolean {
    return true;
  }

  toJson(version: uint8_t) {
    return {};
  }

  fromJson(j = {}, version: uint8_t) {}

  copyPayload(payload: Payload) {
    try {
      const payloadCRCAppropriation = payload as CRCAppropriation;
      this.copyCRCAppropriation(payloadCRCAppropriation);
    } catch (e) {
      Log.error("payload is not instance of CRCAppropriation");
    }

    return this;
  }

  copyCRCAppropriation(payload: CRCAppropriation) {
    return this;
  }

  equals(payload: Payload, version: uint8_t): boolean {
    try {
      const p = payload as CRCAppropriation;
      return true;
    } catch (e) {
      Log.error("payload is not instance of CRCAppropriation");
    }

    return false;
  }
}
