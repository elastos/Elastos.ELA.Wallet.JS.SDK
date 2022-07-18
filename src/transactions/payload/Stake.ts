/*
 * Copyright (c) 2022 Elastos Foundation LTD.
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
import { Payload } from "./Payload";
import { uint8_t } from "../../types";
import { Log } from "../../common/Log";

export class Stake extends Payload {
  estimateSize(version: uint8_t) {
    return 0;
  }

  serialize(stream: ByteStream, version: uint8_t) {}

  deserialize(stream: ByteStream, version: uint8_t): boolean {
    return true;
  }

  toJson(version: uint8_t) {
    return {};
  }

  fromJson(j, version: uint8_t) {}

  isValid(version: uint8_t): boolean {
    return true;
  }

  copyPayload(payload: Payload) {
    try {
      let p = payload as Stake;
      this.copyStake(p);
    } catch (e) {
      Log.error("payload is not instance of Stake");
    }

    return this;
  }

  copyStake(payload: Stake) {
    return this;
  }

  equals(payload: Payload, version: uint8_t) {
    try {
      let p = payload as Stake;
    } catch (e) {
      Log.error("payload is not instance of Stake");
      return false;
    }

    return true;
  }
}
