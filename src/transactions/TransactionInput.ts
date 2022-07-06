// Copyright (c) 2012-2022 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying

import BigNumber from "bignumber.js";
import { ByteStream } from "../common/bytestream";
import { JsonSerializer } from "../common/JsonSerializer";
import { Log } from "../common/Log";
import { ELAMessage } from "../ELAMessage";
import { size_t, uint16_t, uint256, uint32_t } from "../types";

export type InputPtr = TransactionInput;
export type InputArray = InputPtr[];

export type TransactionInputInfo = {
  TxHash: string;
  Index: number;
  Sequence: number;
};

export class TransactionInput extends ELAMessage implements JsonSerializer {
  private _txHash: uint256;
  private _index: uint16_t = 0;
  private _sequence: uint32_t = 0;

  public static newFromTransactionInput(
    input: TransactionInput
  ): TransactionInput {
    return TransactionInput.newFromParams(
      input._txHash,
      input._index,
      input._sequence
    );
  }

  public static newFromParams(
    txHash: uint256,
    index: uint16_t,
    sequence = 0
  ): TransactionInput {
    let transactionInput = new TransactionInput();
    transactionInput._txHash = txHash;
    transactionInput._index = index;
    transactionInput._sequence = sequence;
    return transactionInput;
  }

  public txHash(): uint256 {
    return this._txHash;
  }

  public setTxHash(hash: uint256) {
    this._txHash = hash;
  }

  public index(): uint16_t {
    return this._index;
  }

  public setIndex(index: uint16_t) {
    this._index = index;
  }

  public sequence(): uint32_t {
    return this._sequence;
  }

  public setSequence(sequence: uint32_t) {
    this._sequence = sequence;
  }

  public getSize(): size_t {
    return 32 + 2 + 4;
  }

  public equals(ti: TransactionInput): boolean {
    let equal =
      this._txHash.eq(ti._txHash) &&
      this._index == ti._index &&
      this._sequence == ti._sequence;

    return equal;
  }

  public estimateSize(): size_t {
    let size: size_t = 0;

    size += 32;
    size += 2;
    size += 4;

    return size;
  }

  public serialize(stream: ByteStream) {
    stream.writeBNAsUIntOfSize(this._txHash, 32);
    stream.writeUInt16(this._index);
    stream.writeUInt32(this._sequence);
  }

  public deserialize(stream: ByteStream): boolean {
    this._txHash = stream.readUIntOfBytesAsBN(32);
    if (this._txHash === null) {
      Log.error("deser input txHash");
      return false;
    }

    this._index = stream.readUInt16();
    if (this._index === null) {
      Log.error("deser input index");
      return false;
    }

    this._sequence = stream.readUInt32();
    if (this._sequence === null) {
      Log.error("deser input sequence");
      return false;
    }

    return true;
  }

  public toJson(): TransactionInputInfo {
    return {
      TxHash: this._txHash.toString(16),
      Index: this._index,
      Sequence: this._sequence
    };
  }

  public fromJson(j: TransactionInputInfo): TransactionInput {
    this._txHash = new BigNumber(j["TxHash"], 16);
    this._index = j["Index"];
    this._sequence = j["Sequence"];
    return this;
  }
}
