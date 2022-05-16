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
import BigNumber from "bignumber.js";
import { JSONArray } from "../types";
import { InvalidArgumentException } from "./exceptions/invalidargument.exception";
import { LogicErrorException } from "./exceptions/logic.exception";
import { Log } from "./Log";

const MIN_PASSWORD_LENGTH = 8;
const MAX_PASSWORD_LENGTH = 128;

export namespace Error {
  export enum Code {
    InvalidArgument = 20001,
    InvalidPasswd = 20002,
    WrongPasswd = 20003,
    IDNotFound = 20004,
    CreateMasterWalletError = 20005,
    CreateSubWalletError = 20006,
    JsonArrayError = 20007,
    Mnemonic = 20008,
    PubKeyFormat = 20009,
    PubKeyLength = 20010,
    DepositParam = 20011,
    WithdrawParam = 20012,
    CreateTransactionExceedSize = 20013,
    CreateTransaction = 20014,
    Transaction = 20015,
    PathNotExist = 20016,
    PayloadRegisterID = 20017,
    SqliteError = 20018,
    DerivePurpose = 20019,
    WrongAccountType = 20020,
    WrongNetType = 20021,
    InvalidCoinType = 20022,
    NoCurrentMultiSinAccount = 20023,
    MultiSignersCount = 20024,
    MultiSign = 20025,
    KeyStore = 20026,
    LimitGap = 20027,
    Wallet = 20028,
    Key = 20029,
    HexString = 20030,
    SignType = 20031,
    Address = 20032,
    Sign = 20033,
    KeyStoreNeedPhrasePassword = 20034,
    BalanceNotEnough = 20035,
    JsonFormatError = 20036,
    VoteStakeError = 20037,
    GetTransactionInput = 20038,
    InvalidTransaction = 20039,
    GetUnusedAddress = 20040,
    AccountNotSupportVote = 20041,
    WalletNotContainTx = 20042,
    DepositAmountInsufficient = 20043,
    PrivateKeyNotFound = 20044,
    InvalidRedeemScript = 20045,
    AlreadySigned = 20046,
    EncryptError = 20047,
    VerifyError = 20048,
    TxPending = 20049,
    InvalidMnemonicWordCount = 20050,
    InvalidLocalStore = 20051,
    MasterWalletNotExist = 20052,
    InvalidAsset = 20053,
    ReadConfigFileError = 20054,
    InvalidChainID = 20055,
    UnSupportOldTx = 20056,
    UnsupportOperation = 20057,
    BigInt = 20058,
    DepositNotFound = 20059,
    TooMuchInputs = 20060,
    LastVoteConfirming = 20061,
    ProposalContentTooLarge = 20062,
    ProposalHashNotMatch = 20063,
    // ethereum side chain error code
    InvalidUnitType = 31000,
    InvalidEthereumAddress = 32000,
    Other = 29999
  }
}

export type Error = {
  Code: Error.Code;
  Message: string;
  Data?: BigNumber;
};

export namespace Exception {
  export enum Type {
    LogicError,
    InvalidArgument
  }
}

export class ErrorChecker {
  private static makeErrorJson(
    err: Error.Code,
    msg: string,
    data?: BigNumber
  ): Error {
    return {
      Code: err,
      Message: msg,
      Data: data
    };
  }

  public static throwParamException(err: Error.Code, msg: string) {
    this.checkParam(true, err, msg);
  }

  public static throwLogicException(err: Error.Code, msg: string) {
    this.checkLogic(true, err, msg);
  }

  public static checkParam(condition: boolean, err: Error.Code, msg: string) {
    this.checkCondition(condition, err, msg, Exception.Type.InvalidArgument);
  }

  public static checkBigIntAmount(amount: string) {
    const number = new BigNumber(amount);
    this.checkCondition(
      !number.isInteger(),
      Error.Code.InvalidArgument,
      "invalid bigint amount: " + amount
    );
  }

  public static checkLogic(condition: boolean, err: Error.Code, msg: string) {
    this.checkCondition(condition, err, msg, Exception.Type.LogicError);
  }

  public static checkCondition(
    condition: boolean,
    err: Error.Code,
    msg: string,
    type: Exception.Type = Exception.Type.LogicError,
    enableLog = true
  ) {
    if (condition) {
      let errJson = this.makeErrorJson(err, msg);

      if (enableLog) Log.error(errJson);

      if (type == Exception.Type.LogicError) {
        throw new LogicErrorException(err, msg);
      } else if (type == Exception.Type.InvalidArgument) {
        throw new InvalidArgumentException(err, msg);
      }
    }
  }

  public static checkPassword(password: string, msg: string) {
    this.checkCondition(
      password.length < MIN_PASSWORD_LENGTH,
      Error.Code.InvalidPasswd,
      msg + " password invalid: less than " + MIN_PASSWORD_LENGTH.toString(),
      Exception.Type.InvalidArgument
    );

    this.checkCondition(
      password.length > MAX_PASSWORD_LENGTH,
      Error.Code.InvalidPasswd,
      msg + " password invalid: more than " + MAX_PASSWORD_LENGTH.toString(),
      Exception.Type.InvalidArgument
    );
  }

  public static checkPasswordWithNullLegal(password: string, msg: string) {
    if (password.length === 0) return;
    this.checkPassword(password, msg);
  }

  public static checkParamNotEmpty(argument: string, msg: string) {
    this.checkCondition(
      argument.length === 0,
      Error.Code.InvalidArgument,
      msg + " should not be empty",
      Exception.Type.InvalidArgument
    );
  }

  public static checkJsonArray(
    jsonData: JSONArray,
    count: number,
    msg: string
  ) {
    this.checkCondition(
      jsonData.length < count,
      Error.Code.JsonArrayError,
      msg + " json array size expect at least " + count.toString(),
      Exception.Type.LogicError
    );
  }

  /*
    void ErrorChecker::CheckPathExists(const boost::filesystem::path &path, bool enableLog) {
      CheckCondition(!boost::filesystem::exists(path), Error::PathNotExist,
                     "Path '" + path.string() + "' do not exist", Exception::LogicError, enableLog);
    }
  */

  public static checkPrivateKey(key: string) {
    // TODO fix here later
    this.checkCondition(
      key.includes("xprv"),
      Error.Code.InvalidArgument,
      "Private key is not support xprv"
    );

    this.checkCondition(
      key.length != 32 * 2,
      Error.Code.InvalidArgument,
      "Private key length should be 32 bytes"
    );
  }

  public static checkInternetDate(date: string) {
    const reg = new RegExp(
      /(\\d{4})-(0\\d{1}|1[0-2])-(0\\d{1}|[12]\\d{1}|3[01])T(0\\d{1}|1\\d{1}|2[0-3]):[0-5]\\d{1}:([0-5]\\d{1}Z)/
    );
    this.checkParam(
      !reg.test(date),
      Error.Code.InvalidArgument,
      "date format is error. such as 2019-01-01T19:20:18Z"
    );
  }
}
