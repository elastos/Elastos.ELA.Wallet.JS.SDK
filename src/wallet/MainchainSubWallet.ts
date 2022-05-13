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
import { Buffer } from "buffer";
import BigNumber from "bignumber.js";
import { ElastosBaseSubWallet } from "./ElastosBaseSubWallet";
import {
  json,
  JSONArray,
  uint8_t,
  uint64_t,
  size_t,
  bytes_t,
  uint256,
  JSONObject
} from "../types";
import { CoinInfo } from "../walletcore/CoinInfo";
import { MasterWallet } from "./MasterWallet";
import { ChainConfig } from "../Config";
import { Wallet } from "./Wallet";
import { UTXOSet } from "./UTXO";
import { Error, ErrorChecker } from "../common/ErrorChecker";
import {
  CHAINID_MAINCHAIN,
  CHAINID_IDCHAIN,
  CHAINID_TOKENCHAIN
} from "./WalletCommon";
import { Address, Prefix } from "../walletcore/Address";
import {
  TransferCrossChainVersion,
  TransferCrossChainVersionV1,
  TransferInfo,
  TransferCrossChainAsset
} from "../transactions/payload/TransferCrossChainAsset";
import {
  OutputArray,
  TransactionOutput,
  Type
} from "../transactions/TransactionOutput";
import { Asset } from "../transactions/Asset";
import { Transaction, TransactionType } from "../transactions/Transaction";
import { DEPOSIT_OR_WITHDRAW_FEE, SELA_PER_ELA } from "./SubWallet";
import {
  PayloadCrossChain,
  CrossChainOutputVersion
} from "../transactions/payload/OutputPayload/PayloadCrossChain";
import { Payload } from "../transactions/payload/Payload";
import { TransferAsset } from "../transactions/payload/TransferAsset";
import { DeterministicKey } from "../walletcore/deterministickey";
import { ProducerInfo } from "../transactions/payload/ProducerInfo";
import { CancelProducer } from "../transactions/payload/CancelProducer";
import { ReturnDepositCoin } from "../transactions/payload/ReturnDepositCoin";
import {
  VoteContent,
  VoteContentArray,
  VoteContentType,
  CandidateVotes,
  PayloadVote,
  VOTE_PRODUCER_CR_VERSION
} from "../transactions/payload/OutputPayload/PayloadVote";
import { ByteStream } from "../common/bytestream";
import { CRInfo, CRInfoDIDVersion } from "../transactions/payload/CRInfo";
import { UnregisterCR } from "../transactions/payload/UnregisterCR";
import {
  CRCouncilMemberClaimNode,
  CRCouncilMemberClaimNodeVersion
} from "../transactions/payload/CRCouncilMemberClaimNode";
import {
  CRCProposalDefaultVersion,
  CRCProposal,
  CRCProposalVersion01,
  CRCProposalType
} from "../transactions/payload/CRCProposal";
import { SHA256 } from "../walletcore/sha256";
import {
  CRCProposalReview,
  CRCProposalReviewDefaultVersion,
  CRCProposalReviewVersion01
} from "../transactions/payload/CRCProposalReview";
import {
  CRCProposalTracking,
  CRCProposalTrackingDefaultVersion,
  CRCProposalTrackingVersion01
} from "../transactions/payload/CRCProposalTracking";

export const DEPOSIT_MIN_ELA = 5000;

// TODO: Migrate all COMMENTS from the C++ IMainchainSubWallet interface here.
export class MainchainSubWallet extends ElastosBaseSubWallet {
  constructor(
    info: CoinInfo,
    config: ChainConfig,
    parent: MasterWallet,
    netType: string
  ) {
    super(info, config, parent, netType);
  }

  /**
   * Deposit token from the main chain to side chains, such as ID chain or token chain, etc
   *
   * @version 0x00 means old deposit tx, 0x01 means new deposit tx, other value will throw exception.
   * @param inputs UTXO which will be used. eg
   * [
   *   {
   *     "TxHash": "...", // string
   *     "Index": 123, // int
   *     "Address": "...", // string
   *     "Amount": "100000000" // bigint string in SELA
   *   },
   *   ...
   * ]
   * NOTE:  (utxo input amount) >= amount + 10000 sela + fee
   * @param sideChainID Chain id of the side chain
   * @param amount The amount that will be deposit to the side chain.
   * @param sideChainAddress Receive address of side chain
   * @param lockAddress Generate from genesis block hash
   * @param fee Fee amount. Bigint string in SELA
   * @param memo Remarks string. Can be empty string
   * @return The transaction in JSON format to be signed and published
   */

  createDepositTransaction(
    version: uint8_t,
    inputsJson: JSONArray,
    sideChainID: string,
    amount: string,
    sideChainAddress: string,
    lockAddress: string,
    fee: string,
    memo: string
  ) {
    // WalletPtr wallet = _walletManager->GetWallet();
    let wallet: Wallet = this.getWallet();
    // ArgInfo("{} {}", wallet.getWalletID(), GetFunName());
    // ArgInfo("version: {}", version);
    // ArgInfo("inputs: {}", inputsJson.dump());
    // ArgInfo("sideChainID: {}", sideChainID);
    // ArgInfo("amount: {}", amount);
    // ArgInfo("sideChainAddr: {}", sideChainAddress);
    // ArgInfo("lockAddress: {}", lockAddress);
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxos = new UTXOSet();
    this.UTXOFromJson(utxos, inputsJson);

    if (
      version != TransferCrossChainVersion &&
      version != TransferCrossChainVersionV1
    )
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "invalid version"
      );
    let payloadVersion: uint8_t = version;
    ErrorChecker.checkBigIntAmount(amount);
    ErrorChecker.checkParam(
      sideChainID == CHAINID_MAINCHAIN,
      Error.Code.InvalidArgument,
      "can not be mainChain"
    );

    let bgAmount = new BigNumber(amount);
    let feeAmount = new BigNumber(fee);

    if (sideChainID == CHAINID_IDCHAIN || sideChainID == CHAINID_TOKENCHAIN) {
      let addressValidate = Address.newFromAddressString(sideChainAddress);
      ErrorChecker.checkParam(
        !addressValidate.valid(),
        Error.Code.Address,
        "invalid standard address"
      );
    } else if (sideChainID.indexOf("ETH") !== -1) {
      // TODO
      // ErrorChecker.checkParam(addressValidateString(sideChainAddress) != ETHEREUM_BOOLEAN_TRUE, Error.Code.Address, "invalid ethsc address");
    } else {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "invalid chain id"
      );
    }

    let payload: Payload;
    let outputs: OutputArray;
    let receiveAddr = Address.newFromAddressString(lockAddress);

    if (payloadVersion == TransferCrossChainVersion) {
      let info = TransferInfo.newFromParams(sideChainAddress, 0, bgAmount);
      payload = TransferCrossChainAsset.newFromParams([info]);
      outputs.push(
        TransactionOutput.newFromParams(
          bgAmount.plus(DEPOSIT_OR_WITHDRAW_FEE),
          receiveAddr
        )
      );
    } else if (payloadVersion == TransferCrossChainVersionV1) {
      payload = new TransferCrossChainAsset();
      let outputPayload = PayloadCrossChain.newFromParams(
        CrossChainOutputVersion,
        sideChainAddress,
        bgAmount,
        Buffer.alloc(0)
      );

      outputs.push(
        TransactionOutput.newFromParams(
          bgAmount.plus(DEPOSIT_OR_WITHDRAW_FEE),
          receiveAddr,
          Asset.getELAAssetID(),
          Type.CrossChain,
          outputPayload
        )
      );
    }

    const tx: Transaction = wallet.createTransaction(
      TransactionType.transferCrossChainAsset,
      payload,
      utxos,
      outputs,
      memo,
      feeAmount
    );
    tx.setPayloadVersion(payloadVersion);

    let result: json;
    this.encodeTx(result, tx);

    // ArgInfo("r => {}", result.dump());
    return result;
  }

  getDepositAddress(pubkey: string): string {
    const pub = Buffer.from(pubkey, "hex");
    let depositAddress = Address.newWithPubKey(Prefix.PrefixDeposit, pub);
    return depositAddress.string();
  }

  async generateProducerPayload(
    ownerPublicKey: string,
    nodePublicKey: string,
    nickName: string,
    url: string,
    ipAddress: string,
    location: uint64_t,
    payPasswd: string
  ) {
    // ArgInfo("{} {}", _walletManager->GetWallet()->GetWalletID(), GetFunName());
    // ArgInfo("ownerPubKey: {}", ownerPublicKey);
    // ArgInfo("nodePubKey: {}", nodePublicKey);
    // ArgInfo("nickName: {}", nickName);
    // ArgInfo("url: {}", url);
    // ArgInfo("ipAddress: {}", ipAddress);
    // ArgInfo("location: {}", location);
    // ArgInfo("payPasswd: *");

    ErrorChecker.checkPassword(payPasswd, "Generate payload");

    let verifyPubKey = new DeterministicKey(DeterministicKey.ELASTOS_VERSIONS);
    let ownerPubKey = Buffer.from(ownerPublicKey);
    verifyPubKey.publicKey = ownerPubKey;

    let nodePubKey = Buffer.from(nodePublicKey);
    verifyPubKey.publicKey = nodePubKey;

    let pr = new ProducerInfo();
    pr.setPublicKey(ownerPubKey);
    pr.setNodePublicKey(nodePubKey);
    pr.setNickName(nickName);
    pr.setUrl(url);
    pr.setAddress(ipAddress);
    pr.setLocation(location);

    let ostream = new ByteStream();
    pr.serializeUnsigned(ostream, 0);
    let prUnsigned = ostream.getBytes();

    const signature = await this.getWallet().signWithOwnerKey(
      prUnsigned,
      payPasswd
    );
    pr.setSignature(signature);

    let payloadJson = pr.toJson(0);

    // ArgInfo("r => {}", payloadJson.dump());
    return payloadJson;
  }

  async generateCancelProducerPayload(
    ownerPublicKey: string,
    payPasswd: string
  ): Promise<json> {
    // ArgInfo("{} {}", _walletManager->GetWallet()->GetWalletID(), GetFunName());
    // ArgInfo("ownerPubKey: {}", ownerPublicKey);
    // ArgInfo("payPasswd: *");

    ErrorChecker.checkPassword(payPasswd, "Generate payload");
    let pubKeyLen: size_t = ownerPublicKey.length >> 1;
    ErrorChecker.checkParam(
      pubKeyLen != 33 && pubKeyLen != 65,
      Error.Code.PubKeyLength,
      "Public key length should be 33 or 65 bytes"
    );

    let pc = new CancelProducer();
    pc.setPublicKey(Buffer.from(ownerPublicKey));

    let ostream = new ByteStream();
    pc.serializeUnsigned(ostream, 0);
    let pcUnsigned: bytes_t = ostream.getBytes();

    const signature = await this.getWallet().signWithOwnerKey(
      pcUnsigned,
      payPasswd
    );
    pc.setSignature(signature);

    let payloadJson: json = pc.toJson(0);
    // ArgInfo("r => {}", payloadJson.dump());
    return payloadJson;
  }

  createRegisterProducerTransaction(
    inputsJson: JSONArray,
    payloadJson: json,
    amount: string,
    fee: string,
    memo: string
  ): json {
    let wallet = this.getWallet();

    // ArgInfo("{} {}", wallet.getWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputsJson.dump());
    // ArgInfo("payload: {}", payloadJson.dump());
    // ArgInfo("amount: {}", amount);
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo: UTXOSet;
    this.UTXOFromJson(utxo, inputsJson);

    ErrorChecker.checkBigIntAmount(amount);
    let bgAmount = new BigNumber(amount);
    let minAmount = new BigNumber(DEPOSIT_MIN_ELA);
    let feeAmount = new BigNumber(fee);

    minAmount = minAmount.multipliedBy(SELA_PER_ELA);

    ErrorChecker.checkParam(
      bgAmount.lt(minAmount),
      Error.Code.DepositAmountInsufficient,
      "Producer deposit amount is insufficient"
    );

    let payload = new ProducerInfo();
    try {
      payload.fromJson(payloadJson, 0);
    } catch (e) {
      ErrorChecker.throwParamException(
        Error.Code.JsonFormatError,
        "Payload format err: " + e.what()
      );
    }

    let pubkey: bytes_t = payload.getPublicKey();

    let outputs: OutputArray;
    let receiveAddr = Address.newWithPubKey(Prefix.PrefixDeposit, pubkey);
    outputs.push(TransactionOutput.newFromParams(bgAmount, receiveAddr));

    let tx = wallet.createTransaction(
      TransactionType.registerProducer,
      payload,
      utxo,
      outputs,
      memo,
      feeAmount
    );

    let result: json = {};
    this.encodeTx(result, tx);

    // ArgInfo("r => {}", result.dump());
    return result;
  }

  createUpdateProducerTransaction(
    inputsJson: JSONArray,
    payloadJson: json,
    fee: string,
    memo: string
  ) {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", wallet->GetWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputsJson.dump());
    // ArgInfo("payload: {}", payloadJson.dump());
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo: UTXOSet;
    this.UTXOFromJson(utxo, inputsJson);
    let payload = new ProducerInfo();
    try {
      payload.fromJson(payloadJson, 0);
    } catch (e) {
      ErrorChecker.throwParamException(
        Error.Code.JsonFormatError,
        "Payload format err: " + e.what()
      );
    }
    let feeAmount = new BigNumber(fee);

    let tx = wallet.createTransaction(
      TransactionType.updateProducer,
      payload,
      utxo,
      [],
      memo,
      feeAmount
    );
    let result: json = {};
    this.encodeTx(result, tx);
    // ArgInfo("r => {}", result.dump());
    return result;
  }

  createCancelProducerTransaction(
    inputsJson: JSONArray,
    payloadJson: json,
    fee: string,
    memo: string
  ): json {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", wallet.getWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputsJson.dump());
    // ArgInfo("payload: {}", payloadJson.dump());
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo: UTXOSet;
    this.UTXOFromJson(utxo, inputsJson);

    let payload = new CancelProducer();
    try {
      payload.fromJson(payloadJson, 0);
    } catch (e) {
      ErrorChecker.throwParamException(
        Error.Code.JsonFormatError,
        "Payload format err: " + e.what()
      );
    }

    let feeAmount = new BigNumber(fee);

    let tx = wallet.createTransaction(
      TransactionType.cancelProducer,
      payload,
      utxo,
      [],
      memo,
      feeAmount
    );

    let result: json = {};
    this.encodeTx(result, tx);

    // ArgInfo("r => {}", result.dump());
    return result;
  }

  createRetrieveDepositTransaction(
    inputsJson: JSONArray,
    amount: string,
    fee: string,
    memo: string
  ): json {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", wallet->GetWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputsJson.dump());
    // ArgInfo("amount: {}", amount);
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo: UTXOSet;
    this.UTXOFromJson(utxo, inputsJson);

    let feeAmount = new BigNumber(fee);
    let bgAmount = new BigNumber(amount);
    let outputs: OutputArray;
    let receiveAddr: Address = utxo[0].getAddress();
    outputs.push(
      TransactionOutput.newFromParams(bgAmount.minus(feeAmount), receiveAddr)
    );

    let payload = new ReturnDepositCoin();
    let tx = this.getWallet().createTransaction(
      TransactionType.returnDepositCoin,
      payload,
      utxo,
      outputs,
      memo,
      feeAmount,
      true
    );

    let result = {};
    this.encodeTx(result, tx);

    // ArgInfo("r => {}", result.dump());
    return result;
  }

  getOwnerPublicKey(): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    let publicKey: string = this.getWallet()
      .getOwnerPublilcKey()
      .toString("hex");
    // ArgInfo("r => {}", publicKey);
    return publicKey;
  }

  getOwnerAddress(): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());

    let address = this.getWallet().getOwnerAddress().string();

    // ArgInfo("r => {}", address);

    return address;
  }

  getOwnerDepositAddress(): string {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", wallet.getWalletID(), GetFunName());

    let addrPtr = wallet.getOwnerDepositAddress();
    let addr: string = addrPtr.string();

    // ArgInfo("r => {}", addr);

    return addr;
  }

  voteAmountFromJson(voteAmount: BigNumber, j: string): boolean {
    ErrorChecker.checkParam(
      typeof j !== "string",
      Error.Code.InvalidArgument,
      "stake value should be big int string"
    );
    let voteAmountString: string = j;
    ErrorChecker.checkBigIntAmount(voteAmountString);
    voteAmount = new BigNumber(voteAmountString);
    ErrorChecker.checkParam(
      voteAmount.lte(0),
      Error.Code.InvalidArgument,
      "stake value should larger than 0"
    );

    return true;
  }

  voteContentFromJson(
    voteContents: VoteContentArray,
    maxAmount: BigNumber,
    j: json
  ): boolean {
    let tmpAmount = new BigNumber(0);

    if (j["Type"] == "CRC") {
      let vc = VoteContent.newFromType(VoteContentType.CRC);
      let candidateVotesJson = j["Candidates"] as JSONArray;
      for (let i = 0; i < candidateVotesJson.length; ++i) {
        let voteAmount = new BigNumber(0);
        const item = candidateVotesJson[i];
        this.voteAmountFromJson(voteAmount, Object.values(item)[0]);

        let key = Object.keys(item)[0];
        let cid = Address.newFromAddressString(key);
        ErrorChecker.checkParam(
          !cid.valid(),
          Error.Code.InvalidArgument,
          "invalid candidate cid"
        );
        let candidate = cid.programHash().bytes();

        vc.addCandidate(CandidateVotes.newFromParams(candidate, voteAmount));
      }
      tmpAmount = vc.getTotalVoteAmount();
      if (tmpAmount.gt(maxAmount)) {
        maxAmount = tmpAmount;
      }
      voteContents.push(vc);
    } else if (j["Type"] == "CRCProposal") {
      let vc = VoteContent.newFromType(VoteContentType.CRCProposal);
      let candidateVotesJson = j["Candidates"] as JSONArray;
      for (let i = 0; i < candidateVotesJson.length; ++i) {
        let voteAmount = new BigNumber(0);

        const item = candidateVotesJson[i];
        this.voteAmountFromJson(voteAmount, Object.values(item)[0]);
        let key = Object.keys(item)[0];
        let proposalHash = Buffer.from(key, "hex");

        ErrorChecker.checkParam(
          proposalHash.length != 32,
          Error.Code.InvalidArgument,
          "invalid proposal hash"
        );

        vc.addCandidate(CandidateVotes.newFromParams(proposalHash, voteAmount));
      }
      tmpAmount = vc.getMaxVoteAmount();
      if (tmpAmount.gt(maxAmount)) {
        maxAmount = tmpAmount;
      }
      voteContents.push(vc);
    } else if (j["Type"] == "CRCImpeachment") {
      let vc = VoteContent.newFromType(VoteContentType.CRCImpeachment);
      let candidateVotesJson = j["Candidates"] as JSONArray;
      for (let i = 0; i < candidateVotesJson.length; ++i) {
        let voteAmount = new BigNumber(0);

        const item = candidateVotesJson[i];
        this.voteAmountFromJson(voteAmount, Object.values(item)[0]);

        let key = Object.keys(item)[0];
        let cid = Address.newFromAddressString(key);
        ErrorChecker.checkParam(
          !cid.valid(),
          Error.Code.InvalidArgument,
          "invalid candidate cid"
        );
        let candidate = cid.programHash().bytes();

        vc.addCandidate(CandidateVotes.newFromParams(candidate, voteAmount));
      }
      tmpAmount = vc.getTotalVoteAmount();
      if (tmpAmount.gt(maxAmount)) {
        maxAmount = tmpAmount;
      }
      voteContents.push(vc);
    } else if (j["Type"] == "Delegate") {
      let vc = VoteContent.newFromType(VoteContentType.Delegate);
      let candidateVotesJson = j["Candidates"] as JSONArray;
      for (let i = 0; i < candidateVotesJson.length; ++i) {
        const item = candidateVotesJson[i];
        let voteAmount = new BigNumber(0);
        this.voteAmountFromJson(voteAmount, Object.values(item)[0]);

        let key = Object.keys(item)[0];

        let pubkey = Buffer.from(key, "hex");

        vc.addCandidate(CandidateVotes.newFromParams(pubkey, voteAmount));
      }
      tmpAmount = vc.getMaxVoteAmount();
      if (tmpAmount.gt(maxAmount)) {
        maxAmount = tmpAmount;
      }
      voteContents.push(vc);
    }

    return true;
  }

  createVoteTransaction(
    inputsJson: JSONArray,
    voteContentsJson: json,
    fee: string,
    memo: string
  ): json {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", wallet.getWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputsJson.dump());
    // ArgInfo("voteContent: {}", voteContentsJson.dump());
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxos: UTXOSet;
    this.UTXOFromJson(utxos, inputsJson);

    let outputAmount = new BigNumber(0);
    let voteContents: VoteContentArray;
    this.voteContentFromJson(voteContents, outputAmount, voteContentsJson);

    let outputPayload = PayloadVote.newFromParams(
      voteContents,
      VOTE_PRODUCER_CR_VERSION
    );

    let outputs: OutputArray;
    let output = TransactionOutput.newFromParams(
      outputAmount,
      utxos[0].getAddress(),
      Asset.getELAAssetID(),
      Type.VoteOutput,
      outputPayload
    );
    outputs.push(output);

    const feeAmount = new BigNumber(fee);

    const payload = new TransferAsset();
    const tx = wallet.createTransaction(
      TransactionType.transferAsset,
      payload,
      utxos,
      outputs,
      memo,
      feeAmount,
      true
    );

    let result: json = {};
    this.encodeTx(result, tx);

    // ArgInfo("r => {}", result.dump());
    return result;
  }

  getCRDepositAddress(): string {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", wallet.getWalletID(), GetFunName());

    let addrPtr = wallet.getCROwnerDepositAddress();
    let addr = addrPtr.string();

    // ArgInfo("r => {}", addr);

    return addr;
  }

  generateCRInfoPayload(
    crPublicKey: string,
    did: string,
    nickName: string,
    url: string,
    location: uint64_t
  ): json {
    // ArgInfo("{} {}", _walletManager->GetWallet()->GetWalletID(), GetFunName());
    // ArgInfo("crPublicKey: {}", crPublicKey);
    // ArgInfo("did: {}", did);
    // ArgInfo("nickName: {}", nickName);
    // ArgInfo("url: {}", url);
    // ArgInfo("location: {}", location);

    let pubKeyLen: size_t = crPublicKey.length >> 1;
    ErrorChecker.checkParam(
      pubKeyLen != 33 && pubKeyLen != 65,
      Error.Code.PubKeyLength,
      "Public key length should be 33 or 65 bytes"
    );

    let pubkey = Buffer.from(crPublicKey);

    let didAddress = Address.newFromAddressString(did);
    let address = Address.newWithPubKey(Prefix.PrefixStandard, pubkey);

    let crInfo = new CRInfo();
    crInfo.setCode(address.redeemScript());
    crInfo.setDID(didAddress.programHash());
    crInfo.setNickName(nickName);
    crInfo.setUrl(url);
    crInfo.setLocation(location);

    let cid = new Address();
    cid.setRedeemScript(Prefix.PrefixIDChain, crInfo.getCode());
    crInfo.setCID(cid.programHash());

    let ostream = new ByteStream();
    crInfo.serializeUnsigned(ostream, CRInfoDIDVersion);
    let digest = SHA256.encodeToBuffer(ostream.getBytes());

    let payloadJson = crInfo.toJson(CRInfoDIDVersion);
    payloadJson["Digest"] = digest.toString("hex");

    // ArgInfo("r => {}", payloadJson.dump());
    return payloadJson;
  }

  generateUnregisterCRPayload(CID: string): json {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("CID: {}", CID);

    let cid = Address.newFromAddressString(CID);
    ErrorChecker.checkParam(
      !cid.valid(),
      Error.Code.InvalidArgument,
      "invalid crDID"
    );

    let unregisterCR: UnregisterCR;
    unregisterCR.setCID(cid.programHash());

    let ostream = new ByteStream();
    unregisterCR.serializeUnsigned(ostream, 0);
    let digest = SHA256.encodeToBuffer(ostream.getBytes());

    let payloadJson = unregisterCR.toJson(0);
    payloadJson["Digest"] = digest.toString("hex");

    // ArgInfo("r => {}", payloadJson.dump());
    return payloadJson;
  }

  createRegisterCRTransaction(
    inputsJson: JSONArray,
    payloadJSON: json,
    amount: string,
    fee: string,
    memo: string
  ): json {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", wallet.getWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputsJson.dump());
    // ArgInfo("payload: {}", payloadJSON.dump());
    // ArgInfo("amount: {}", amount);
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo: UTXOSet;
    this.UTXOFromJson(utxo, inputsJson);

    ErrorChecker.checkBigIntAmount(amount);

    let bgAmount = new BigNumber(amount);
    let minAmount = new BigNumber(DEPOSIT_MIN_ELA);
    let feeAmount = new BigNumber(fee);

    minAmount.multipliedBy(SELA_PER_ELA);

    ErrorChecker.checkParam(
      bgAmount.lt(minAmount),
      Error.Code.DepositAmountInsufficient,
      "cr deposit amount is insufficient"
    );

    ErrorChecker.checkParam(
      !payloadJSON["Signature"],
      Error.Code.InvalidArgument,
      "Signature can not be empty"
    );

    let payloadVersion: uint8_t = CRInfoDIDVersion;
    let payload = new CRInfo();
    try {
      payload.fromJson(payloadJSON, payloadVersion);
      ErrorChecker.checkParam(
        !payload.isValid(payloadVersion),
        Error.Code.InvalidArgument,
        "verify signature failed"
      );
    } catch (e) {
      ErrorChecker.throwParamException(
        Error.Code.JsonFormatError,
        "Payload format err: " + e.what()
      );
    }

    let code = payload.getCode();
    let receiveAddr = new Address();
    receiveAddr.setRedeemScript(Prefix.PrefixDeposit, code);

    let outputs: OutputArray;
    outputs.push(TransactionOutput.newFromParams(bgAmount, receiveAddr));

    let tx = wallet.createTransaction(
      TransactionType.registerCR,
      payload,
      utxo,
      outputs,
      memo,
      feeAmount
    );
    tx.setPayloadVersion(payloadVersion);

    let result = {};
    this.encodeTx(result, tx);

    // ArgInfo("r => {}", result.dump());
    return result;
  }

  createUpdateCRTransaction(
    inputsJson: JSONArray,
    payloadJSON: JSONObject,
    fee: string,
    memo: string
  ): json {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", wallet.getWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputsJson.dump());
    // ArgInfo("payload: {}", payloadJSON.dump());
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo: UTXOSet;
    this.UTXOFromJson(utxo, inputsJson);

    let payloadVersion: uint8_t = CRInfoDIDVersion;
    let payload = new CRInfo();
    try {
      payload.fromJson(payloadJSON, payloadVersion);
    } catch (e) {
      ErrorChecker.throwParamException(
        Error.Code.JsonFormatError,
        "Payload format err: " + e.what()
      );
    }

    let feeAmount = new BigNumber(fee);

    let tx = wallet.createTransaction(
      TransactionType.updateCR,
      payload,
      utxo,
      [],
      memo,
      feeAmount
    );
    tx.setPayloadVersion(payloadVersion);

    let result = {};
    this.encodeTx(result, tx);

    // ArgInfo("r => {}", result.dump());
    return result;
  }

  createUnregisterCRTransaction(
    inputsJson: JSONArray,
    payloadJSON: JSONObject,
    fee: string,
    memo: string
  ): json {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", wallet.getWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputsJson.dump());
    // ArgInfo("payload: {}", payloadJSON.dump());
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo: UTXOSet;
    this.UTXOFromJson(utxo, inputsJson);

    ErrorChecker.checkParam(
      !payloadJSON["Signature"],
      Error.Code.InvalidArgument,
      "invalied signature"
    );

    let payload = new UnregisterCR();
    try {
      payload.fromJson(payloadJSON, 0);
    } catch (e) {
      ErrorChecker.throwParamException(
        Error.Code.JsonFormatError,
        "Payload format err: " + e.what()
      );
    }

    let feeAmount = new BigNumber(fee);

    let tx = wallet.createTransaction(
      TransactionType.unregisterCR,
      payload,
      utxo,
      [],
      memo,
      feeAmount
    );

    let result: json = {};
    this.encodeTx(result, tx);

    // ArgInfo("r => {}", result.dump());
    return result;
  }

  createRetrieveCRDepositTransaction(
    inputsJson: JSONArray,
    amount: string,
    fee: string,
    memo: string
  ): json {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", wallet.getWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputsJson.dump());
    // ArgInfo("amount: {}", amount);
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo: UTXOSet;
    this.UTXOFromJson(utxo, inputsJson);

    let feeAmount = new BigNumber(fee);
    let bgAmount = new BigNumber(amount);

    let outputs: OutputArray;
    let receiveAddr = utxo[0].getAddress();
    outputs.push(
      TransactionOutput.newFromParams(bgAmount.minus(feeAmount), receiveAddr)
    );

    let payload = new ReturnDepositCoin();
    let tx = wallet.createTransaction(
      TransactionType.returnCRDepositCoin,
      payload,
      utxo,
      outputs,
      memo,
      feeAmount,
      true
    );

    let result = {};
    this.encodeTx(result, tx);
    // ArgInfo("r => {}", result.dump());
    return result;
  }

  CRCouncilMemberClaimNodeDigest(payload: json): string {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", wallet.getWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload.dump());

    let version: uint8_t = CRCouncilMemberClaimNodeVersion;
    let p: CRCouncilMemberClaimNode;
    try {
      p.fromJsonUnsigned(payload, version);
    } catch (e) {
      ErrorChecker.throwParamException(Error.Code.InvalidArgument, "from json");
    }

    if (!p.isValidUnsigned(version)) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "invalid payload"
      );
    }

    let digest: string = p.digestUnsigned(version).toString(16);

    // ArgInfo("r => {}", digest);
    return digest;
  }

  createCRCouncilMemberClaimNodeTransaction(
    inputsJson: JSONArray,
    payloadJson: JSONObject,
    fee: string,
    memo: string
  ): json {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", wallet.getWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputsJson.dump());
    // ArgInfo("payload: {}", payloadJson.dump());
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo: UTXOSet;
    this.UTXOFromJson(utxo, inputsJson);

    let version: uint8_t = CRCProposalDefaultVersion;
    let payload = new CRCouncilMemberClaimNode();
    try {
      payload.fromJson(payloadJson, version);
    } catch (e) {
      ErrorChecker.throwParamException(Error.Code.InvalidArgument, "from json");
    }

    if (!payload.isValid(version))
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "invalid payload"
      );

    let feeAmount = new BigNumber(fee);

    let tx = wallet.createTransaction(
      TransactionType.crCouncilMemberClaimNode,
      payload,
      utxo,
      [],
      memo,
      feeAmount
    );
    tx.setPayloadVersion(version);

    let result = {};
    this.encodeTx(result, tx);
    // ArgInfo("r => {}", result.dump());

    return result;
  }

  proposalOwnerDigest(payload: json): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload.dump());

    let proposal: CRCProposal = new CRCProposal();
    let version: uint8_t = CRCProposalDefaultVersion;
    try {
      if (payload["JsonKeyDraftData"]) {
        version = CRCProposalVersion01;
      } else {
        version = CRCProposalDefaultVersion;
      }
      proposal.fromJsonNormalOwnerUnsigned(payload, version);
    } catch (e) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "convert from json"
      );
    }

    ErrorChecker.checkParam(
      !proposal.isValidNormalOwnerUnsigned(version),
      Error.Code.InvalidArgument,
      "invalid payload"
    );

    let digest: string = proposal
      .digestNormalOwnerUnsigned(version)
      .toString(16);

    // ArgInfo("r => {}", digest);
    return digest;
  }

  proposalCRCouncilMemberDigest(payload: json): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload);

    let proposal: CRCProposal = new CRCProposal();
    let version: uint8_t = CRCProposalDefaultVersion;
    try {
      if (payload["JsonKeyDraftData"]) {
        version = CRCProposalVersion01;
      } else {
        version = CRCProposalDefaultVersion;
      }
      proposal.fromJsonNormalCRCouncilMemberUnsigned(payload, version);
    } catch (e) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "convert from json"
      );
    }

    ErrorChecker.checkParam(
      !proposal.isValidNormalCRCouncilMemberUnsigned(version),
      Error.Code.InvalidArgument,
      "invalid payload"
    );

    let digest: string = proposal
      .digestNormalCRCouncilMemberUnsigned(version)
      .toString(16);

    // ArgInfo("r => {}", digest);
    return digest;
  }

  calculateProposalHash(payload: json): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload);

    let p = new CRCProposal();
    let version: uint8_t = CRCProposalDefaultVersion;
    try {
      if (payload["JsonKeyDraftData"]) {
        version = CRCProposalVersion01;
      } else {
        version = CRCProposalDefaultVersion;
      }
      p.fromJson(payload, version);
    } catch (e) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "convert from json"
      );
    }

    ErrorChecker.checkParam(
      !p.isValid(version),
      Error.Code.InvalidArgument,
      "invalid payload"
    );

    let stream = new ByteStream();
    p.serialize(stream, version);
    let hash = SHA256.hashTwice(stream.getBytes());
    let hashString = hash.toString("hex");

    // ArgInfo("r => {}", hashString);
    return hashString;
  }

  createProposalTransaction(
    inputsJson: JSONArray,
    payload: json,
    fee: string,
    memo: string
  ): json {
    let wallet: Wallet = this.getWallet();
    // ArgInfo("{} {}", wallet.getWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputsJson);
    // ArgInfo("payload: {}", payload);
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo: UTXOSet;
    this.UTXOFromJson(utxo, inputsJson);

    let p = new CRCProposal();
    let version: uint8_t = CRCProposalDefaultVersion;
    try {
      if (payload["JsonKeyDraftData"]) {
        version = CRCProposalVersion01;
      } else {
        version = CRCProposalDefaultVersion;
      }
      p.fromJson(payload, version);
    } catch (e) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "convert from json"
      );
    }

    ErrorChecker.checkParam(
      !p.isValid(version),
      Error.Code.InvalidArgument,
      "invalid payload"
    );

    let feeAmount = new BigNumber(fee);

    let tx = wallet.createTransaction(
      TransactionType.crcProposal,
      p,
      utxo,
      [],
      memo,
      feeAmount
    );
    tx.setPayloadVersion(version);

    let result: json = {};
    this.encodeTx(result, tx);

    // ArgInfo("r => {}", result);
    return result;
  }

  proposalReviewDigest(payload: json): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload.dump());

    let proposalReview = new CRCProposalReview();
    let version: uint8_t = CRCProposalReviewDefaultVersion;
    try {
      if (payload["JsonKeyOpinionData"]) {
        version = CRCProposalReviewVersion01;
      } else {
        version = CRCProposalReviewDefaultVersion;
      }
      proposalReview.fromJsonUnsigned(payload, version);
    } catch (e) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "convert from json"
      );
    }

    if (!proposalReview.isValidUnsigned(version)) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "invalid payload"
      );
    }

    let digest: string = proposalReview.digestUnsigned(version).toString(16);

    // ArgInfo("r => {}", digest);
    return digest;
  }

  createProposalReviewTransaction(
    inputsJson: JSONArray,
    payload: json,
    fee: string,
    memo: string
  ): json {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", this.getWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputsJson);
    // ArgInfo("payload: {}", payload);
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo: UTXOSet;
    this.UTXOFromJson(utxo, inputsJson);

    let p = new CRCProposalReview();
    let version: uint8_t = CRCProposalReviewDefaultVersion;
    try {
      if (payload["JsonKeyOpinionData"]) version = CRCProposalReviewVersion01;
      else version = CRCProposalReviewDefaultVersion;
      p.fromJson(payload, version);
    } catch (e) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "convert from json"
      );
    }

    if (!p.isValid(version))
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "invalid payload"
      );

    let feeAmount = new BigNumber(fee);

    let tx = wallet.createTransaction(
      TransactionType.crcProposalReview,
      p,
      utxo,
      [],
      memo,
      feeAmount
    );
    tx.setPayloadVersion(version);

    let result: json = {};
    this.encodeTx(result, tx);

    // ArgInfo("r => {}", result);
    return result;
  }

  proposalTrackingOwnerDigest(payload: json): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload);

    let version: uint8_t = CRCProposalTrackingDefaultVersion;
    let proposalTracking = new CRCProposalTracking();
    try {
      if (payload["JsonKeyMessageData"]) version = CRCProposalTrackingVersion01;
      else version = CRCProposalTrackingDefaultVersion;
      proposalTracking.fromJsonOwnerUnsigned(payload, version);
    } catch (e) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "convert from json"
      );
    }

    if (!proposalTracking.isValidOwnerUnsigned(version)) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "invalid payload"
      );
    }
    let digest: string = proposalTracking
      .digestOwnerUnsigned(version)
      .toString(16);

    // ArgInfo("r => {}", digest);
    return digest;
  }

  proposalTrackingNewOwnerDigest(payload: json): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload);

    let version: uint8_t = CRCProposalTrackingDefaultVersion;
    let proposalTracking = new CRCProposalTracking();
    try {
      if (payload["JsonKeyMessageData"]) version = CRCProposalTrackingVersion01;
      else version = CRCProposalTrackingDefaultVersion;
      proposalTracking.fromJsonNewOwnerUnsigned(payload, version);
    } catch (e) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "convert from json"
      );
    }

    if (!proposalTracking.isValidNewOwnerUnsigned(version)) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "invalid payload"
      );
    }

    let digest: string = proposalTracking
      .digestNewOwnerUnsigned(version)
      .toString(16);

    // ArgInfo("r => {}", digest);
    return digest;
  }

  proposalTrackingSecretaryDigest(payload: json): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload);

    let version: uint8_t = CRCProposalTrackingDefaultVersion;
    let proposalTracking = new CRCProposalTracking();
    try {
      if (
        payload["JsonKeyMessageData"] &&
        payload["JsonKeySecretaryGeneralOpinionData"]
      )
        version = CRCProposalTrackingVersion01;
      else version = CRCProposalTrackingDefaultVersion;
      proposalTracking.fromJsonSecretaryUnsigned(payload, version);
    } catch (e) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "convert from json"
      );
    }

    if (!proposalTracking.isValidSecretaryUnsigned(version)) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "invalid payload"
      );
    }

    let digest: string = proposalTracking
      .digestSecretaryUnsigned(version)
      .toString(16);

    // ArgInfo("r => {}", digest);
    return digest;
  }

  createProposalTrackingTransaction(
    inputsJson: JSONArray,
    payload: json,
    fee: string,
    memo: string
  ): json {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", wallet.getWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputsJson);
    // ArgInfo("payload: {}", payload);
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo: UTXOSet;
    this.UTXOFromJson(utxo, inputsJson);

    let version: uint8_t = CRCProposalTrackingDefaultVersion;
    let p = new CRCProposalTracking();
    try {
      if (
        payload["JsonKeyMessageData"] &&
        payload["JsonKeySecretaryGeneralOpinionData"]
      )
        version = CRCProposalTrackingVersion01;
      else version = CRCProposalTrackingDefaultVersion;
      p.fromJson(payload, version);
    } catch (e) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "convert from json"
      );
    }

    if (!p.isValid(version))
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "invalid payload"
      );

    let feeAmount = new BigNumber(fee);

    let tx = wallet.createTransaction(
      TransactionType.crcProposalTracking,
      p,
      utxo,
      [],
      memo,
      feeAmount
    );
    tx.setPayloadVersion(version);

    let result: json = {};
    this.encodeTx(result, tx);
    // ArgInfo("r => {}", result);

    return result;
  }

  proposalSecretaryGeneralElectionDigest(payload: json): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload);

    let version: uint8_t = CRCProposalDefaultVersion;
    let proposal = new CRCProposal();
    try {
      if (payload["JsonKeyDraftData"]) version = CRCProposalVersion01;
      else version = CRCProposalDefaultVersion;
      let payloadFixed = payload;
      payloadFixed["JsonKeyType"] = CRCProposalType.secretaryGeneralElection;
      proposal.fromJsonSecretaryElectionUnsigned(payloadFixed, version);
    } catch (e) {
      ErrorChecker.throwParamException(Error.Code.InvalidArgument, "from json");
    }

    if (!proposal.isValidSecretaryElectionUnsigned(version)) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "invalid payload"
      );
    }

    let digest = proposal.digestSecretaryElectionUnsigned(version).toString(16);

    // ArgInfo("r => {}", digest);
    return digest;
  }

  proposalSecretaryGeneralElectionCRCouncilMemberDigest(payload: json): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload);

    let version: uint8_t = CRCProposalDefaultVersion;
    let proposal = new CRCProposal();
    try {
      if (payload["JsonKeyDraftData"]) version = CRCProposalVersion01;
      else version = CRCProposalDefaultVersion;
      let payloadFixed = payload;
      payloadFixed["JsonKeyType"] = CRCProposalType.secretaryGeneralElection;
      proposal.fromJsonSecretaryElectionCRCouncilMemberUnsigned(
        payloadFixed,
        version
      );
    } catch (e) {
      ErrorChecker.throwParamException(Error.Code.InvalidArgument, "from json");
    }

    if (!proposal.isValidSecretaryElectionCRCouncilMemberUnsigned(version)) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "invalid payload"
      );
    }

    let digest = proposal
      .digestSecretaryElectionCRCouncilMemberUnsigned(version)
      .toString(16);

    // ArgInfo("r => {}", digest);
    return digest;
  }

  createSecretaryGeneralElectionTransaction(
    inputsJson: JSONArray,
    payload: json,
    fee: string,
    memo: string
  ): json {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", wallet.getWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputsJson);
    // ArgInfo("payload: {}", payload);
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo: UTXOSet;
    this.UTXOFromJson(utxo, inputsJson);

    let version: uint8_t = CRCProposalDefaultVersion;
    let p = new CRCProposal();
    try {
      if (payload["JsonKeyDraftData"]) version = CRCProposalVersion01;
      else version = CRCProposalDefaultVersion;
      let payloadFixed = payload;
      payloadFixed["JsonKeyType"] = CRCProposalType.secretaryGeneralElection;
      p.fromJson(payloadFixed, version);
    } catch (e) {
      ErrorChecker.throwParamException(Error.Code.InvalidArgument, "from json");
    }

    if (!p.isValid(version))
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "invalid payload"
      );

    let feeAmount = new BigNumber(fee);

    let tx = wallet.createTransaction(
      TransactionType.crcProposal,
      p,
      utxo,
      [],
      memo,
      feeAmount
    );
    tx.setPayloadVersion(version);

    let result: json = {};
    this.encodeTx(result, tx);
    // ArgInfo("r => {}", result);

    return result;
  }

  //////////////////////////////////////////////////
  //             Proposal Change Owner            //
  //////////////////////////////////////////////////
  proposalChangeOwnerDigest(payload: json): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload);

    let version: uint8_t = CRCProposalDefaultVersion;
    let proposal = new CRCProposal();
    try {
      if (payload["JsonKeyDraftData"]) version = CRCProposalVersion01;
      else version = CRCProposalDefaultVersion;
      let payloadFixed: json = payload;
      payloadFixed["JsonKeyType"] = CRCProposalType.changeProposalOwner;
      proposal.fromJsonChangeOwnerUnsigned(payloadFixed, version);
    } catch (e) {
      ErrorChecker.throwParamException(Error.Code.InvalidArgument, "from json");
    }

    if (!proposal.isValidChangeOwnerUnsigned(version)) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "invalid payload"
      );
    }

    let digest: string = proposal
      .digestChangeOwnerUnsigned(version)
      .toString(16);

    // ArgInfo("r => {}", digest);
    return digest;
  }

  proposalChangeOwnerCRCouncilMemberDigest(payload: json): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload);

    let version: uint8_t = CRCProposalDefaultVersion;
    let proposal = new CRCProposal();
    try {
      if (payload["JsonKeyDraftData"]) version = CRCProposalVersion01;
      else version = CRCProposalDefaultVersion;
      let payloadFixed: json = payload;
      payloadFixed["JsonKeyType"] = CRCProposalType.changeProposalOwner;
      proposal.fromJsonChangeOwnerCRCouncilMemberUnsigned(
        payloadFixed,
        version
      );
    } catch (e) {
      ErrorChecker.throwParamException(Error.Code.InvalidArgument, "from json");
    }

    if (!proposal.isValidChangeOwnerCRCouncilMemberUnsigned(version)) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "invalid payload"
      );
    }

    let digest = proposal
      .digestChangeOwnerCRCouncilMemberUnsigned(version)
      .toString(16);

    // ArgInfo("r => {}", digest);
    return digest;
  }

  createProposalChangeOwnerTransaction(
    inputsJson: JSONArray,
    payload: json,
    fee: string,
    memo: string
  ): json {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", wallet.getWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputsJson);
    // ArgInfo("payload: {}", payload);
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo: UTXOSet;
    this.UTXOFromJson(utxo, inputsJson);

    let version: uint8_t = CRCProposalDefaultVersion;
    let p = new CRCProposal();
    try {
      if (payload["JsonKeyDraftData"]) version = CRCProposalVersion01;
      else version = CRCProposalDefaultVersion;
      let payloadFixed: json = payload;
      payloadFixed["JsonKeyType"] = CRCProposalType.changeProposalOwner;
      p.fromJson(payloadFixed, version);
    } catch (e) {
      ErrorChecker.throwParamException(Error.Code.InvalidArgument, "from json");
    }

    if (!p.isValid(version)) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "invalid payload"
      );
    }

    let feeAmount = new BigNumber(fee);

    let tx = wallet.createTransaction(
      TransactionType.crcProposal,
      p,
      utxo,
      [],
      memo,
      feeAmount
    );
    tx.setPayloadVersion(version);

    let result: json = {};
    this.encodeTx(result, tx);
    // ArgInfo("r => {}", result);

    return result;
  }

  //////////////////////////////////////////////////
  //           Proposal Terminate Proposal        //
  //////////////////////////////////////////////////
  terminateProposalOwnerDigest(payload: json): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload);

    let version: uint8_t = CRCProposalDefaultVersion;
    let proposal = new CRCProposal();
    try {
      if (payload["JsonKeyDraftData"]) version = CRCProposalVersion01;
      else version = CRCProposalDefaultVersion;
      let payloadFixed: json = payload;
      payloadFixed["JsonKeyType"] = CRCProposalType.terminateProposal;
      proposal.fromJsonTerminateProposalOwnerUnsigned(payloadFixed, version);
    } catch (e) {
      ErrorChecker.throwParamException(Error.Code.InvalidArgument, "from json");
    }

    if (!proposal.isValidTerminateProposalOwnerUnsigned(version)) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "invalid payload"
      );
    }

    let digest: string = proposal
      .digestTerminateProposalOwnerUnsigned(version)
      .toString(16);

    // ArgInfo("r => {}", digest);
    return digest;
  }

  terminateProposalCRCouncilMemberDigest(payload: json): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload);

    let version: uint8_t = CRCProposalDefaultVersion;
    let proposal = new CRCProposal();
    try {
      if (payload["JsonKeyDraftData"]) version = CRCProposalVersion01;
      else version = CRCProposalDefaultVersion;
      let payloadFixed: json = payload;
      payloadFixed["JsonKeyType"] = CRCProposalType.terminateProposal;
      proposal.fromJsonTerminateProposalCRCouncilMemberUnsigned(
        payloadFixed,
        version
      );
    } catch (e) {
      ErrorChecker.throwParamException(Error.Code.InvalidArgument, "from json");
    }

    if (!proposal.isValidTerminateProposalCRCouncilMemberUnsigned(version)) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "invalid payload"
      );
    }

    let digest = proposal
      .digestTerminateProposalCRCouncilMemberUnsigned(version)
      .toString(16);

    // ArgInfo("r => {}", digest);
    return digest;
  }

  createTerminateProposalTransaction(
    inputsJson: JSONArray,
    payload: json,
    fee: string,
    memo: string
  ): json {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", wallet.getWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputsJson);
    // ArgInfo("payload: {}", payload);
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo: UTXOSet;
    this.UTXOFromJson(utxo, inputsJson);

    let version: uint8_t = CRCProposalDefaultVersion;
    let p = new CRCProposal();
    try {
      if (payload["JsonKeyDraftData"]) version = CRCProposalVersion01;
      else version = CRCProposalDefaultVersion;
      let payloadFixed: json = payload;
      payloadFixed["JsonKeyType"] = CRCProposalType.terminateProposal;
      p.fromJson(payloadFixed, version);
    } catch (e) {
      ErrorChecker.throwParamException(Error.Code.InvalidArgument, "from json");
    }

    if (!p.isValid(version))
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "invalid payload"
      );

    let feeAmount = new BigNumber(fee);

    let tx = wallet.createTransaction(
      TransactionType.crcProposal,
      p,
      utxo,
      [],
      memo,
      feeAmount
    );
    tx.setPayloadVersion(version);

    let result: json = {};
    this.encodeTx(result, tx);
    // ArgInfo("r => {}", result);

    return result;
  }

  //////////////////////////////////////////////////
  //              Reserve Custom ID               //
  //////////////////////////////////////////////////
  reserveCustomIDOwnerDigest(payload: json): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload);

    let version: uint8_t = CRCProposalDefaultVersion;
    let proposal = new CRCProposal();
    try {
      if (payload["JsonKeyDraftData"]) version = CRCProposalVersion01;
      else version = CRCProposalDefaultVersion;
      let payloadFixed: json = payload;
      payloadFixed["JsonKeyType"] = CRCProposalType.reserveCustomID;
      proposal.fromJsonReserveCustomIDOwnerUnsigned(payloadFixed, version);
    } catch (e) {
      ErrorChecker.throwParamException(Error.Code.InvalidArgument, "from json");
    }

    if (!proposal.isValidReserveCustomIDOwnerUnsigned(version)) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "invalid payload"
      );
    }

    let digest: string = proposal
      .digestReserveCustomIDOwnerUnsigned(version)
      .toString(16);

    // ArgInfo("r => {}", digest);
    return digest;
  }

  reserveCustomIDCRCouncilMemberDigest(payload): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload);

    let version: uint8_t = CRCProposalDefaultVersion;
    let proposal = new CRCProposal();
    try {
      if (payload["JsonKeyDraftData"]) version = CRCProposalVersion01;
      else version = CRCProposalDefaultVersion;
      let payloadFixed: json = payload;
      payloadFixed["JsonKeyType"] = CRCProposalType.reserveCustomID;
      proposal.fromJsonReserveCustomIDCRCouncilMemberUnsigned(
        payloadFixed,
        version
      );
    } catch (e) {
      ErrorChecker.throwParamException(Error.Code.InvalidArgument, "from json");
    }

    if (!proposal.isValidReserveCustomIDCRCouncilMemberUnsigned(version)) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "invalid payload"
      );
    }

    let digest: string = proposal
      .digestReserveCustomIDCRCouncilMemberUnsigned(version)
      .toString(16);

    // ArgInfo("r => {}", digest);
    return digest;
  }

  createReserveCustomIDTransaction(
    inputsJson: JSONArray,
    payload: json,
    fee: string,
    memo: string
  ): json {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", wallet.getWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputsJson);
    // ArgInfo("payload: {}", payload);
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo: UTXOSet;
    this.UTXOFromJson(utxo, inputsJson);

    let version: uint8_t = CRCProposalDefaultVersion;
    let p = new CRCProposal();
    try {
      if (payload["JsonKeyDraftData"]) version = CRCProposalVersion01;
      else version = CRCProposalDefaultVersion;
      let payloadFixed: json = payload;
      payloadFixed["JsonKeyType"] = CRCProposalType.reserveCustomID;
      p.fromJson(payloadFixed, version);
    } catch (e) {
      ErrorChecker.throwParamException(Error.Code.InvalidArgument, "from json");
    }

    if (!p.isValid(version))
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "invalid payload"
      );

    let feeAmount = new BigNumber(fee);

    let tx = wallet.createTransaction(
      TransactionType.crcProposal,
      p,
      utxo,
      [],
      memo,
      feeAmount
    );
    tx.setPayloadVersion(version);

    let result: json = {};
    this.encodeTx(result, tx);
    // ArgInfo("r => {}", result);

    return result;
  }

  //////////////////////////////////////////////////
  //               Receive Custom ID              //
  //////////////////////////////////////////////////
  receiveCustomIDOwnerDigest(payload): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload.dum);

    let version: uint8_t = CRCProposalDefaultVersion;
    let proposal = new CRCProposal();
    try {
      if (payload["JsonKeyDraftData"]) version = CRCProposalVersion01;
      else version = CRCProposalDefaultVersion;
      let payloadFixed: json = payload;
      payloadFixed["JsonKeyType"] = CRCProposalType.receiveCustomID;
      proposal.fromJsonReceiveCustomIDOwnerUnsigned(payloadFixed, version);
    } catch (e) {
      ErrorChecker.throwParamException(Error.Code.InvalidArgument, "from json");
    }

    if (!proposal.isValidReceiveCustomIDOwnerUnsigned(version)) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "invalid payload"
      );
    }

    let digest: string = proposal
      .digestReceiveCustomIDOwnerUnsigned(version)
      .toString(16);

    // ArgInfo("r => {}", digest);
    return digest;
  }

  rceiveCustomIDCRCouncilMemberDigest(payload): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload);

    let version: uint8_t = CRCProposalDefaultVersion;
    let proposal = new CRCProposal();
    try {
      if (payload["JsonKeyDraftData"]) version = CRCProposalVersion01;
      else version = CRCProposalDefaultVersion;
      let payloadFixed: json = payload;
      payloadFixed["JsonKeyType"] = CRCProposalType.receiveCustomID;
      proposal.fromJsonReceiveCustomIDCRCouncilMemberUnsigned(
        payloadFixed,
        version
      );
    } catch (e) {
      ErrorChecker.throwParamException(Error.Code.InvalidArgument, "from json");
    }

    if (!proposal.isValidReceiveCustomIDCRCouncilMemberUnsigned(version)) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "invalid payload"
      );
    }

    let digest: string = proposal
      .digestReceiveCustomIDCRCouncilMemberUnsigned(version)
      .toString(16);

    // ArgInfo("r => {}", digest);
    return digest;
  }

  createReceiveCustomIDTransaction(
    inputsJson: JSONArray,
    payload: json,
    fee: string,
    memo: string
  ): json {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", this.getWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputsJson);
    // ArgInfo("payload: {}", payload);
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo: UTXOSet;
    this.UTXOFromJson(utxo, inputsJson);

    let version: uint8_t = CRCProposalDefaultVersion;
    let p = new CRCProposal();
    try {
      if (payload["JsonKeyDraftData"]) version = CRCProposalVersion01;
      else version = CRCProposalDefaultVersion;
      let payloadFixed: json = payload;
      payloadFixed["JsonKeyType"] = CRCProposalType.receiveCustomID;
      p.fromJson(payloadFixed, version);
    } catch (e) {
      ErrorChecker.throwParamException(Error.Code.InvalidArgument, "from json");
    }

    if (!p.isValid(version))
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "invalid payload"
      );

    let feeAmount = new BigNumber(fee);

    let tx = wallet.createTransaction(
      TransactionType.crcProposal,
      p,
      utxo,
      [],
      memo,
      feeAmount
    );
    tx.setPayloadVersion(version);

    let result: json = {};
    this.encodeTx(result, tx);
    // ArgInfo("r => {}", result.dump());

    return result;
  }

  //////////////////////////////////////////////////
  //              Change Custom ID Fee            //
  //////////////////////////////////////////////////
  changeCustomIDFeeOwnerDigest(payload): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload.dump());

    let version: uint8_t = CRCProposalDefaultVersion;
    let proposal = new CRCProposal();
    try {
      if (payload["JsonKeyDraftData"]) version = CRCProposalVersion01;
      else version = CRCProposalDefaultVersion;
      let payloadFixed = payload;
      payloadFixed["JsonKeyType"] = CRCProposalType.changeCustomIDFee;
      proposal.fromJsonChangeCustomIDFeeOwnerUnsigned(payloadFixed, version);
    } catch (e) {
      ErrorChecker.throwParamException(Error.Code.InvalidArgument, "from json");
    }

    if (!proposal.isValidChangeCustomIDFeeOwnerUnsigned(version)) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "invalid payload"
      );
    }

    let digest: string = proposal
      .digestChangeCustomIDFeeOwnerUnsigned(version)
      .toString(16);

    // ArgInfo("r => {}", digest);
    return digest;
  }

  changeCustomIDFeeCRCouncilMemberDigest(payload): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload.dump());

    let version: uint8_t = CRCProposalDefaultVersion;
    let proposal = new CRCProposal();
    try {
      if (payload["JsonKeyDraftData"]) version = CRCProposalVersion01;
      else version = CRCProposalDefaultVersion;
      let payloadFixed: json = payload;
      payloadFixed["JsonKeyType"] = CRCProposalType.changeCustomIDFee;
      proposal.fromJsonChangeCustomIDFeeCRCouncilMemberUnsigned(
        payloadFixed,
        version
      );
    } catch (e) {
      ErrorChecker.throwParamException(Error.Code.InvalidArgument, "from json");
    }

    if (!proposal.isValidChangeCustomIDFeeCRCouncilMemberUnsigned(version)) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "invalid payload"
      );
    }

    let digest: string = proposal
      .digestChangeCustomIDFeeCRCouncilMemberUnsigned(version)
      .toString(16);

    // ArgInfo("r => {}", digest);
    return digest;
  }

  createChangeCustomIDFeeTransaction(
    inputs: JSONArray,
    payload: json,
    fee: string,
    memo: string
  ): json {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", this.getSubWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputs);
    // ArgInfo("payload: {}", payload);
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo: UTXOSet;
    this.UTXOFromJson(utxo, inputs);

    let version: uint8_t = CRCProposalDefaultVersion;
    let p = new CRCProposal();
    try {
      if (payload["JsonKeyDraftData"]) version = CRCProposalVersion01;
      else version = CRCProposalDefaultVersion;
      let payloadFixed: json = payload;
      payloadFixed["JsonKeyType"] = CRCProposalType.changeCustomIDFee;
      p.fromJson(payloadFixed, version);
    } catch (e) {
      ErrorChecker.throwParamException(Error.Code.InvalidArgument, "from json");
    }

    if (!p.isValid(version))
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "invalid payload"
      );

    let feeAmount = new BigNumber(fee);

    let tx = wallet.createTransaction(
      TransactionType.crcProposal,
      p,
      utxo,
      [],
      memo,
      feeAmount
    );
    tx.setPayloadVersion(version);

    let result: json = {};
    this.encodeTx(result, tx);
    // ArgInfo("r => {}", result);

    return result;
  }

  /*
			std::string MainchainSubWallet::ProposalWithdrawDigest(const nlohmann::json &payload) const {
				ArgInfo("{} {}", _walletManager->GetWallet()->GetWalletID(), GetFunName());
				ArgInfo("payload: {}", payload.dump());

				uint8_t version = CRCProposalWithdrawVersion_01;
				CRCProposalWithdraw proposalWithdraw;
				try {
					proposalWithdraw.FromJsonUnsigned(payload, version);
				} catch (const std::exception &e) {
					ErrorChecker::ThrowParamException(Error::InvalidArgument, "convert from json");
				}

				if (!proposalWithdraw.IsValidUnsigned(version))
					ErrorChecker::ThrowParamException(Error::InvalidArgument, "invalid payload");

				std::string digest = proposalWithdraw.DigestUnsigned(version).GetHex();

				ArgInfo("r => {}", digest);
				return digest;
			}

			nlohmann::json MainchainSubWallet::CreateProposalWithdrawTransaction(
							const nlohmann::json &inputsJson,
									const nlohmann::json &payload,
									const std::string &fee,
									const std::string &memo) const {
				WalletPtr wallet = _walletManager->GetWallet();
				ArgInfo("{} {}", wallet->GetWalletID(), GetFunName());
				ArgInfo("inputs: {}", inputsJson.dump());
							ArgInfo("payload: {}", payload.dump());
				ArgInfo("fee: {}", fee);
							ArgInfo("memo: {}", memo);

							UTXOSet utxo;
							UTXOFromJson(utxo, inputsJson);

				uint8_t version = CRCProposalWithdrawVersion_01;
				PayloadPtr p(new CRCProposalWithdraw());
				try {
					p->FromJson(payload, version);
				} catch (const std::exception &e) {
					ErrorChecker::ThrowParamException(Error::InvalidArgument, "from json");
				}

				if (!p->IsValid(version))
					ErrorChecker::ThrowParamException(Error::InvalidArgument, "invalid payload");

				BigInt feeAmount;
				feeAmount.setDec(fee);

				TransactionPtr tx = wallet->CreateTransaction(Transaction::crcProposalWithdraw, p, utxo, {}, memo, feeAmount);
				tx->SetPayloadVersion(version);

				nlohmann::json result;
				EncodeTx(result, tx);
				ArgInfo("r => {}", result.dump());

				return result;
			}

					std::string MainchainSubWallet::RegisterSidechainOwnerDigest(const nlohmann::json &payload) const {
							ArgInfo("{} {}", _walletManager->GetWallet()->GetWalletID(), GetFunName());
							ArgInfo("payload: {}", payload.dump());

							uint8_t version = CRCProposalDefaultVersion;
							CRCProposal proposal;
							try {
									if (payload.contains(JsonKeyDraftData))
											version = CRCProposalVersion01;
									else
											version = CRCProposalDefaultVersion;
									nlohmann::json payloadFixed = payload;
									payloadFixed[JsonKeyType] = CRCProposal::registerSideChain;
									proposal.FromJsonRegisterSidechainUnsigned(payloadFixed, version);
							} catch (const nlohmann::json::exception &e) {
									ErrorChecker::ThrowParamException(Error::InvalidArgument, "from json");
							}

							if (!proposal.IsValidRegisterSidechainUnsigned(version)) {
									ErrorChecker::ThrowParamException(Error::InvalidArgument, "invalid payload");
							}

							std::string digest = proposal.DigestRegisterSidechainUnsigned(version).GetHex();

							ArgInfo("r => {}", digest);
							return digest;
					}

					std::string MainchainSubWallet::RegisterSidechainCRCouncilMemberDigest(const nlohmann::json &payload) const {
							ArgInfo("{} {}", _walletManager->GetWallet()->GetWalletID(), GetFunName());
							ArgInfo("payload: {}", payload.dump());

							uint8_t version = CRCProposalDefaultVersion;
							CRCProposal proposal;
							try {
									if (payload.contains(JsonKeyDraftData))
											version = CRCProposalVersion01;
									else
											version = CRCProposalDefaultVersion;
									nlohmann::json payloadFixed = payload;
									payloadFixed[JsonKeyType] = CRCProposal::registerSideChain;
									proposal.FromJsonRegisterSidechainCRCouncilMemberUnsigned(payloadFixed, version);
							} catch (const nlohmann::json::exception &e) {
									ErrorChecker::ThrowParamException(Error::InvalidArgument, "from json");
							}

							if (!proposal.IsValidRegisterSidechainCRCouncilMemberUnsigned(version)) {
									ErrorChecker::ThrowParamException(Error::InvalidArgument, "invalid payload");
							}

							std::string digest = proposal.DigestRegisterSidechainCRCouncilMemberUnsigned(version).GetHex();

							ArgInfo("r => {}", digest);
							return digest;
					}

					nlohmann::json MainchainSubWallet::CreateRegisterSidechainTransaction(
									const nlohmann::json &inputs,
									const nlohmann::json &payload,
									const std::string &fee,
									const std::string &memo) const {
							WalletPtr wallet = _walletManager->GetWallet();
							ArgInfo("{} {}", GetSubWalletID(), GetFunName());
							ArgInfo("inputs: {}", inputs.dump());
							ArgInfo("payload: {}", payload.dump());
							ArgInfo("fee: {}", fee);
							ArgInfo("memo: {}", memo);

							UTXOSet utxo;
							UTXOFromJson(utxo, inputs);

							uint8_t version = CRCProposalDefaultVersion;
							PayloadPtr p(new CRCProposal());
							try {
									if (payload.contains(JsonKeyDraftData))
											version = CRCProposalVersion01;
									else
											version = CRCProposalDefaultVersion;
									nlohmann::json payloadFixed = payload;
									payloadFixed[JsonKeyType] = CRCProposal::registerSideChain;
									p->FromJson(payloadFixed, version);
							} catch (const nlohmann::json::exception &e) {
									ErrorChecker::ThrowParamException(Error::InvalidArgument, "from json");
							}

							if (!p->IsValid(version))
									ErrorChecker::ThrowParamException(Error::InvalidArgument, "invalid payload");

							BigInt feeAmount;
							feeAmount.setDec(fee);

							TransactionPtr tx = wallet->CreateTransaction(Transaction::crcProposal, p, utxo, {}, memo, feeAmount);
							tx->SetPayloadVersion(version);

							nlohmann::json result;
							EncodeTx(result, tx);
							ArgInfo("r => {}", result.dump());

							return result;
					}
	 */
}
