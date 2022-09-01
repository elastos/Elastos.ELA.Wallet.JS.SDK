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
import BigNumber from "bignumber.js";
import { isAddress } from "@ethersproject/address";
import { Buffer } from "buffer";
import { ByteStream } from "../common/bytestream";
import { Error, ErrorChecker } from "../common/ErrorChecker";
import { reverseHashString } from "../common/utils";
import { ChainConfig } from "../config";
import { Asset } from "../transactions/Asset";
import {
  CancelProducer,
  CancelProducerInfo
} from "../transactions/payload/CancelProducer";
import {
  CRCouncilMemberClaimNode,
  CRCouncilMemberClaimNodeInfo,
  CRCouncilMemberClaimNodeVersion
} from "../transactions/payload/CRCouncilMemberClaimNode";
import {
  ChangeCustomIDFeeOwnerInfo,
  ChangeProposalOwnerInfo,
  CRCProposal,
  CRCProposalDefaultVersion,
  CRCProposalInfo,
  CRCProposalType,
  CRCProposalVersion01,
  JsonKeyDraftData,
  JsonKeyType,
  NormalProposalOwnerInfo,
  ReceiveCustomIDOwnerInfo,
  RegisterSidechainProposalInfo,
  ReserveCustomIDOwnerInfo,
  SecretaryElectionInfo,
  TerminateProposalOwnerInfo
} from "../transactions/payload/CRCProposal";
import {
  CRCProposalReview,
  CRCProposalReviewDefaultVersion,
  CRCProposalReviewInfo,
  CRCProposalReviewVersion01,
  JsonKeyOpinionData
} from "../transactions/payload/CRCProposalReview";
import {
  CRCProposalTracking,
  CRCProposalTrackingDefaultVersion,
  CRCProposalTrackingInfo,
  CRCProposalTrackingVersion01,
  JsonKeyMessageData,
  JsonKeySecretaryGeneralOpinionData
} from "../transactions/payload/CRCProposalTracking";
import {
  CRCProposalWithdrawVersion_01,
  CRCProposalWithdraw,
  CRCProposalWithdrawInfo
} from "../transactions/payload/CRCProposalWithdraw";
import {
  CRInfo,
  CRInfoDIDVersion,
  CRInfoJson,
  CRInfoPayload
} from "../transactions/payload/CRInfo";
import {
  CrossChainOutputVersion,
  PayloadCrossChain
} from "../transactions/payload/OutputPayload/PayloadCrossChain";
import {
  CandidateVotes,
  PayloadVote,
  VoteContent,
  VoteContentArray,
  VoteContentType,
  VOTE_PRODUCER_CR_VERSION,
  VoteContentInfo
} from "../transactions/payload/OutputPayload/PayloadVote";
import { Payload } from "../transactions/payload/Payload";
import {
  ProducerInfo,
  ProducerInfoJson,
  ProducerInfoVersion,
  ProducerInfoDposV2Version
} from "../transactions/payload/ProducerInfo";
import { ReturnDepositCoin } from "../transactions/payload/ReturnDepositCoin";
import { TransferAsset } from "../transactions/payload/TransferAsset";
import {
  TransferCrossChainAsset,
  TransferCrossChainVersion,
  TransferCrossChainVersionV1,
  TransferInfo
} from "../transactions/payload/TransferCrossChainAsset";
import {
  UnregisterCR,
  UnregisterCRInfo,
  UnregisterCRPayload
} from "../transactions/payload/UnregisterCR";
import { Transaction, TransactionType } from "../transactions/Transaction";
import {
  OutputArray,
  TransactionOutput,
  Type
} from "../transactions/TransactionOutput";
import { bytes_t, size_t, uint32_t, uint64_t, uint8_t } from "../types";
import { Address, AddressArray, Prefix } from "../walletcore/Address";
import { CoinInfo } from "../walletcore/CoinInfo";
import { EcdsaSigner } from "../walletcore/ecdsasigner";
import { SHA256 } from "../walletcore/sha256";
import { ElastosBaseSubWallet } from "./ElastosBaseSubWallet";
import { EncodedTx } from "./IElastosBaseSubWallet";
import { MasterWallet } from "./MasterWallet";
import { DEPOSIT_OR_WITHDRAW_FEE, SELA_PER_ELA } from "./SubWallet";
import { UTXOInput, UTXOSet } from "./UTXO";
import { Wallet } from "./Wallet";
import {
  CHAINID_IDCHAIN,
  CHAINID_MAINCHAIN,
  CHAINID_TOKENCHAIN
} from "./WalletCommon";
import { Stake } from "../transactions/payload/Stake";
import {
  PayloadStake,
  PayloadStakeInfo
} from "../transactions/payload/OutputPayload/PayloadStake";
import { Voting, VotingInfo } from "../transactions/payload/Voting";
import {
  DPoSV2ClaimReward,
  DPoSV2ClaimRewardInfo,
  DPoSV2ClaimRewardVersion
} from "../transactions/payload/DPoSV2ClaimReward";
// import {
//   CancelVotes,
//   CancelVotesInfo
// } from "../transactions/payload/CancelVotes";
import { Unstake, UnstakeInfo } from "../transactions/payload/Unstake";

export const DEPOSIT_MIN_ELA = 5000;

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
    inputs: UTXOInput[],
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
    this.UTXOFromJson(utxos, inputs);

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
      ErrorChecker.checkParam(
        !isAddress(sideChainAddress),
        Error.Code.Address,
        "invalid ethsc address"
      );
    } else {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "invalid chain id"
      );
    }

    let payload: Payload;
    let outputs: OutputArray = [];
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

    let result = <EncodedTx>{};
    this.encodeTx(result, tx);

    // ArgInfo("r => {}", result.dump());
    return result;
  }

  getDepositAddress(pubkey: string): string {
    const pub = Buffer.from(pubkey, "hex");
    let depositAddress = Address.newWithPubKey(Prefix.PrefixDeposit, pub);
    return depositAddress.string();
  }

  //////////////////////////////////////////////////
  /*            Producer (DPoS node)              */
  //////////////////////////////////////////////////
  /**
   * Generate payload for registering or updating producer.
   *
   * @param ownerPublicKey The public key to identify a producer. Can't change
   *                       later. The producer reward will be sent to address
   *                       of this public key.
   * @param nodePublicKey  The public key to identify a node. Can be update
   *                       by CreateUpdateProducerTransaction().
   * @param nickName       Nickname of producer.
   * @param url            URL of producer.
   * @param ipAddress      IP address of node. This argument is deprecated.
   * @param location       Location code.
   * @param payPasswd      Pay password is using for signing the payload with
   *                       the owner private key.
   * @param stakeUntil     The block height when your staking expires. It is required in DPoS 2.0 version.
   *
   * @return               The payload in JSON format.
   */
  async generateProducerPayload(
    ownerPublicKey: string,
    nodePublicKey: string,
    nickName: string,
    url: string,
    ipAddress: string,
    location: string,
    stakeUntil: uint32_t,
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
    if (stakeUntil) {
      ErrorChecker.checkParam(
        typeof stakeUntil !== "number",
        Error.Code.InvalidArgument,
        "The type of stakeUntil should be number"
      );
    }

    let ownerPubKey = Buffer.from(ownerPublicKey, "hex");
    EcdsaSigner.getKeyFromPublic(ownerPubKey);

    let nodePubKey = Buffer.from(nodePublicKey, "hex");
    EcdsaSigner.getKeyFromPublic(nodePubKey);

    let pr = new ProducerInfo();
    pr.setPublicKey(ownerPubKey);
    pr.setNodePublicKey(nodePubKey);
    pr.setNickName(nickName);
    pr.setUrl(url);
    pr.setAddress(ipAddress);
    let l: uint64_t = new BigNumber(location);
    pr.setLocation(l);

    let ostream = new ByteStream();
    let version = ProducerInfoVersion;
    if (stakeUntil) {
      version = ProducerInfoDposV2Version;
      pr.setStakeUntil(stakeUntil);
    }
    pr.serializeUnsigned(ostream, version);

    let prUnsigned = ostream.getBytes();
    let signature = await this.getWallet().signWithOwnerKey(
      prUnsigned,
      payPasswd
    );

    pr.setSignature(signature);

    let payloadJson = pr.toJson(version);

    // ArgInfo("r => {}", payloadJson.dump());
    return payloadJson;
  }

  /**
   * Generate payaload for unregistering producer.
   *
   * @param ownerPublicKey The public key to identify a producer.
   * @param payPasswd Pay password is using for signing the payload with the owner private key.
   *
   * @return The payload in JSON format.
   */
  async generateCancelProducerPayload(
    ownerPublicKey: string,
    payPasswd: string
  ) {
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
    pc.setPublicKey(Buffer.from(ownerPublicKey, "hex"));

    let ostream = new ByteStream();
    pc.serializeUnsigned(ostream, 0);
    let pcUnsigned: bytes_t = ostream.getBytes();

    const signature = await this.getWallet().signWithOwnerKey(
      pcUnsigned,
      payPasswd
    );
    pc.setSignature(signature);

    let payloadJson = pc.toJson(0);
    // ArgInfo("r => {}", payloadJson.dump());
    return payloadJson;
  }

  /**
   * Create register producer transaction
   *
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
   * @param payloadJson Generate by GenerateProducerPayload()
   * @param amount Amount must lager than 500,000,000,000 sela
   * @param fee Fee amount. Bigint string in SELA
   * @param memo Remarks string. Can be empty string
   * @return The transaction in JSON format to be signed and published
   */
  createRegisterProducerTransaction(
    inputs: UTXOInput[],
    payloadJson: ProducerInfoJson,
    amount: string,
    fee: string,
    memo: string
  ) {
    let wallet = this.getWallet();

    // ArgInfo("{} {}", wallet.getWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputsJson.dump());
    // ArgInfo("payload: {}", payloadJson.dump());
    // ArgInfo("amount: {}", amount);
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo = new UTXOSet();
    this.UTXOFromJson(utxo, inputs);

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
    let version = ProducerInfoVersion;
    if (payloadJson.StakeUntil) {
      version = ProducerInfoDposV2Version;
    }
    try {
      payload.fromJson(payloadJson, version);
    } catch (e) {
      ErrorChecker.throwParamException(
        Error.Code.JsonFormatError,
        "Payload format err: " + e
      );
    }

    let pubkey: bytes_t = payload.getPublicKey();

    let outputs: OutputArray = [];
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
    tx.setPayloadVersion(version);

    let result = <EncodedTx>{};
    this.encodeTx(result, tx);

    // ArgInfo("r => {}", result.dump());
    return result;
  }

  /**
   * Create update producer transaction.
   *
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
   * @param payloadJson Generate by GenerateProducerPayload().
   * @param fee Fee amount. Bigint string in SELA
   * @param memo Remarks string. Can be empty string.
   *
   * @return The transaction in JSON format to be signed and published.
   */
  createUpdateProducerTransaction(
    inputs: UTXOInput[],
    payloadJson: ProducerInfoJson,
    fee: string,
    memo: string
  ) {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", wallet->GetWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputsJson.dump());
    // ArgInfo("payload: {}", payloadJson.dump());
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo = new UTXOSet();
    this.UTXOFromJson(utxo, inputs);

    let payload = new ProducerInfo();
    let version = ProducerInfoVersion;
    if (payloadJson.StakeUntil) {
      version = ProducerInfoDposV2Version;
    }
    try {
      payload.fromJson(payloadJson, version);
    } catch (e) {
      ErrorChecker.throwParamException(
        Error.Code.JsonFormatError,
        "Payload format err: " + e
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
    tx.setPayloadVersion(version);

    let result = <EncodedTx>{};
    this.encodeTx(result, tx);
    // ArgInfo("r => {}", result.dump());
    return result;
  }

  /**
   * Create cancel producer transaction.
   *
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
   * @param payloadJson Generate by GenerateCancelProducerPayload().
   * @param fee Fee amount. Bigint string in SELA
   * @param memo Remarks string. Can be empty string.
   * @return The transaction in JSON format to be signed and published.
   */
  createCancelProducerTransaction(
    inputs: UTXOInput[],
    payloadJson: CancelProducerInfo,
    fee: string,
    memo: string
  ) {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", wallet.getWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputsJson.dump());
    // ArgInfo("payload: {}", payloadJson.dump());
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo = new UTXOSet();
    this.UTXOFromJson(utxo, inputs);

    let payload = new CancelProducer();
    try {
      payload.fromJson(payloadJson, 0);
    } catch (e) {
      ErrorChecker.throwParamException(
        Error.Code.JsonFormatError,
        "Payload format err: " + e
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

    let result = <EncodedTx>{};
    this.encodeTx(result, tx);

    // ArgInfo("r => {}", result.dump());
    return result;
  }

  /**
   * Create retrieve deposit transaction.
   *
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
   * @param amount Retrieve amount including fee
   * @param fee Fee amount. Bigint string in SELA
   * @param memo Remarks string. Can be empty string.
   *
   * @return The transaction in JSON format to be signed and published.
   */
  createRetrieveDepositTransaction(
    inputs: UTXOInput[],
    amount: string,
    fee: string,
    memo: string
  ) {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", wallet->GetWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputsJson.dump());
    // ArgInfo("amount: {}", amount);
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo = new UTXOSet();
    this.UTXOFromJson(utxo, inputs);

    let feeAmount = new BigNumber(fee);
    let bgAmount = new BigNumber(amount);
    let outputs: OutputArray = [];
    // code from the dev branch of wallet c++ sdk
    let addresses = wallet.getAddresses(0, 1, false);
    ErrorChecker.checkLogic(
      addresses.length == 0,
      Error.Code.Address,
      "can't get address"
    );
    let receiveAddr: Address = addresses[0];
    outputs.push(
      TransactionOutput.newFromParams(bgAmount.minus(feeAmount), receiveAddr)
    );

    let payload = new ReturnDepositCoin();
    let tx = wallet.createTransaction(
      TransactionType.returnDepositCoin,
      payload,
      utxo,
      outputs,
      memo,
      feeAmount,
      true
    );

    let result = <EncodedTx>{};
    this.encodeTx(result, tx);

    // ArgInfo("r => {}", result.dump());
    return result;
  }

  /**
   * Get owner public key.
   *
   * @return Owner public key.
   */
  getOwnerPublicKey(): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    let publicKey: string = this.getWallet()
      .getOwnerPublilcKey()
      .toString("hex");
    // ArgInfo("r => {}", publicKey);
    return publicKey;
  }

  /**
   * Get address of owner public key
   * @return Address of owner public key
   */
  getOwnerAddress(): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    let address = this.getWallet().getOwnerAddress().string();

    // ArgInfo("r => {}", address);
    return address;
  }

  /**
   * Get deposit address of owner.
   */
  getOwnerDepositAddress(): string {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", wallet.getWalletID(), GetFunName());

    let addrPtr = wallet.getOwnerDepositAddress();
    let addr: string = addrPtr.string();

    // ArgInfo("r => {}", addr);
    return addr;
  }

  /**
   * Get stake address of owner.
   */
  getOwnerStakeAddress(): string {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", wallet.getWalletID(), GetFunName());

    let addrPtr = wallet.getOwnerStakeAddress();
    let addr: string = addrPtr.string();

    // ArgInfo("r => {}", addr);
    return addr;
  }

  /**
   * Get code of stake address of owner.
   */
  getCodeofOwnerStakeAddress(): string {
    let wallet = this.getWallet();
    let addrPtr = wallet.getOwnerStakeAddress();
    return addrPtr.redeemScript().toString("hex");
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
    j: VoteContentInfo[]
  ): { maxAmount: BigNumber } {
    let tmpAmount = new BigNumber(0);

    for (let it = 0; it < j.length; ++it) {
      if (j[it]["Type"] == "CRC") {
        let vc = VoteContent.newFromType(VoteContentType.CRC);
        let candidateVotesJson = j[it]["Candidates"];
        let keys = Object.keys(candidateVotesJson);
        for (let i = 0; i < keys.length; ++i) {
          let voteAmount = new BigNumber(0);
          const rs = this.voteAmountFromJson(
            voteAmount,
            candidateVotesJson[keys[i]]
          );
          if (rs) {
            voteAmount = new BigNumber(candidateVotesJson[keys[i]]);
          }

          let key = keys[i];
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
      } else if (j[it]["Type"] == "CRCProposal") {
        let vc = VoteContent.newFromType(VoteContentType.CRCProposal);
        let candidateVotesJson = j[it]["Candidates"];
        let keys = Object.keys(candidateVotesJson);
        for (let i = 0; i < keys.length; ++i) {
          let voteAmount = new BigNumber(0);
          let rs = this.voteAmountFromJson(
            voteAmount,
            candidateVotesJson[keys[i]]
          );
          if (rs) {
            voteAmount = new BigNumber(candidateVotesJson[keys[i]]);
          }

          let key = keys[i];
          let proposalHash = Buffer.from(reverseHashString(key), "hex");
          ErrorChecker.checkParam(
            proposalHash.length != 32,
            Error.Code.InvalidArgument,
            "invalid proposal hash"
          );

          vc.addCandidate(
            CandidateVotes.newFromParams(proposalHash, voteAmount)
          );
        }
        tmpAmount = vc.getMaxVoteAmount();
        if (tmpAmount.gt(maxAmount)) {
          maxAmount = tmpAmount;
        }
        voteContents.push(vc);
      } else if (j[it]["Type"] == "CRCImpeachment") {
        let vc = VoteContent.newFromType(VoteContentType.CRCImpeachment);
        let candidateVotesJson = j[it]["Candidates"];
        let keys = Object.keys(candidateVotesJson);
        for (let i = 0; i < keys.length; ++i) {
          let voteAmount = new BigNumber(0);
          let rs = this.voteAmountFromJson(
            voteAmount,
            candidateVotesJson[keys[i]]
          );
          if (rs) {
            voteAmount = new BigNumber(candidateVotesJson[keys[i]]);
          }

          let key = keys[i];
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
      } else if (j[it]["Type"] == "Delegate") {
        let vc = VoteContent.newFromType(VoteContentType.Delegate);
        let candidateVotesJson = j[it]["Candidates"];
        let keys = Object.keys(candidateVotesJson);
        for (let i = 0; i < keys.length; ++i) {
          let voteAmount = new BigNumber(0);
          let rs = this.voteAmountFromJson(
            voteAmount,
            candidateVotesJson[keys[i]]
          );
          if (rs) {
            voteAmount = new BigNumber(candidateVotesJson[keys[i]]);
          }

          let key = keys[i];
          let pubkey = Buffer.from(key, "hex");

          vc.addCandidate(CandidateVotes.newFromParams(pubkey, voteAmount));
        }
        tmpAmount = vc.getMaxVoteAmount();
        if (tmpAmount.gt(maxAmount)) {
          maxAmount = tmpAmount;
        }
        voteContents.push(vc);
      }
    }

    return { maxAmount };
  }

  //////////////////////////////////////////////////
  /*                      Vote                    */
  //////////////////////////////////////////////////
  /**
   * Create vote transaction.
   *
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
   * @param voteContents Including all kinds of vote. eg
   *
   * [
   *   {
   *     "Type":"CRC",
   *     "Candidates":
   *     {
   *       "iYMVuGs1FscpgmghSzg243R6PzPiszrgj7": "100000000", // key is CID
   *       ...
   *     }
   *   },
   *   {
   *     "Type":"CRCProposal",
   *     "Candidates":
   *     {
   *       "109780cf45c7a6178ad674ac647545b47b10c2c3e3b0020266d0707e5ca8af7c": "100000000", // key is proposal hash
   *       ...
   *     }
   *   },
   *   {
   *     "Type": "CRCImpeachment",
   *     "Candidates":
   *     {
   *       "innnNZJLqmJ8uKfVHKFxhdqVtvipNHzmZs": "100000000", // key is CID
   *       ...
   *     }
   *   },
   *   {
   *     "Type":"Delegate",
   *     "Candidates":
   *     {
   *       "031f7a5a6bf3b2450cd9da4048d00a8ef1cb4912b5057535f65f3cc0e0c36f13b4": "100000000", // key is a DPoS node's public key
   *       ...
   *     }
   *   }
   * ]
   * @param fee Fee amount. Bigint string in SELA
   * @param memo Remarks string. Can be empty string.

  * @return The transaction in JSON format to be signed and published.
  */
  createVoteTransaction(
    inputs: UTXOInput[],
    voteContents: VoteContentInfo[],
    fee: string,
    memo: string
  ): EncodedTx {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", wallet.getWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputsJson.dump());
    // ArgInfo("voteContent: {}", voteContentsJson.dump());
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxos = new UTXOSet();
    this.UTXOFromJson(utxos, inputs);

    let outputAmount = new BigNumber(0);
    let voteContentArr: VoteContentArray = [];
    let rs = this.voteContentFromJson(
      voteContentArr,
      outputAmount,
      voteContents
    );

    if (rs && rs.maxAmount) {
      outputAmount = rs.maxAmount;
    }

    let outputPayload = PayloadVote.newFromParams(
      voteContentArr,
      VOTE_PRODUCER_CR_VERSION
    );

    let outputs: OutputArray = [];
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

    let result = <EncodedTx>{};
    this.encodeTx(result, tx);

    // ArgInfo("r => {}", result.dump());
    return result;
  }

  //////////////////////////////////////////////////
  /*                      CRC                    */
  //////////////////////////////////////////////////

  /**
   * Get CR deposit
   * @return
   */
  getCRDepositAddress(): string {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", wallet.getWalletID(), GetFunName());

    let addrPtr = wallet.getCROwnerDepositAddress();
    let addr = addrPtr.string();

    // ArgInfo("r => {}", addr);

    return addr;
  }

  /**
   * Generate cr info payload without signature
   * You can use DID SDK to sign the digest generated by this API to get signature
   * @param crPublicKey    The public key to identify a cr. Can't change later.
   * @param did            DID to be bonded, like `icwTktC5M6fzySQ5yU7bKAZ6ipP623apFY`
   * @param nickName       Nickname of cr.
   * @param url            URL of cr.
   * @param location       Location code.
   *
   * @return               The payload in JSON format contains the "Digest"
   * field to be signed and then set the "Signature" field. Such as
   * {
   *    "Code":"210370a77a257aa81f46629865eb8f3ca9cb052fcfd874e8648cfbea1fbf071b0280ac",
   * 	"CID":"iT42VNGXNUeqJ5yP4iGrqja6qhSEdSQmeP",
   * 	"DID":"icwTktC5M6fzySQ5yU7bKAZ6ipP623apFY",
   * 	"Location":86,
   * 	"NickName":"test",
   * 	"Url":"test.com",
   * 	"Digest":"9970b0612f9146f3f5744f7a843dfa6aac3534a6f44232e08469b212323be573"
   * 	}
   */
  generateCRInfoPayload(
    crPublicKey: string,
    did: string,
    nickName: string,
    url: string,
    location: string
  ): CRInfoPayload {
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

    let pubkey = Buffer.from(crPublicKey, "hex");

    let didAddress = Address.newFromAddressString(did);
    let address = Address.newWithPubKey(Prefix.PrefixStandard, pubkey);

    let crInfo = new CRInfo();
    crInfo.setCode(address.redeemScript());
    crInfo.setDID(didAddress.programHash());
    crInfo.setNickName(nickName);
    crInfo.setUrl(url);
    let l: uint64_t = new BigNumber(location);
    crInfo.setLocation(l);

    let cid = new Address();
    cid.setRedeemScript(Prefix.PrefixIDChain, crInfo.getCode());
    crInfo.setCID(cid.programHash());

    let ostream = new ByteStream();
    crInfo.serializeUnsigned(ostream, CRInfoDIDVersion);
    let digest = SHA256.encodeToBuffer(ostream.getBytes());

    let payloadJson = crInfo.toJson(CRInfoDIDVersion);
    payloadJson["Digest"] = digest.toString("hex");

    delete payloadJson.Signature;
    return {
      ...payloadJson,
      Digest: digest.toString("hex")
    };
  }

  /**
   * Generate unregister cr payload without signature.
   * You can use DID SDK to sign the digest generated by this API to get signature
   * @param CID          The cid of cr will unregister, like `iT42VNGXNUeqJ5yP4iGrqja6qhSEdSQmeP`
   * @return             The payload in JSON format contains the "Digest"
   * field to be signed and then set the "Signature" field.
   * Such as
   * {
   * 	"CID":"iT42VNGXNUeqJ5yP4iGrqja6qhSEdSQmeP",
   * 	"Digest":"8e17a8bcacc5d70b5b312fccefc19d25d88ac6450322a846132e859509b88001"
   * 	}
   */
  generateUnregisterCRPayload(CID: string): UnregisterCRPayload {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("CID: {}", CID);

    let cid = Address.newFromAddressString(CID);
    ErrorChecker.checkParam(
      !cid.valid(),
      Error.Code.InvalidArgument,
      "invalid crDID"
    );

    let unregisterCR = new UnregisterCR();
    unregisterCR.setCID(cid.programHash());

    let ostream = new ByteStream();
    unregisterCR.serializeUnsigned(ostream, 0);
    let digest = SHA256.encodeToBuffer(ostream.getBytes());

    let payloadJson = unregisterCR.toJson(0);

    return {
      CID: payloadJson.CID,
      Digest: digest.toString("hex")
    };
  }

  /**
   * Create register cr transaction.
   *
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
   * @param payloadJson Generate by GenerateCRInfoPayload().
   * @param amount Amount must lager than 500,000,000,000 sela
   * @param fee Fee amount. Bigint string in SELA
   * @param memo Remarks string. Can be empty string.
   * @return The transaction in JSON format to be signed and published.
   */
  createRegisterCRTransaction(
    inputs: UTXOInput[],
    payloadJson: CRInfoJson,
    amount: string,
    fee: string,
    memo: string
  ): EncodedTx {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", wallet.getWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputsJson.dump());
    // ArgInfo("payload: {}", payloadJSON.dump());
    // ArgInfo("amount: {}", amount);
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo = new UTXOSet();
    this.UTXOFromJson(utxo, inputs);

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
      !payloadJson["Signature"],
      Error.Code.InvalidArgument,
      "Signature can not be empty"
    );

    let payloadVersion: uint8_t = CRInfoDIDVersion;
    let payload = new CRInfo();
    try {
      payload.fromJson(payloadJson, payloadVersion);
      ErrorChecker.checkParam(
        !payload.isValid(payloadVersion),
        Error.Code.InvalidArgument,
        "verify signature failed"
      );
    } catch (e) {
      ErrorChecker.throwParamException(
        Error.Code.JsonFormatError,
        "Payload format err: " + e
      );
    }

    let code = payload.getCode();
    let receiveAddr = new Address();
    receiveAddr.setRedeemScript(Prefix.PrefixDeposit, code);

    let outputs: OutputArray = [];
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

    let result = <EncodedTx>{};
    this.encodeTx(result, tx);

    // ArgInfo("r => {}", result.dump());
    return result;
  }

  /**
   * Create update cr transaction.
   *
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
   * @param payloadJson Generate by GenerateCRInfoPayload().
   * @param fee Fee amount. Bigint string in SELA
   * @param memo Remarks string. Can be empty string.
   * @return The transaction in JSON format to be signed and published.
   */
  createUpdateCRTransaction(
    inputs: UTXOInput[],
    payloadJson: CRInfoJson,
    fee: string,
    memo: string
  ): EncodedTx {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", wallet.getWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputsJson.dump());
    // ArgInfo("payload: {}", payloadJSON.dump());
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo = new UTXOSet();
    this.UTXOFromJson(utxo, inputs);

    let payloadVersion: uint8_t = CRInfoDIDVersion;
    let payload = new CRInfo();
    try {
      payload.fromJson(payloadJson, payloadVersion);
    } catch (e) {
      ErrorChecker.throwParamException(
        Error.Code.JsonFormatError,
        "Payload format err: " + e
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

    let result = <EncodedTx>{};
    this.encodeTx(result, tx);

    // ArgInfo("r => {}", result.dump());
    return result;
  }

  /**
   * Create unregister cr transaction.
   *
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
   * @param payloadJson Generate by GenerateUnregisterCRPayload().
   * @param fee Fee amount. Bigint string in SELA
   * @param memo Remarks string. Can be empty string.
   * @return The transaction in JSON format to be signed and published.
   */
  createUnregisterCRTransaction(
    inputs: UTXOInput[],
    payloadJson: UnregisterCRInfo,
    fee: string,
    memo: string
  ): EncodedTx {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", wallet.getWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputsJson.dump());
    // ArgInfo("payload: {}", payloadJSON.dump());
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo = new UTXOSet();
    this.UTXOFromJson(utxo, inputs);

    ErrorChecker.checkParam(
      !payloadJson["Signature"],
      Error.Code.InvalidArgument,
      "invalied signature"
    );

    let payload = new UnregisterCR();
    try {
      payload.fromJson(payloadJson, 0);
    } catch (e) {
      ErrorChecker.throwParamException(
        Error.Code.JsonFormatError,
        "Payload format err: " + e
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

    let result = <EncodedTx>{};
    this.encodeTx(result, tx);

    // ArgInfo("r => {}", result.dump());
    return result;
  }

  /**
   * Create retrieve deposit cr transaction.
   *
   * @param inputs UTXO which will be used. eg
   * [
   *   {
   *     "TxHash": "...", // string
   *     "Index": 0, // int
   *     "Address": "DreWWZa4k6XuUcKcJRzSGUdGHMopoXnGUY", // string, deposit address
   *     "Amount": "501000000000" // bigint string in SELA
   *   }
   * ]
   * @param amount Retrieve amount including fee
   * @param fee Fee amount. Bigint string in SELA
   * @param memo Remarks string. Can be empty string.
   * @return The transaction in JSON format to be signed and published.
   */
  createRetrieveCRDepositTransaction(
    inputs: UTXOInput[],
    amount: string,
    fee: string,
    memo: string
  ): EncodedTx {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", wallet.getWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputsJson.dump());
    // ArgInfo("amount: {}", amount);
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo = new UTXOSet();
    this.UTXOFromJson(utxo, inputs);

    let feeAmount = new BigNumber(fee);
    let bgAmount = new BigNumber(amount);

    let outputs: OutputArray = [];
    // code from the dev branch of c++ sdk
    let addresses: AddressArray = wallet.getAddresses(0, 1, false);
    ErrorChecker.checkParam(
      addresses.length == 0,
      Error.Code.InvalidArgument,
      "can't get address"
    );
    outputs.push(
      TransactionOutput.newFromParams(bgAmount.minus(feeAmount), addresses[0])
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

    let result = <EncodedTx>{};
    this.encodeTx(result, tx);
    // ArgInfo("r => {}", result.dump());
    return result;
  }

  /**
   * Generate digest for signature of CR council members
   * @param payload
   * {
   *   "NodePublicKey": "...",
   *   "CRCouncilMemberDID": "...",
   * }
   * @return
   */
  CRCouncilMemberClaimNodeDigest(
    payload: CRCouncilMemberClaimNodeInfo
  ): string {
    // let wallet = this.getWallet();
    // ArgInfo("{} {}", wallet.getWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload.dump());

    let version: uint8_t = CRCouncilMemberClaimNodeVersion;
    let p = new CRCouncilMemberClaimNode();
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

    let digest = p.digestUnsigned(version);

    // ArgInfo("r => {}", digest);
    return digest;
  }

  /**
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
   * @param payloadJson
   * {
   *   "NodePublicKey": "...",
   *   "CRCouncilMemberDID": "...",
   *   "CRCouncilMemberSignature": "..."
   * }
   * @param fee Fee amount. Bigint string in SELA
   * @param memo Remarks string. Can be empty string.
   * @return
   */
  createCRCouncilMemberClaimNodeTransaction(
    inputs: UTXOInput[],
    payloadJson: CRCouncilMemberClaimNodeInfo,
    fee: string,
    memo: string
  ): EncodedTx {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", wallet.getWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputsJson.dump());
    // ArgInfo("payload: {}", payloadJson.dump());
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo = new UTXOSet();
    this.UTXOFromJson(utxo, inputs);

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

    let result = <EncodedTx>{};
    this.encodeTx(result, tx);
    // ArgInfo("r => {}", result.dump());

    return result;
  }

  //////////////////////////////////////////////////
  /*                     Proposal                 */
  //////////////////////////////////////////////////
  /**
   * Generate digest of payload.
   *
   * @param payload Proposal payload. Must contain the following:
   * {
   *    "Type": 0,
   *    "CategoryData": "testdata",  // limit: 4096 bytes
   *    "OwnerPublicKey": "031f7a5a6bf3b2450cd9da4048d00a8ef1cb4912b5057535f65f3cc0e0c36f13b4",
   *    "DraftHash": "a3d0eaa466df74983b5d7c543de6904f4c9418ead5ffd6d25814234a96db37b0",
   *    "DraftData": "", // Optional, string format, limit 1 Mbytes
   *    "Budgets": [{"Type":0,"Stage":0,"Amount":"300"},{"Type":1,"Stage":1,"Amount":"33"},{"Type":2,"Stage":2,"Amount":"344"}],
   *    "Recipient": "EPbdmxUVBzfNrVdqJzZEySyWGYeuKAeKqv", // address
   * }
   *
   * Type can be value as below:
   * {
   *	 Normal: 0x0000
   *	 ELIP: 0x0100
   * }
   *
   * Budget must contain the following:
   * {
   *   "Type": 0,             // imprest = 0, normalPayment = 1, finalPayment = 2
   *   "Stage": 0,            // value can be [0, 128)
   *   "Amount": "100000000"  // sela
   * }
   *
   * @return Digest of payload.
   */
  proposalOwnerDigest(payload: NormalProposalOwnerInfo): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload.dump());

    let proposal: CRCProposal = new CRCProposal();
    let version: uint8_t = CRCProposalDefaultVersion;
    try {
      if (payload[JsonKeyDraftData]) {
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

    let digest: string = proposal.digestNormalOwnerUnsigned(version);

    // ArgInfo("r => {}", digest);
    return digest;
  }

  /**
   * Generate digest of payload.
   *
   * @param payload Proposal payload. Must contain the following:
   * {
   *    "Type": 0,                   // same as mention on method ProposalOwnerDigest()
   *    "CategoryData": "testdata",  // limit: 4096 bytes
   *    "OwnerPublicKey": "031f7a5a6bf3b2450cd9da4048d00a8ef1cb4912b5057535f65f3cc0e0c36f13b4", // Owner DID public key
   *    "DraftHash": "a3d0eaa466df74983b5d7c543de6904f4c9418ead5ffd6d25814234a96db37b0",
   *    "DraftData": "", // Optional, string format, limit 1 Mbytes
   *    "Budgets": [                 // same as mention on method ProposalOwnerDigest()
   *      {"Type":0,"Stage":0,"Amount":"300"},{"Type":1,"Stage":1,"Amount":"33"},{"Type":2,"Stage":2,"Amount":"344"}
   *    ],
   *    "Recipient": "EPbdmxUVBzfNrVdqJzZEySyWGYeuKAeKqv", // address
   *
   *    // signature of owner
   *    "Signature": "ff0ff9f45478f8f9fcd50b15534c9a60810670c3fb400d831cd253370c42a0af79f7f4015ebfb4a3791f5e45aa1c952d40408239dead3d23a51314b339981b76",
   *    "CRCouncilMemberDID": "icwTktC5M6fzySQ5yU7bKAZ6ipP623apFY"
   * }
   *
   * @return Digest of payload.
   */
  proposalCRCouncilMemberDigest(payload: NormalProposalOwnerInfo): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload);

    let proposal: CRCProposal = new CRCProposal();
    let version: uint8_t = CRCProposalDefaultVersion;
    try {
      if (payload[JsonKeyDraftData]) {
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

    let digest: string = proposal.digestNormalCRCouncilMemberUnsigned(version);
    // ArgInfo("r => {}", digest);
    return digest;
  }

  /**
   * Calculate proposal hash.
   *
   * @param payload Proposal payload signed by owner and CR committee. Same as payload of CreateProposalTransaction()
   * @param memo Remarks string. Can be empty string.
   * @return The transaction in JSON format to be signed and published.
   */
  calculateProposalHash(payload: CRCProposalInfo): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload);

    let p = new CRCProposal();
    let version: uint8_t = CRCProposalDefaultVersion;
    try {
      if (payload[JsonKeyDraftData]) {
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

  /**
   * Create proposal transaction.
   *
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
   * @param payload Proposal payload signed by owner and CR committee.
   * {
   *    "Type": 0,                   // same as mention on method ProposalOwnerDigest()
   *    "CategoryData": "testdata",  // limit: 4096 bytes
   *    "OwnerPublicKey": "031f7a5a6bf3b2450cd9da4048d00a8ef1cb4912b5057535f65f3cc0e0c36f13b4", // Owner DID public key
   *    "DraftHash": "a3d0eaa466df74983b5d7c543de6904f4c9418ead5ffd6d25814234a96db37b0",
   *    "DraftData": "", // Optional, string format, limit 1 Mbytes
   *    "Budgets": [                 // same as mention on method ProposalOwnerDigest()
   *      {"Type":0,"Stage":0,"Amount":"300"},{"Type":1,"Stage":1,"Amount":"33"},{"Type":2,"Stage":2,"Amount":"344"}
   *    ],
   *    "Recipient": "EPbdmxUVBzfNrVdqJzZEySyWGYeuKAeKqv", // address
   *
   *    // signature of owner
   *    "Signature": "ff0ff9f45478f8f9fcd50b15534c9a60810670c3fb400d831cd253370c42a0af79f7f4015ebfb4a3791f5e45aa1c952d40408239dead3d23a51314b339981b76",
   *    "CRCouncilMemberDID": "icwTktC5M6fzySQ5yU7bKAZ6ipP623apFY",
   *    "CRCouncilMemberSignature": "ff0ff9f45478f8f9fcd50b15534c9a60810670c3fb400d831cd253370c42a0af79f7f4015ebfb4a3791f5e45aa1c952d40408239dead3d23a51314b339981b76"
   * }
   *
   * @param fee Fee amount. Bigint string in SELA
   * @param memo Remarks string. Can be empty string
   * @return The transaction in JSON format to be signed and published
   */
  createProposalTransaction(
    inputs: UTXOInput[],
    payload: CRCProposalInfo,
    fee: string,
    memo: string
  ): EncodedTx {
    let wallet: Wallet = this.getWallet();
    // ArgInfo("{} {}", wallet.getWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputsJson);
    // ArgInfo("payload: {}", payload);
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo = new UTXOSet();
    this.UTXOFromJson(utxo, inputs);

    let p = new CRCProposal();
    let version: uint8_t = CRCProposalDefaultVersion;
    try {
      if (payload[JsonKeyDraftData]) {
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

    let result = <EncodedTx>{};
    this.encodeTx(result, tx);

    // ArgInfo("r => {}", result);
    return result;
  }

  //////////////////////////////////////////////////
  /*               Proposal Review                */
  //////////////////////////////////////////////////
  /**
   * Generate digest of payload.
   *
   * @param payload Payload proposal review.
   * {
   *   "ProposalHash": "a3d0eaa466df74983b5d7c543de6904f4c9418ead5ffd6d25814234a96db37b0",
   *   "VoteResult": 1,    // approve = 0, reject = 1, abstain = 2
   *   "OpinionHash": "a3d0eaa466df74983b5d7c543de6904f4c9418ead5ffd6d25814234a96db37b0",
   *   "OpinionData": "", // Optional, string format, limit 1 Mbytes
   *   "DID": "icwTktC5M6fzySQ5yU7bKAZ6ipP623apFY", // did of CR council member
   * }
   *
   * @return Digest of payload.
   */
  proposalReviewDigest(payload: CRCProposalReviewInfo): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload.dump());

    let proposalReview = new CRCProposalReview();
    let version: uint8_t = CRCProposalReviewDefaultVersion;
    try {
      if (payload[JsonKeyOpinionData]) {
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

    let digest = proposalReview.digestUnsigned(version);

    // ArgInfo("r => {}", digest);
    return digest;
  }

  /**
   * Create proposal review transaction.
   *
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
   * @param payload Signed payload.
   * {
   *   "ProposalHash": "a3d0eaa466df74983b5d7c543de6904f4c9418ead5ffd6d25814234a96db37b0",
   *   "VoteResult": 1,    // approve = 0, reject = 1, abstain = 2
   *   "OpinionHash": "a3d0eaa466df74983b5d7c543de6904f4c9418ead5ffd6d25814234a96db37b0",
   *   "OpinionData": "", // Optional, string format, limit 1 Mbytes
   *   "DID": "icwTktC5M6fzySQ5yU7bKAZ6ipP623apFY", // did of CR council member's did
   *   // signature of CR council member
   *   "Signature": "ff0ff9f45478f8f9fcd50b15534c9a60810670c3fb400d831cd253370c42a0af79f7f4015ebfb4a3791f5e45aa1c952d40408239dead3d23a51314b339981b76"
   * }
   *
   * @param fee Fee amount. Bigint string in SELA
   * @param memo Remarks string. Can be empty string.
   * @return The transaction in JSON format to be signed and published.
   */
  createProposalReviewTransaction(
    inputs: UTXOInput[],
    payload: CRCProposalReviewInfo,
    fee: string,
    memo: string
  ): EncodedTx {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", this.getWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputs);
    // ArgInfo("payload: {}", payload);
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo = new UTXOSet();
    this.UTXOFromJson(utxo, inputs);

    let p = new CRCProposalReview();
    let version: uint8_t = CRCProposalReviewDefaultVersion;
    try {
      if (payload[JsonKeyOpinionData]) version = CRCProposalReviewVersion01;
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

    let result = <EncodedTx>{};
    this.encodeTx(result, tx);

    // ArgInfo("r => {}", result);
    return result;
  }

  //////////////////////////////////////////////////
  /*               Proposal Tracking              */
  //////////////////////////////////////////////////
  /**
   * Generate digest of payload.
   *
   * @param payload Proposal tracking payload.
   * {
   *   "ProposalHash": "7c5d2e7cfd7d4011414b5ddb3ab43e2aca247e342d064d1091644606748d7513",
   *   "MessageHash": "0b5ee188b455ab5605cd452d7dda5c205563e1b30c56e93c6b9fda133f8cc4d4",
   *   "MessageData": "", // Optional, string format, limit 800 Kbytes
   *   "Stage": 0, // value can be [0, 128)
   *   "OwnerPublicKey": "02c632e27b19260d80d58a857d2acd9eb603f698445cc07ba94d52296468706331",
   *   // If this proposal tracking is not use for changing owner, will be empty, eg: "NewOwnerPublicKey":"". Otherwise not empty.
   *   "NewOwnerPublicKey": "02c632e27b19260d80d58a857d2acd9eb603f698445cc07ba94d52296468706331",
   * }
   *
   * @return Digest of payload
   */
  proposalTrackingOwnerDigest(payload: CRCProposalTrackingInfo): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload);

    let version: uint8_t = CRCProposalTrackingDefaultVersion;
    let proposalTracking = new CRCProposalTracking();
    try {
      if (payload[JsonKeyMessageData]) version = CRCProposalTrackingVersion01;
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
    let digest = proposalTracking.digestOwnerUnsigned(version);

    // ArgInfo("r => {}", digest);
    return digest;
  }

  /**
   * Generate digest of payload.
   *
   * @param payload Proposal tracking payload.
   * {
   *   "ProposalHash": "7c5d2e7cfd7d4011414b5ddb3ab43e2aca247e342d064d1091644606748d7513",
   *   "MessageHash": "0b5ee188b455ab5605cd452d7dda5c205563e1b30c56e93c6b9fda133f8cc4d4",
   *   "MessageData": "", // Optional, string format, limit 800 Kbytes
   *   "Stage": 0, // value can be [0, 128)
   *   "OwnerPublicKey": "02c632e27b19260d80d58a857d2acd9eb603f698445cc07ba94d52296468706331",
   *   // If this proposal tracking is not use for changing owner, will be empty, eg: "NewOwnerPublicKey":"". Otherwise not empty.
   *   "NewOwnerPublicKey": "02c632e27b19260d80d58a857d2acd9eb603f698445cc07ba94d52296468706331",
   *   "OwnerSignature": "9a24a084a6f599db9906594800b6cb077fa7995732c575d4d125c935446c93bbe594ee59e361f4d5c2142856c89c5d70c8811048bfb2f8620fbc18a06cb58109",
   * }
   *
   * @return Digest of payload.
   */
  proposalTrackingNewOwnerDigest(payload: CRCProposalTrackingInfo): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload);

    let version: uint8_t = CRCProposalTrackingDefaultVersion;
    let proposalTracking = new CRCProposalTracking();
    try {
      if (payload[JsonKeyMessageData]) version = CRCProposalTrackingVersion01;
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

    let digest = proposalTracking.digestNewOwnerUnsigned(version);
    // ArgInfo("r => {}", digest);
    return digest;
  }

  /**
   * Generate digest of payload.
   *
   * @param payload Proposal tracking payload.
   * {
   *   "ProposalHash": "7c5d2e7cfd7d4011414b5ddb3ab43e2aca247e342d064d1091644606748d7513",
   *   "MessageHash": "0b5ee188b455ab5605cd452d7dda5c205563e1b30c56e93c6b9fda133f8cc4d4",
   *   "MessageData": "", // Optional, string format, limit 800 Kbytes
   *   "Stage": 0, // value can be [0, 128)
   *   "OwnerPublicKey": "02c632e27b19260d80d58a857d2acd9eb603f698445cc07ba94d52296468706331",
   *   // If this proposal tracking is not use for changing owner, will be empty, eg: "NewOwnerPublicKey":"". Otherwise not empty.
   *   "NewOwnerPublicKey": "02c632e27b19260d80d58a857d2acd9eb603f698445cc07ba94d52296468706331",
   *   "OwnerSignature": "9a24a084a6f599db9906594800b6cb077fa7995732c575d4d125c935446c93bbe594ee59e361f4d5c2142856c89c5d70c8811048bfb2f8620fbc18a06cb58109",
   *   // If NewOwnerPubKey is empty, this must be empty. eg: "NewOwnerSignature":""
   *   "NewOwnerSignature": "9a24a084a6f599db9906594800b6cb077fa7995732c575d4d125c935446c93bbe594ee59e361f4d5c2142856c89c5d70c8811048bfb2f8620fbc18a06cb58109",
   *   "Type": 0, // common = 0, progress = 1, rejected = 2, terminated = 3, changeOwner = 4, finalized = 5
   *   "SecretaryGeneralOpinionHash": "7c5d2e7cfd7d4011414b5ddb3ab43e2aca247e342d064d1091644606748d7513",
   *   "SecretaryGeneralOpinionData": "", // Optional, string format, limit 200 Kbytes
   * }
   *
   * @return Digest of payload
   */
  proposalTrackingSecretaryDigest(payload: CRCProposalTrackingInfo): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload);

    let version: uint8_t = CRCProposalTrackingDefaultVersion;
    let proposalTracking = new CRCProposalTracking();
    try {
      if (
        payload[JsonKeyMessageData] &&
        payload[JsonKeySecretaryGeneralOpinionData]
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

    let digest = proposalTracking.digestSecretaryUnsigned(version);
    // ArgInfo("r => {}", digest);
    return digest;
  }

  /**
   * Create proposal tracking transaction.
   *
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
   * @param payload Proposal tracking payload.
   * {
   *   "ProposalHash": "7c5d2e7cfd7d4011414b5ddb3ab43e2aca247e342d064d1091644606748d7513",
   *   "MessageHash": "0b5ee188b455ab5605cd452d7dda5c205563e1b30c56e93c6b9fda133f8cc4d4",
   *   "MessageData": "", // Optional, string format, limit 800 Kbytes
   *   "Stage": 0, // value can be [0, 128)
   *   "OwnerPublicKey": "02c632e27b19260d80d58a857d2acd9eb603f698445cc07ba94d52296468706331",
   *   // If this proposal tracking is not use for changing owner, will be empty, eg: "NewOwnerPublicKey":"". Otherwise not empty.
   *   "NewOwnerPublicKey": "02c632e27b19260d80d58a857d2acd9eb603f698445cc07ba94d52296468706331",
   *   "OwnerSignature": "9a24a084a6f599db9906594800b6cb077fa7995732c575d4d125c935446c93bbe594ee59e361f4d5c2142856c89c5d70c8811048bfb2f8620fbc18a06cb58109",
   *   // If NewOwnerPubKey is empty, this must be empty. eg: "NewOwnerSignature":""
   *   "NewOwnerSignature": "9a24a084a6f599db9906594800b6cb077fa7995732c575d4d125c935446c93bbe594ee59e361f4d5c2142856c89c5d70c8811048bfb2f8620fbc18a06cb58109",
   *   "Type": 0, // common = 0, progress = 1, rejected = 2, terminated = 3, changeOwner = 4, finalized = 5
   *   "SecretaryGeneralOpinionHash": "7c5d2e7cfd7d4011414b5ddb3ab43e2aca247e342d064d1091644606748d7513",
   *   "SecretaryGeneralOpinionData": "", // Optional, string format, limit 200 Kbytes
   *   "SecretaryGeneralSignature": "9a24a084a6f599db9906594800b6cb077fa7995732c575d4d125c935446c93bbe594ee59e361f4d5c2142856c89c5d70c8811048bfb2f8620fbc18a06cb58109"
   * }
   *
   * @param fee Fee amount. Bigint string in SELA
   * @param memo Remarks string. Can be empty string.
   * @return The transaction in JSON format to be signed and published.
   */
  createProposalTrackingTransaction(
    inputs: UTXOInput[],
    payload: CRCProposalTrackingInfo,
    fee: string,
    memo: string
  ): EncodedTx {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", wallet.getWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputsJson);
    // ArgInfo("payload: {}", payload);
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo = new UTXOSet();
    this.UTXOFromJson(utxo, inputs);

    let version: uint8_t = CRCProposalTrackingDefaultVersion;
    let p = new CRCProposalTracking();
    try {
      if (
        payload[JsonKeyMessageData] &&
        payload[JsonKeySecretaryGeneralOpinionData]
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

    let result = <EncodedTx>{};
    this.encodeTx(result, tx);
    // ArgInfo("r => {}", result);

    return result;
  }

  //////////////////////////////////////////////////
  /*      Proposal Secretary General Election     */
  //////////////////////////////////////////////////
  /**
   * @param payload Proposal secretary election payload
   * {
   *    "CategoryData": "testdata",  // limit: 4096 bytes
   *    "OwnerPublicKey": "031f7a5a6bf3b2450cd9da4048d00a8ef1cb4912b5057535f65f3cc0e0c36f13b4",
   *    "DraftHash": "a3d0eaa466df74983b5d7c543de6904f4c9418ead5ffd6d25814234a96db37b0",
   *    "DraftData": "", // Optional, string format, limit 1 Mbytes
   *    "SecretaryGeneralPublicKey": "...",
   *    "SecretaryGeneralDID": "...",
   * }
   * @return
   */
  proposalSecretaryGeneralElectionDigest(
    payload: SecretaryElectionInfo
  ): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload);

    let version: uint8_t = CRCProposalDefaultVersion;
    let proposal = new CRCProposal();
    try {
      if (payload[JsonKeyDraftData]) version = CRCProposalVersion01;
      else version = CRCProposalDefaultVersion;
      let payloadFixed = payload;
      payloadFixed[JsonKeyType] = CRCProposalType.secretaryGeneralElection;
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

    return proposal.digestSecretaryElectionUnsigned(version);
  }

  /**
   * @param payload Proposal secretary election payload
   * {
   *    "CategoryData": "testdata",  // limit: 4096 bytes
   *    "OwnerPublicKey": "031f7a5a6bf3b2450cd9da4048d00a8ef1cb4912b5057535f65f3cc0e0c36f13b4",
   *    "DraftHash": "a3d0eaa466df74983b5d7c543de6904f4c9418ead5ffd6d25814234a96db37b0",
   *    "DraftData": "", // Optional, string format, limit 1 Mbytes
   *    "SecretaryGeneralPublicKey": "...",
   *    "SecretaryGeneralDID": "...",
   *    "Signature": "...",
   *    "SecretaryGeneralSignature": "...",
   *    "CRCouncilMemberDID": "...",
   * }
   * @return
   */
  proposalSecretaryGeneralElectionCRCouncilMemberDigest(
    payload: SecretaryElectionInfo
  ): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload);

    let version: uint8_t = CRCProposalDefaultVersion;
    let proposal = new CRCProposal();
    try {
      if (payload[JsonKeyDraftData]) version = CRCProposalVersion01;
      else version = CRCProposalDefaultVersion;
      let payloadFixed = payload;
      payloadFixed[JsonKeyType] = CRCProposalType.secretaryGeneralElection;
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

    return proposal.digestSecretaryElectionCRCouncilMemberUnsigned(version);
  }

  /**
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
   * @param payload Proposal secretary election payload
   * {
   *    "CategoryData": "testdata",  // limit: 4096 bytes
   *    "OwnerPublicKey": "031f7a5a6bf3b2450cd9da4048d00a8ef1cb4912b5057535f65f3cc0e0c36f13b4",
   *    "DraftHash": "a3d0eaa466df74983b5d7c543de6904f4c9418ead5ffd6d25814234a96db37b0",
   *    "DraftData": "", // Optional, string format, limit 1 Mbytes
   *    "SecretaryGeneralPublicKey": "...",
   *    "SecretaryGeneralDID": "...",
   *    "Signature": "...",
   *    "SecretaryGeneralSignature": "...",
   *    "CRCouncilMemberDID": "...",
   *    "CRCouncilMemberSignature": "..."
   * }
   * @param fee Fee amount. Bigint string in SELA
   * @param memo Remarks string
   * @return
   */
  createSecretaryGeneralElectionTransaction(
    inputs: UTXOInput[],
    payload: CRCProposalInfo,
    fee: string,
    memo: string
  ): EncodedTx {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", wallet.getWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputs);
    // ArgInfo("payload: {}", payload);
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo = new UTXOSet();
    this.UTXOFromJson(utxo, inputs);

    let version: uint8_t = CRCProposalDefaultVersion;
    let p = new CRCProposal();
    try {
      if (payload[JsonKeyDraftData]) version = CRCProposalVersion01;
      else version = CRCProposalDefaultVersion;
      let payloadFixed = payload;
      payloadFixed[JsonKeyType] = CRCProposalType.secretaryGeneralElection;
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

    let result = <EncodedTx>{};
    this.encodeTx(result, tx);
    // ArgInfo("r => {}", result);

    return result;
  }

  //////////////////////////////////////////////////
  /*             Proposal Change Owner            */
  //////////////////////////////////////////////////
  /**
   * Use for owner & new owner sign
   * @param payload Proposal change owner payload
   * {
   *    "CategoryData": "testdata",  // limit: 4096 bytes
   *    "OwnerPublicKey": "...",
   *    "DraftHash": "...",
   *    "DraftData": "", // Optional, string format, limit 1 Mbytes
   *    "TargetProposalHash": "...",
   *    "NewRecipient": "...",
   *    "NewOwnerPublicKey": "...",
   * }
   * @return
   */
  proposalChangeOwnerDigest(payload: ChangeProposalOwnerInfo): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload);

    let version: uint8_t = CRCProposalDefaultVersion;
    let proposal = new CRCProposal();
    try {
      if (payload[JsonKeyDraftData]) version = CRCProposalVersion01;
      else version = CRCProposalDefaultVersion;
      let payloadFixed = payload;
      payloadFixed[JsonKeyType] = CRCProposalType.changeProposalOwner;
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

    let digest: string = proposal.digestChangeOwnerUnsigned(version);

    // ArgInfo("r => {}", digest);
    return digest;
  }

  /**
   * @param payload Proposal change owner payload
   * {
   *    "CategoryData": "testdata",  // limit: 4096 bytes
   *    "OwnerPublicKey": "...",
   *    "DraftHash": "...",
   *    "DraftData": "", // Optional, string format, limit 1 Mbytes
   *    "TargetProposalHash": "...",
   *    "NewRecipient": "...",
   *    "NewOwnerPublicKey": "...",
   *    "Signature": "...",
   *    "NewOwnerSignature": "...",
   *    "CRCouncilMemberDID": "..."
   * }
   * @return
   */
  proposalChangeOwnerCRCouncilMemberDigest(
    payload: ChangeProposalOwnerInfo
  ): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload);

    let version: uint8_t = CRCProposalDefaultVersion;
    let proposal = new CRCProposal();
    try {
      if (payload[JsonKeyDraftData]) version = CRCProposalVersion01;
      else version = CRCProposalDefaultVersion;
      let payloadFixed = payload;
      payloadFixed[JsonKeyType] = CRCProposalType.changeProposalOwner;
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

    let digest = proposal.digestChangeOwnerCRCouncilMemberUnsigned(version);

    // ArgInfo("r => {}", digest);
    return digest;
  }

  /**
   *
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
   * @param payload Proposal change owner payload
   * {
   *    "CategoryData": "testdata",  // limit: 4096 bytes
   *    "OwnerPublicKey": "...",
   *    "DraftHash": "...",
   *    "DraftData": "", // Optional, string format, limit 1 Mbytes
   *    "TargetProposalHash": "...",
   *    "NewRecipient": "...",
   *    "NewOwnerPublicKey": "...",
   *    "Signature": "...",
   *    "NewOwnerSignature": "...",
   *    "CRCouncilMemberDID": "...",
   *    "CRCouncilMemberSignature": "...",
   * }
   * @param fee Fee amount. Bigint string in SELA
   * @param memo Remark string.
   * @return
   */
  createProposalChangeOwnerTransaction(
    inputs: UTXOInput[],
    payload: CRCProposalInfo,
    fee: string,
    memo: string
  ): EncodedTx {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", wallet.getWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputs);
    // ArgInfo("payload: {}", payload);
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo = new UTXOSet();
    this.UTXOFromJson(utxo, inputs);

    let version: uint8_t = CRCProposalDefaultVersion;
    let p = new CRCProposal();
    try {
      if (payload[JsonKeyDraftData]) version = CRCProposalVersion01;
      else version = CRCProposalDefaultVersion;
      let payloadFixed = payload;
      payloadFixed[JsonKeyType] = CRCProposalType.changeProposalOwner;
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

    let result = <EncodedTx>{};
    this.encodeTx(result, tx);
    // ArgInfo("r => {}", result);

    return result;
  }

  //////////////////////////////////////////////////
  /*           Proposal Terminate Proposal        */
  //////////////////////////////////////////////////
  /**
   * @param payload Terminate proposal payload
   * {
   *    "CategoryData": "testdata",  // limit: 4096 bytes
   *    "OwnerPublicKey": "...",
   *    "DraftHash": "...",
   *    "DraftData": "", // Optional, string format, limit 1 Mbytes
   *    "TargetProposalHash": "...",
   * }
   * @return
   */
  terminateProposalOwnerDigest(payload: TerminateProposalOwnerInfo): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload);

    let version: uint8_t = CRCProposalDefaultVersion;
    let proposal = new CRCProposal();
    try {
      if (payload[JsonKeyDraftData]) version = CRCProposalVersion01;
      else version = CRCProposalDefaultVersion;
      let payloadFixed = payload;
      payloadFixed[JsonKeyType] = CRCProposalType.terminateProposal;
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

    let digest: string = proposal.digestTerminateProposalOwnerUnsigned(version);

    // ArgInfo("r => {}", digest);
    return digest;
  }

  /**
   * @param payload Terminate proposal payload
   * {
   *    "CategoryData": "testdata",  // limit: 4096 bytes
   *    "OwnerPublicKey": "...",
   *    "DraftHash": "...",
   *    "DraftData": "", // Optional, string format, limit 1 Mbytes
   *    "TargetProposalHash": "...",
   *    "Signature": "...",
   *    "CRCouncilMemberDID": "...",
   * }
   * @return
   */
  terminateProposalCRCouncilMemberDigest(
    payload: TerminateProposalOwnerInfo
  ): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload);

    let version: uint8_t = CRCProposalDefaultVersion;
    let proposal = new CRCProposal();
    try {
      if (payload[JsonKeyDraftData]) version = CRCProposalVersion01;
      else version = CRCProposalDefaultVersion;
      let payloadFixed = payload;
      payloadFixed[JsonKeyType] = CRCProposalType.terminateProposal;
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

    let digest =
      proposal.digestTerminateProposalCRCouncilMemberUnsigned(version);

    // ArgInfo("r => {}", digest);
    return digest;
  }

  /**
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
   * @param payload Terminate proposal payload
   * {
   *    "CategoryData": "testdata",  // limit: 4096 bytes
   *    "OwnerPublicKey": "...",
   *    "DraftHash": "...",
   *    "DraftData": "", // Optional, string format, limit 1 Mbytes
   *    "TargetProposalHash": "...",
   *    "Signature": "...",
   *    "CRCouncilMemberDID": "...",
   *    "CRCouncilMemberSignature": "...",
   * }
   * @param fee Fee amount. Bigint string in SELA
   * @param memo Remark string
   * @return
   */
  createTerminateProposalTransaction(
    inputs: UTXOInput[],
    payload: CRCProposalInfo,
    fee: string,
    memo: string
  ): EncodedTx {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", wallet.getWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputs);
    // ArgInfo("payload: {}", payload);
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo = new UTXOSet();
    this.UTXOFromJson(utxo, inputs);

    let version: uint8_t = CRCProposalDefaultVersion;
    let p = new CRCProposal();
    try {
      if (payload[JsonKeyDraftData]) version = CRCProposalVersion01;
      else version = CRCProposalDefaultVersion;
      let payloadFixed = payload;
      payloadFixed[JsonKeyType] = CRCProposalType.terminateProposal;
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

    let result = <EncodedTx>{};
    this.encodeTx(result, tx);
    // ArgInfo("r => {}", result);

    return result;
  }

  //////////////////////////////////////////////////
  /*              Reserve Custom ID               */
  //////////////////////////////////////////////////
  /**
   * @param payload Reserve Custom ID payload
   * {
   *    "CategoryData": "testdata",  // limit: 4096 bytes
   *    "OwnerPublicKey": "...",
   *    "DraftHash": "...",
   *    "DraftData": "", // Optional, string format, limit 1 Mbytes
   *    "ReservedCustomIDList": ["...", "...", ...],
   * }
   * @return
   */
  reserveCustomIDOwnerDigest(payload: ReserveCustomIDOwnerInfo): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload);

    let version: uint8_t = CRCProposalDefaultVersion;
    let proposal = new CRCProposal();
    try {
      if (payload[JsonKeyDraftData]) version = CRCProposalVersion01;
      else version = CRCProposalDefaultVersion;
      let payloadFixed = payload;
      payloadFixed[JsonKeyType] = CRCProposalType.reserveCustomID;
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

    let digest = proposal.digestReserveCustomIDOwnerUnsigned(version);

    // ArgInfo("r => {}", digest);
    return digest;
  }

  /**
   * @param payload Reserve Custom ID payload
   * {
   *    "CategoryData": "testdata",  // limit: 4096 bytes
   *    "OwnerPublicKey": "...",
   *    "DraftHash": "...",
   *    "DraftData": "", // Optional, string format, limit 1 Mbytes
   *    "ReservedCustomIDList": ["...", "...", ...],
   *    "Signature": "...",
   *    "CRCouncilMemberDID": "icwTktC5M6fzySQ5yU7bKAZ6ipP623apFY",
   * }
   * @return
   */
  reserveCustomIDCRCouncilMemberDigest(
    payload: ReserveCustomIDOwnerInfo
  ): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload);

    let version: uint8_t = CRCProposalDefaultVersion;
    let proposal = new CRCProposal();
    try {
      if (payload[JsonKeyDraftData]) version = CRCProposalVersion01;
      else version = CRCProposalDefaultVersion;
      let payloadFixed = payload;
      payloadFixed[JsonKeyType] = CRCProposalType.reserveCustomID;
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

    let digest = proposal.digestReserveCustomIDCRCouncilMemberUnsigned(version);

    // ArgInfo("r => {}", digest);
    return digest;
  }

  /**
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
   * @param payload Reserve Custom ID payload
   * {
   *    "CategoryData": "testdata",  // limit: 4096 bytes
   *    "OwnerPublicKey": "...",
   *    "DraftHash": "...",
   *    "DraftData": "", // Optional, string format, limit 1 Mbytes
   *    "ReservedCustomIDList": ["...", "...", ...],
   *    "Signature": "...",
   *    "CRCouncilMemberDID": "icwTktC5M6fzySQ5yU7bKAZ6ipP623apFY",
   *    "CRCouncilMemberSignature": "...",
   * }
   * @param fee Fee amount. Bigint string in SELA
   * @param memo Remark string
   * @return
   */
  createReserveCustomIDTransaction(
    inputs: UTXOInput[],
    payload: CRCProposalInfo,
    fee: string,
    memo: string
  ): EncodedTx {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", wallet.getWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputs);
    // ArgInfo("payload: {}", payload);
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo = new UTXOSet();
    this.UTXOFromJson(utxo, inputs);

    let version: uint8_t = CRCProposalDefaultVersion;
    let p = new CRCProposal();
    try {
      if (payload[JsonKeyDraftData]) version = CRCProposalVersion01;
      else version = CRCProposalDefaultVersion;
      let payloadFixed = payload;
      payloadFixed[JsonKeyType] = CRCProposalType.reserveCustomID;
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

    let result = <EncodedTx>{};
    this.encodeTx(result, tx);
    // ArgInfo("r => {}", result);

    return result;
  }

  //////////////////////////////////////////////////
  /*               Receive Custom ID              */
  //////////////////////////////////////////////////
  /**
   * @param payload Receive Custom ID payload
   * {
   *    "CategoryData": "testdata",  // limit: 4096 bytes
   *    "OwnerPublicKey": "...",
   *    "DraftHash": "...",
   *    "DraftData": "", // Optional, string format, limit 1 Mbytes
   *    "ReceivedCustomIDList": ["...", "...", ...],
   *    "ReceiverDID": "iT42VNGXNUeqJ5yP4iGrqja6qhSEdSQmeP"
   * }
   * @return
   */
  receiveCustomIDOwnerDigest(payload: ReceiveCustomIDOwnerInfo): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload.dum);

    let version: uint8_t = CRCProposalDefaultVersion;
    let proposal = new CRCProposal();
    try {
      if (payload[JsonKeyDraftData]) version = CRCProposalVersion01;
      else version = CRCProposalDefaultVersion;
      let payloadFixed = payload;
      payloadFixed[JsonKeyType] = CRCProposalType.receiveCustomID;
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

    let digest = proposal.digestReceiveCustomIDOwnerUnsigned(version);

    // ArgInfo("r => {}", digest);
    return digest;
  }

  /**
   * @param payload Receive Custom ID payload
   * {
   *    "CategoryData": "testdata",  // limit: 4096 bytes
   *    "OwnerPublicKey": "...",
   *    "DraftHash": "...",
   *    "DraftData": "", // Optional, string format, limit 1 Mbytes
   *    "ReceivedCustomIDList": ["...", "...", ...],
   *    "ReceiverDID": "iT42VNGXNUeqJ5yP4iGrqja6qhSEdSQmeP"
   *    "Signature": "...",
   *    "CRCouncilMemberDID": "icwTktC5M6fzySQ5yU7bKAZ6ipP623apFY",
   * }
   * @return
   */
  receiveCustomIDCRCouncilMemberDigest(
    payload: ReceiveCustomIDOwnerInfo
  ): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload);

    let version: uint8_t = CRCProposalDefaultVersion;
    let proposal = new CRCProposal();
    try {
      if (payload[JsonKeyDraftData]) version = CRCProposalVersion01;
      else version = CRCProposalDefaultVersion;
      let payloadFixed = payload;
      payloadFixed[JsonKeyType] = CRCProposalType.receiveCustomID;
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

    let digest = proposal.digestReceiveCustomIDCRCouncilMemberUnsigned(version);

    // ArgInfo("r => {}", digest);
    return digest;
  }

  /**
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
   * @param payload Receive Custom ID payload
   * {
   *    "CategoryData": "testdata",  // limit: 4096 bytes
   *    "OwnerPublicKey": "...",
   *    "DraftHash": "...",
   *    "DraftData": "", // Optional, string format, limit 1 Mbytes
   *    "ReceivedCustomIDList": ["...", "...", ...],
   *    "ReceiverDID": "iT42VNGXNUeqJ5yP4iGrqja6qhSEdSQmeP"
   *    "Signature": "...",
   *    "CRCouncilMemberDID": "icwTktC5M6fzySQ5yU7bKAZ6ipP623apFY",
   *    "CRCouncilMemberSignature": "...",
   * }
   * @param fee Fee amount. Bigint string in SELA
   * @param memo Remark string
   * @return
   */
  createReceiveCustomIDTransaction(
    inputs: UTXOInput[],
    payload: CRCProposalInfo,
    fee: string,
    memo: string
  ): EncodedTx {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", this.getWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputs);
    // ArgInfo("payload: {}", payload);
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo = new UTXOSet();
    this.UTXOFromJson(utxo, inputs);

    let version: uint8_t = CRCProposalDefaultVersion;
    let p = new CRCProposal();
    try {
      if (payload[JsonKeyDraftData]) version = CRCProposalVersion01;
      else version = CRCProposalDefaultVersion;
      let payloadFixed = payload;
      payloadFixed[JsonKeyType] = CRCProposalType.receiveCustomID;
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

    let result = <EncodedTx>{};
    this.encodeTx(result, tx);
    // ArgInfo("r => {}", result.dump());

    return result;
  }

  //////////////////////////////////////////////////
  /*              Change Custom ID Fee            */
  //////////////////////////////////////////////////
  /**
   * @param payload Change custom ID fee payload
   * {
   *    "CategoryData": "testdata",  // limit: 4096 bytes
   *    "OwnerPublicKey": "...",
   *    "DraftHash": "...",
   *    "DraftData": "", // Optional, string format, limit 1 Mbytes
   *    "CustomIDFeeRateInfo": {
   *      "RateOfCustomIDFee": 10000,
   *      "EIDEffectiveHeight": 10000
   *    }
   * }
   * @return
   */
  changeCustomIDFeeOwnerDigest(payload: ChangeCustomIDFeeOwnerInfo): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload.dump());

    let version: uint8_t = CRCProposalDefaultVersion;
    let proposal = new CRCProposal();
    try {
      if (payload[JsonKeyDraftData]) version = CRCProposalVersion01;
      else version = CRCProposalDefaultVersion;
      let payloadFixed = payload;
      payloadFixed[JsonKeyType] = CRCProposalType.changeCustomIDFee;
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

    let digest: string = proposal.digestChangeCustomIDFeeOwnerUnsigned(version);

    // ArgInfo("r => {}", digest);
    return digest;
  }

  /**
   * @param payload Change custom ID fee payload
   * {
   *    "CategoryData": "testdata",  // limit: 4096 bytes
   *    "OwnerPublicKey": "...",
   *    "DraftHash": "...",
   *    "DraftData": "", // Optional, string format, limit 1 Mbytes
   *    "CustomIDFeeRateInfo": {
   *      "RateOfCustomIDFee": 10000,
   *      "EIDEffectiveHeight": 10000
   *    },
   *    "Signature": "...",
   *    "CRCouncilMemberDID": "icwTktC5M6fzySQ5yU7bKAZ6ipP623apFY",
   * }
   * @return
   */
  changeCustomIDFeeCRCouncilMemberDigest(
    payload: ChangeCustomIDFeeOwnerInfo
  ): string {
    // ArgInfo("{} {}", this.getWallet().getWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload.dump());

    let version: uint8_t = CRCProposalDefaultVersion;
    let proposal = new CRCProposal();
    try {
      if (payload[JsonKeyDraftData]) version = CRCProposalVersion01;
      else version = CRCProposalDefaultVersion;
      let payloadFixed = payload;
      payloadFixed[JsonKeyType] = CRCProposalType.changeCustomIDFee;
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

    let digest: string =
      proposal.digestChangeCustomIDFeeCRCouncilMemberUnsigned(version);

    // ArgInfo("r => {}", digest);
    return digest;
  }

  /**
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
   * @param payload Change custom ID fee payload
   * {
   *    "CategoryData": "testdata",  // limit: 4096 bytes
   *    "OwnerPublicKey": "...",
   *    "DraftHash": "...",
   *    "DraftData": "", // Optional, string format, limit 1 Mbytes
   *    "CustomIDFeeRateInfo": {
   *      "RateOfCustomIDFee": 10000,
   *      "EIDEffectiveHeight": 10000
   *    },
   *    "Signature": "...",
   *    "CRCouncilMemberDID": "icwTktC5M6fzySQ5yU7bKAZ6ipP623apFY",
   *    "CRCouncilMemberSignature": "...",
   * }
   * @param fee Fee amount. Bigint string in SELA
   * @param memo Remark string
   * @return
   */
  createChangeCustomIDFeeTransaction(
    inputs: UTXOInput[],
    payload: CRCProposalInfo,
    fee: string,
    memo: string
  ): EncodedTx {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", this.getSubWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputs);
    // ArgInfo("payload: {}", payload);
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo = new UTXOSet();
    this.UTXOFromJson(utxo, inputs);

    let version: uint8_t = CRCProposalDefaultVersion;
    let p = new CRCProposal();
    try {
      if (payload[JsonKeyDraftData]) version = CRCProposalVersion01;
      else version = CRCProposalDefaultVersion;
      let payloadFixed = payload;
      payloadFixed[JsonKeyType] = CRCProposalType.changeCustomIDFee;
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

    let result = <EncodedTx>{};
    this.encodeTx(result, tx);
    // ArgInfo("r => {}", result);

    return result;
  }

  //////////////////////////////////////////////////
  /*               Proposal Withdraw              */
  //////////////////////////////////////////////////
  /**
   * Generate digest of payload.
   *
   * @param payload Proposal payload.
   * {
   *   "ProposalHash": "7c5d2e7cfd7d4011414b5ddb3ab43e2aca247e342d064d1091644606748d7513",
   *   "OwnerPublicKey": "02c632e27b19260d80d58a857d2acd9eb603f698445cc07ba94d52296468706331",
   *   "Recipient": "EPbdmxUVBzfNrVdqJzZEySyWGYeuKAeKqv", // address
   *   "Amount": "100000000", // 1 ela = 100000000 sela
   * }
   *
   * @return Digest of payload.
   */
  proposalWithdrawDigest(payload: CRCProposalWithdrawInfo) {
    // ArgInfo("{} {}", _walletManager->GetWallet()->GetWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload.dump());

    let version: uint8_t = CRCProposalWithdrawVersion_01;
    let proposalWithdraw = new CRCProposalWithdraw();
    try {
      proposalWithdraw.fromJsonUnsigned(payload, version);
    } catch (e) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "convert from json"
      );
    }

    if (!proposalWithdraw.isValidUnsigned(version))
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "invalid payload"
      );

    let digest = proposalWithdraw.digestUnsigned(version);

    // ArgInfo("r => {}", digest);
    return digest;
  }

  /**
   * Create proposal withdraw transaction.
   * @inputs UTXO which will be used. eg
   * [
   *   {
   *     "TxHash": "...", // string
   *     "Index": 123, // int
   *     "Address": "...", // string
   *     "Amount": "100000000" // bigint string in SELA
   *   },
   *   ...
   * ]
   * @payload Proposal payload.
   * {
   *   "ProposalHash": "7c5d2e7cfd7d4011414b5ddb3ab43e2aca247e342d064d1091644606748d7513",
   *   "OwnerPublicKey": "02c632e27b19260d80d58a857d2acd9eb603f698445cc07ba94d52296468706331",
   *   "Recipient": "EPbdmxUVBzfNrVdqJzZEySyWGYeuKAeKqv", // address
   *   "Amount": "100000000", // 1 ela = 100000000 sela
   *   "Signature": "9a24a084a6f599db9906594800b6cb077fa7995732c575d4d125c935446c93bbe594ee59e361f4d5c2142856c89c5d70c8811048bfb2f8620fbc18a06cb58109"
   * }
   * @fee Fee amount. Bigint string in SELA
   * @memo Remarks string. Can be empty string.
   *
   * @return Transaction in JSON format.
   */
  createProposalWithdrawTransaction(
    inputsJson: UTXOInput[],
    payload: CRCProposalWithdrawInfo,
    fee: string,
    memo: string
  ): EncodedTx {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", wallet->GetWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputsJson.dump());
    // ArgInfo("payload: {}", payload.dump());
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo = new UTXOSet();
    this.UTXOFromJson(utxo, inputsJson);

    let version = CRCProposalWithdrawVersion_01;
    let p = new CRCProposalWithdraw();
    try {
      p.fromJson(payload, version);
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
      TransactionType.crcProposalWithdraw,
      p,
      utxo,
      [],
      memo,
      feeAmount
    );
    tx.setPayloadVersion(version);

    let result = <EncodedTx>{};
    this.encodeTx(result, tx);
    // ArgInfo("r => {}", result.dump());

    return result;
  }

  //////////////////////////////////////////////////
  /*         Proposal Register side-chain         */
  //////////////////////////////////////////////////
  /**
   * @payload Change custom ID fee payload
   * {
   *    "CategoryData": "testdata",  // limit: 4096 bytes
   *    "OwnerPublicKey": "...",
   *    "DraftHash": "...",
   *    "DraftData": "", // Optional, string format, limit 1 Mbytes
   *    "SidechainInfo": {
   *      "SideChainName": "...",
   *      "MagicNumber": 0, // uint32_t
   *      "GenesisHash": "...", // hexstring of uint256
   *      "ExchangeRate": 1, // uint64_t
   *      "EffectiveHeight": 1000, // uint32_t
   *      "ResourcePath": "..." // path string
   *    }
   * }
   * @return
   */
  registerSidechainOwnerDigest(payload: RegisterSidechainProposalInfo): string {
    // ArgInfo("{} {}", _walletManager->GetWallet()->GetWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload.dump());

    let version: uint8_t = CRCProposalDefaultVersion;
    let proposal = new CRCProposal();
    try {
      if (payload[JsonKeyDraftData]) version = CRCProposalVersion01;
      else version = CRCProposalDefaultVersion;
      let payloadFixed = payload;
      payloadFixed[JsonKeyType] = CRCProposalType.registerSideChain;
      proposal.fromJsonRegisterSidechainUnsigned(payloadFixed, version);
    } catch (e) {
      ErrorChecker.throwParamException(Error.Code.InvalidArgument, "from json");
    }

    if (!proposal.isValidRegisterSidechainUnsigned(version)) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "invalid payload"
      );
    }

    return proposal.digestRegisterSidechainUnsigned(version);
  }

  /**
   * @payload Change custom ID fee payload
   * {
   *    "CategoryData": "testdata",  // limit: 4096 bytes
   *    "OwnerPublicKey": "...",
   *    "DraftHash": "...",
   *    "DraftData": "", // Optional, string format, limit 1 Mbytes
   *    "SidechainInfo": {
   *      "SideChainName": "...",
   *      "MagicNumber": 0, // uint32_t
   *      "GenesisHash": "...", // hexstring of uint256
   *      "ExchangeRate": 1, // uint64_t
   *      "EffectiveHeight": 1000, // uint32_t
   *      "ResourcePath": "..." // path string
   *    }
   *    "Signature": "...",
   *    "CRCouncilMemberDID": "icwTktC5M6fzySQ5yU7bKAZ6ipP623apFY",
   * }
   * @return
   */
  registerSidechainCRCouncilMemberDigest(
    payload: RegisterSidechainProposalInfo
  ): string {
    // ArgInfo("{} {}", _walletManager->GetWallet()->GetWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload.dump());

    let version = CRCProposalDefaultVersion;
    let proposal = new CRCProposal();
    try {
      if (payload[JsonKeyDraftData]) version = CRCProposalVersion01;
      else version = CRCProposalDefaultVersion;
      let payloadFixed = payload;
      payloadFixed[JsonKeyType] = CRCProposalType.registerSideChain;
      proposal.fromJsonRegisterSidechainCRCouncilMemberUnsigned(
        payloadFixed,
        version
      );
    } catch (e) {
      ErrorChecker.throwParamException(Error.Code.InvalidArgument, "from json");
    }

    if (!proposal.isValidRegisterSidechainCRCouncilMemberUnsigned(version)) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "invalid payload"
      );
    }

    return proposal.digestRegisterSidechainCRCouncilMemberUnsigned(version);
  }

  /**
   * @inputs UTXO which will be used. eg
   * [
   *   {
   *     "TxHash": "...", // string
   *     "Index": 123, // int
   *     "Address": "...", // string
   *     "Amount": "100000000" // bigint string in SELA
   *   },
   *   ...
   * ]
   * @payload Register side-chain payload
   * {
   *    "CategoryData": "testdata",  // limit: 4096 bytes
   *    "OwnerPublicKey": "...",
   *    "DraftHash": "...",
   *    "DraftData": "", // Optional, string format, limit 1 Mbytes
   *    "SidechainInfo": {
   *      "SideChainName": "...",
   *      "MagicNumber": 0, // uint32_t
   *      "GenesisHash": "...", // hexstring of uint256
   *      "ExchangeRate": 1, // uint64_t
   *      "EffectiveHeight": 1000, // uint32_t
   *      "ResourcePath": "..." // path string
   *    }
   *    "Signature": "...",
   *    "CRCouncilMemberDID": "icwTktC5M6fzySQ5yU7bKAZ6ipP623apFY",
   *    "CRCouncilMemberSignature": "...",
   * }
   * @fee Fee amount. Bigint string in SELA
   * @memo Remark string
   * @return
   */
  createRegisterSidechainTransaction(
    inputs: UTXOInput[],
    payload: CRCProposalInfo,
    fee: string,
    memo: string
  ): EncodedTx {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", GetSubWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputs.dump());
    // ArgInfo("payload: {}", payload.dump());
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo = new UTXOSet();
    this.UTXOFromJson(utxo, inputs);

    let version = CRCProposalDefaultVersion;
    let p = new CRCProposal();
    try {
      if (payload[JsonKeyDraftData]) version = CRCProposalVersion01;
      else version = CRCProposalDefaultVersion;
      let payloadFixed = payload;
      payloadFixed[JsonKeyType] = CRCProposalType.registerSideChain;
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

    let result = <EncodedTx>{};
    this.encodeTx(result, tx);
    // ArgInfo("r => {}", result.dump());

    return result;
  }

  //////////////////////////////////////////////////
  /*            DPoS 2.0 new transactions         */
  //////////////////////////////////////////////////
  /**
   * @param inputs tx inputs in json format
   * [
   *   {
   *     "TxHash": "...", // string
   *     "Index": 123, // int
   *     "Address": "...", // string
   *     "Amount": "100000000" // bigint string in SELA
   *   },
   *   ...
   * ]
   * @param payload
   * {
   *   "Version": 0, // uint8_t
   *   "StakeAddress": "...",
   * }
   * @param lockAddress lock addres
   * @param amount stake amount. bigint string in SELA
   * @param fee Fee amount. Bigint string in SELA
   * @param memo Remark string
   * @return
   */
  createStakeTransaction(
    inputs: UTXOInput[],
    payload: PayloadStakeInfo,
    lockAddress: string,
    amount: string,
    fee: string,
    memo: string
  ) {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", GetSubWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputs.dump());
    // ArgInfo("payload: {}", payload.dump());
    // ArgInfo("lockAddress: {}", lockAddress);
    // ArgInfo("amount: {}", amount);
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo = new UTXOSet();
    this.UTXOFromJson(utxo, inputs);

    let version = 0;
    let p = new Stake();
    let outputpayload = new PayloadStake();
    try {
      outputpayload.fromJson(payload);
    } catch (e) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "payload from json"
      );
    }

    let bgAmount = new BigNumber(amount);
    let receiveAddr = Address.newFromAddressString(lockAddress);

    let outputs: TransactionOutput[] = [];
    outputs.push(
      TransactionOutput.newFromParams(
        bgAmount,
        receiveAddr,
        Asset.getELAAssetID(),
        Type.Stake,
        outputpayload
      )
    );

    let feeAmount = new BigNumber(fee);

    let tx = wallet.createTransaction(
      TransactionType.Stake,
      p,
      utxo,
      outputs,
      memo,
      feeAmount
    );
    tx.setPayloadVersion(version);

    let result = <EncodedTx>{};
    this.encodeTx(result, tx);
    // ArgInfo("r => {}", result.dump());

    return result;
  }

  /**
   * @param inputs only accept ordinary addresses with the same private key as the stake address
   * @param payload
   * if version is 0x00
   * {
   *   "Version": 0x00, // uint8_t
   *   "Contents": [
   *     {
   *       "VoteType": 0x00, // uint8_t
   *       "VotesInfo": [
   *         {
   *           "Candidate": "...", // string
   *           "Votes": "100000", // uint64_t
   *           "Locktime": 1000000 // uint32_t
   *         },
   *         ...
   *       ]
   *     },
   *     ...
   *   ]
   * }
   *
   * if version is 0x01
   * {
   *   "Version": 0x01,
   *   "RenewalVotesContent": [
   *     {
   *       "ReferKey": "0x...", // uint256 string
   *       "VoteInfo": {
   *         "Candidate": "...", // string
   *         "Votes": "10000", // uint64_t
   *         "Locktime": 100000000 // uint32_t
   *       }
   *     },
   *     ...
   *   ]
   * }
   * @param fee Fee amount. Bigint string in SELA
   * @param memo Remark string
   * @return
   */
  createDPoSV2VoteTransaction(
    inputs: UTXOInput[],
    payload: VotingInfo,
    fee: string,
    memo: string
  ) {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", GetSubWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputs.dump());
    // ArgInfo("payload: {}", payload.dump());
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo = new UTXOSet();
    this.UTXOFromJson(utxo, inputs);

    let version = 0;
    let p = new Voting();
    try {
      version = payload["Version"];
      p.fromJson(payload, version);
    } catch (e) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "payload from json"
      );
    }

    let feeAmount = new BigNumber(fee);

    let tx = wallet.createTransaction(
      TransactionType.Voting,
      p,
      utxo,
      [],
      memo,
      feeAmount
    );
    tx.setPayloadVersion(version);

    let result = <EncodedTx>{};
    this.encodeTx(result, tx);
    // ArgInfo("r => {}", result.dump());

    return result;
  }

  /**
   * @param payload
   * {
   *   "Amount": "100000000" // Bigint string in SELA, 1 ELA = 100000000 SELA
   * }
   * @return digest of the payload which will be signed
   */
  getDPoSV2ClaimRewardDigest(payload: DPoSV2ClaimRewardInfo): string {
    // let wallet = this.getWallet();
    // ArgInfo("{} {}", GetSubWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload.dump());

    let version = DPoSV2ClaimRewardVersion;
    let p = new DPoSV2ClaimReward();
    try {
      p.fromJsonUnsigned(payload, version);
    } catch (e) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "payload from json"
      );
    }

    return p.digestDPoSV2ClaimReward(version);
  }

  /**
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
   * @param payload
   * {
   *   "Amount": "100000000", // Bigint string in SELA, 1 ELA = 100000000 SELA
   *   "Signature": "..."
   * }
   * @fee Fee amount. Bigint string in SELA
   * @memo Remark string
   * @return
   */
  createDPoSV2ClaimRewardTransaction(
    inputs: UTXOInput[],
    payload: DPoSV2ClaimRewardInfo,
    fee: string,
    memo: string
  ) {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", GetSubWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputs.dump());
    // ArgInfo("payload: {}", payload.dump());
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo = new UTXOSet();
    this.UTXOFromJson(utxo, inputs);

    let version = DPoSV2ClaimRewardVersion;
    let p = new DPoSV2ClaimReward();
    try {
      p.fromJson(payload, version);
    } catch (e) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "payload from json"
      );
    }
    let feeAmount = new BigNumber(fee);

    let tx = wallet.createTransaction(
      TransactionType.DposV2ClaimReward,
      p,
      utxo,
      [],
      memo,
      feeAmount
    );
    tx.setPayloadVersion(version);

    let result = <EncodedTx>{};
    this.encodeTx(result, tx);
    // ArgInfo("r => {}", result.dump());

    return result;
  }

  /**
   * This API is removed.
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
   * @param payload
   * {
   *   "ReferKeys": [
   *     "0x...", // uint256 string
   *     ...
   *   ]
   * }
   * @param fee Fee amount. Bigint string in SELA
   * @param memo Remark string
   * @return
   */
  /*
  createCancelVotesTransaction(
    inputs: UTXOInput[],
    payload: CancelVotesInfo,
    fee: string,
    memo: string
  ) {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", GetSubWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputs.dump());
    // ArgInfo("payload: {}", payload.dump());
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo = new UTXOSet();
    this.UTXOFromJson(utxo, inputs);

    let version = 0;
    let p = new CancelVotes();
    try {
      p.fromJson(payload, version);
    } catch (e) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "payload from json"
      );
    }
    let feeAmount = new BigNumber(fee);

    let tx = wallet.createTransaction(
      TransactionType.CancelVotes,
      p,
      utxo,
      [],
      memo,
      feeAmount
    );
    tx.setPayloadVersion(version);

    let result = <EncodedTx>{};
    this.encodeTx(result, tx);
    // ArgInfo("r => {}", result.dump());
    return result;
  }
  */

  /**
   * @param payload
   * {
   *   "ToAddress": "...", // return voting rights to here
   *   "Code": "...", // hex-string of code
   *   "Value": "100000000" // SELA
   * }
   * @return
   */
  unstakeDigest(payload: UnstakeInfo): string {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", GetSubWalletID(), GetFunName());
    // ArgInfo("payload: {}", payload.dump());

    let version = 0;
    let p = new Unstake();
    try {
      p.fromJsonUnsigned(payload, version);
    } catch (e) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "payload from json"
      );
    }

    return p.digestUnstake(version);
  }

  /**
   * @param inputs inputs UTXO which will be used. eg
   * [
   *   {
   *     "TxHash": "...", // string
   *     "Index": 123, // int
   *     "Address": "...", // string
   *     "Amount": "100000000" // bigint string in SELA
   *   },
   *   ...
   * ]
   * @param payload
   * {
   *   "ToAddress": "...",
   *   "Code": "...",
   *   "Value": "100000000",
   *   "Signature": "..."
   * }
   * @param fee Fee amount. Bigint string in SELA
   * @param memo Remark string
   * @return
   */
  createUnstakeTransaction(
    inputs: UTXOInput[],
    payload: UnstakeInfo,
    fee: string,
    memo: string
  ) {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", GetSubWalletID(), GetFunName());
    // ArgInfo("inputs: {}", inputs.dump());
    // ArgInfo("payload: {}", payload.dump());
    // ArgInfo("fee: {}", fee);
    // ArgInfo("memo: {}", memo);

    let utxo = new UTXOSet();
    this.UTXOFromJson(utxo, inputs);

    let version = 0;
    let p = new Unstake();
    try {
      p.fromJson(payload, version);
    } catch (e) {
      ErrorChecker.throwParamException(
        Error.Code.InvalidArgument,
        "payload from json"
      );
    }

    let feeAmount = new BigNumber(fee);

    let tx = wallet.createTransaction(
      TransactionType.Unstake,
      p,
      utxo,
      [],
      memo,
      feeAmount
    );
    tx.setPayloadVersion(version);

    let result = <EncodedTx>{};
    this.encodeTx(result, tx);
    // ArgInfo("r => {}", result.dump());
    return result;
  }
}
