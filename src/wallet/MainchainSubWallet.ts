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
import { ElastosBaseSubWallet } from "./ElastosBaseSubWallet";
import { json, JSONArray, uint8_t, uint64_t, size_t, bytes_t } from "../types";
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
import { DeterministicKey } from "../walletcore/deterministickey";
import { ProducerInfo } from "../transactions/payload/ProducerInfo";
import { CancelProducer } from "../transactions/payload/CancelProducer";
import { ReturnDepositCoin } from "../transactions/payload/ReturnDepositCoin";
import { ByteStream } from "../common/bytestream";

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

  generateProducerPayload(
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

    pr.setSignature(this.getWallet().signWithOwnerKey(prUnsigned, payPasswd));

    let payloadJson = pr.toJson(0);

    // ArgInfo("r => {}", payloadJson.dump());
    return payloadJson;
  }

  generateCancelProducerPayload(
    ownerPublicKey: string,
    payPasswd: string
  ): json {
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

    pc.setSignature(this.getWallet().signWithOwnerKey(pcUnsigned, payPasswd));

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

  /*
					voteContentFromJson(voteContents: VoteContentArray, maxAmount: BigNumber, j: json): boolean {
					let tmpAmount = new BigNumber(0);

							for (nlohmann::json::const_iterator it = j.cbegin(); it != j.cend(); ++it) {
									if ((*it)["Type"].get<std::string>() == "CRC") {
											VoteContent vc(VoteContent::Type::CRC);
											nlohmann::json candidateVotesJson = (*it)["Candidates"];
											for (nlohmann::json::iterator it = candidateVotesJson.begin(); it != candidateVotesJson.end(); ++it) {
													BigInt voteAmount;
													VoteAmountFromJson(voteAmount, it.value());

													std::string key = it.key();
													Address cid(key);
													ErrorChecker::CheckParam(!cid.Valid(), Error::InvalidArgument, "invalid candidate cid");
													bytes_t candidate = cid.ProgramHash().bytes();

													vc.AddCandidate(CandidateVotes(candidate, voteAmount));
											}
											tmpAmount = vc.GetTotalVoteAmount();
											if (tmpAmount > maxAmount)
													maxAmount = tmpAmount;
											voteContents.push_back(vc);
									} else if ((*it)["Type"].get<std::string>() == "CRCProposal") {
											VoteContent vc(VoteContent::Type::CRCProposal);
											nlohmann::json candidateVotesJson = (*it)["Candidates"];
											for (nlohmann::json::iterator it = candidateVotesJson.begin(); it != candidateVotesJson.end(); ++it) {
													BigInt voteAmount;
													VoteAmountFromJson(voteAmount, it.value());

													uint256 proposalHash;
													proposalHash.SetHex(std::string(it.key()));
													ErrorChecker::CheckParam(proposalHash.size() != 32, Error::InvalidArgument, "invalid proposal hash");

													vc.AddCandidate(CandidateVotes(proposalHash.bytes(), voteAmount));
											}
											tmpAmount = vc.GetMaxVoteAmount();
											if (tmpAmount > maxAmount)
													maxAmount = tmpAmount;
											voteContents.push_back(vc);
									} else if ((*it)["Type"].get<std::string>() == "CRCImpeachment") {
											VoteContent vc(VoteContent::Type::CRCImpeachment);
											nlohmann::json candidateVotesJson = (*it)["Candidates"];
											for (nlohmann::json::iterator it = candidateVotesJson.begin(); it != candidateVotesJson.end(); ++it) {
													BigInt voteAmount;
													VoteAmountFromJson(voteAmount, it.value());

													std::string key = it.key();
													Address cid(key);
													ErrorChecker::CheckParam(!cid.Valid(), Error::InvalidArgument, "invalid candidate cid");
													bytes_t candidate = cid.ProgramHash().bytes();

													vc.AddCandidate(CandidateVotes(candidate, voteAmount));
											}
											tmpAmount = vc.GetTotalVoteAmount();
											if (tmpAmount > maxAmount)
													maxAmount = tmpAmount;
											voteContents.push_back(vc);
									} else if ((*it)["Type"].get<std::string>() == "Delegate") {
											VoteContent vc(VoteContent::Type::Delegate);
											nlohmann::json candidateVotesJson = (*it)["Candidates"];
											for (nlohmann::json::iterator it = candidateVotesJson.begin(); it != candidateVotesJson.end(); ++it) {
													BigInt voteAmount;
													VoteAmountFromJson(voteAmount, it.value());

													bytes_t pubkey;
													pubkey.setHex(it.key());

													vc.AddCandidate(CandidateVotes(pubkey, voteAmount));
											}
											tmpAmount = vc.GetMaxVoteAmount();
											if (tmpAmount > maxAmount)
													maxAmount = tmpAmount;
											voteContents.push_back(vc);
									}
							}

							return true;
			}

					nlohmann::json MainchainSubWallet::CreateVoteTransaction(const nlohmann::json &inputsJson,
					const nlohmann::json &voteContentsJson,
					const std::string &fee,
					const std::string &memo) const {
							WalletPtr wallet = _walletManager->GetWallet();
				ArgInfo("{} {}", wallet->GetWalletID(), GetFunName());
				ArgInfo("inputs: {}", inputsJson.dump());
				ArgInfo("voteContent: {}", voteContentsJson.dump());
				ArgInfo("fee: {}", fee);
				ArgInfo("memo: {}", memo);

							UTXOSet utxos;
							UTXOFromJson(utxos, inputsJson);

							BigInt outputAmount;
							VoteContentArray voteContents;
							VoteContentFromJson(voteContents, outputAmount, voteContentsJson);

							OutputPayloadPtr outputPayload(new PayloadVote(voteContents, VOTE_PRODUCER_CR_VERSION));

							OutputArray outputs;
							OutputPtr output(new TransactionOutput(TransactionOutput(outputAmount, (*utxos.begin())->GetAddress(), Asset::GetELAAssetID(), TransactionOutput::VoteOutput, outputPayload)));
							outputs.push_back(output);

							BigInt feeAmount;
							feeAmount.setDec(fee);

							PayloadPtr payload = PayloadPtr(new TransferAsset());
							TransactionPtr tx = wallet->CreateTransaction(Transaction::transferAsset,
							payload, utxos, outputs, memo, feeAmount, true);

				nlohmann::json result;
				EncodeTx(result, tx);

				ArgInfo("r => {}", result.dump());
				return result;
			}
*/

  getCRDepositAddress(): string {
    let wallet = this.getWallet();
    // ArgInfo("{} {}", wallet.getWalletID(), GetFunName());

    let addrPtr = wallet.getCROwnerDepositAddress();
    let addr = addrPtr.string();

    // ArgInfo("r => {}", addr);

    return addr;
  }

  /*
			nlohmann::json MainchainSubWallet::GenerateCRInfoPayload(
					const std::string &crPublicKey,
					const std::string &did,
					const std::string &nickName,
					const std::string &url,
					uint64_t location) const {
				ArgInfo("{} {}", _walletManager->GetWallet()->GetWalletID(), GetFunName());
				ArgInfo("crPublicKey: {}", crPublicKey);
				ArgInfo("did: {}", did);
				ArgInfo("nickName: {}", nickName);
				ArgInfo("url: {}", url);
				ArgInfo("location: {}", location);

				size_t pubKeyLen = crPublicKey.size() >> 1;
				ErrorChecker::CheckParam(pubKeyLen != 33 && pubKeyLen != 65, Error::PubKeyLength,
																 "Public key length should be 33 or 65 bytes");

				bytes_t pubkey(crPublicKey);

				Address didAddress(did);
				Address address(PrefixStandard, pubkey);

				CRInfo crInfo;
				crInfo.SetCode(address.RedeemScript());
				crInfo.SetDID(didAddress.ProgramHash());
				crInfo.SetNickName(nickName);
				crInfo.SetUrl(url);
				crInfo.SetLocation(location);

				Address cid;
				cid.SetRedeemScript(PrefixIDChain, crInfo.GetCode());
				crInfo.SetCID(cid.ProgramHash());

				ByteStream ostream;
				crInfo.SerializeUnsigned(ostream, CRInfoDIDVersion);
				uint256 digest(sha256(ostream.GetBytes()));

				nlohmann::json payloadJson = crInfo.ToJson(CRInfoDIDVersion);
				payloadJson["Digest"] = digest.GetHex();

				ArgInfo("r => {}", payloadJson.dump());
				return payloadJson;
			}

			nlohmann::json MainchainSubWallet::GenerateUnregisterCRPayload(const std::string &CID) const {
				ArgInfo("{} {}", _walletManager->GetWallet()->GetWalletID(), GetFunName());
				ArgInfo("CID: {}", CID);

				Address cid(CID);
				ErrorChecker::CheckParam(!cid.Valid(), Error::InvalidArgument, "invalid crDID");

				UnregisterCR unregisterCR;
				unregisterCR.SetCID(cid.ProgramHash());

				ByteStream ostream;
				unregisterCR.SerializeUnsigned(ostream, 0);
				uint256 digest(sha256(ostream.GetBytes()));

				nlohmann::json payloadJson = unregisterCR.ToJson(0);
				payloadJson["Digest"] = digest.GetHex();

				ArgInfo("r => {}", payloadJson.dump());
				return payloadJson;
			}

			nlohmann::json MainchainSubWallet::CreateRegisterCRTransaction(
					const nlohmann::json &inputsJson,
					const nlohmann::json &payloadJSON,
					const std::string &amount,
					const std::string &fee,
					const std::string &memo) const {

				WalletPtr wallet = _walletManager->GetWallet();
				ArgInfo("{} {}", wallet->GetWalletID(), GetFunName());
				ArgInfo("inputs: {}", inputsJson.dump());
				ArgInfo("payload: {}", payloadJSON.dump());
				ArgInfo("amount: {}", amount);
				ArgInfo("fee: {}", fee);
				ArgInfo("memo: {}", memo);

				UTXOSet utxo;
				UTXOFromJson(utxo, inputsJson);

				ErrorChecker::CheckBigIntAmount(amount);
				BigInt bgAmount, minAmount(DEPOSIT_MIN_ELA), feeAmount;
				bgAmount.setDec(amount);
				feeAmount.setDec(fee);

				minAmount *= SELA_PER_ELA;

				ErrorChecker::CheckParam(bgAmount < minAmount, Error::DepositAmountInsufficient,
																 "cr deposit amount is insufficient");

				ErrorChecker::CheckParam(payloadJSON.find("Signature") == payloadJSON.end(), Error::InvalidArgument,
																 "Signature can not be empty");

				uint8_t payloadVersion = CRInfoDIDVersion;
				PayloadPtr payload = PayloadPtr(new CRInfo());
				try {
					payload->FromJson(payloadJSON, payloadVersion);
					ErrorChecker::CheckParam(!payload->IsValid(payloadVersion), Error::InvalidArgument, "verify signature failed");
				} catch (const nlohmann::detail::exception &e) {
					ErrorChecker::ThrowParamException(Error::JsonFormatError,
										"Payload format err: " + std::string(e.what()));
				}

				bytes_t code = static_cast<CRInfo *>(payload.get())->GetCode();
				Address receiveAddr;
				receiveAddr.SetRedeemScript(PrefixDeposit, code);

				OutputArray outputs;
				outputs.push_back(OutputPtr(new TransactionOutput(bgAmount, receiveAddr)));

				TransactionPtr tx = wallet->CreateTransaction(Transaction::registerCR, payload, utxo, outputs, memo, feeAmount);
				tx->SetPayloadVersion(payloadVersion);

				nlohmann::json result;
				EncodeTx(result, tx);

				ArgInfo("r => {}", result.dump());
				return result;
			}

			nlohmann::json MainchainSubWallet::CreateUpdateCRTransaction(
					const nlohmann::json &inputsJson,
					const nlohmann::json &payloadJSON,
					const std::string &fee,
					const std::string &memo) const {
				WalletPtr wallet = _walletManager->GetWallet();
				ArgInfo("{} {}", wallet->GetWalletID(), GetFunName());
				ArgInfo("inputs: {}", inputsJson.dump());
				ArgInfo("payload: {}", payloadJSON.dump());
							ArgInfo("fee: {}", fee);
				ArgInfo("memo: {}", memo);

				UTXOSet utxo;
				UTXOFromJson(utxo, inputsJson);

				uint8_t payloadVersion = CRInfoDIDVersion;
				PayloadPtr payload = PayloadPtr(new CRInfo());
				try {
					payload->FromJson(payloadJSON, payloadVersion);
				} catch (const nlohmann::detail::exception &e) {
					ErrorChecker::ThrowParamException(Error::JsonFormatError,
					"Payload format err: " + std::string(e.what()));
				}

				BigInt feeAmount;
				feeAmount.setDec(fee);

				TransactionPtr tx = wallet->CreateTransaction(Transaction::updateCR, payload, utxo, {}, memo, feeAmount);
				tx->SetPayloadVersion(payloadVersion);

				nlohmann::json result;
				EncodeTx(result, tx);

				ArgInfo("r => {}", result.dump());
				return result;

			}

			nlohmann::json MainchainSubWallet::CreateUnregisterCRTransaction(
					const nlohmann::json &inputsJson,
					const nlohmann::json &payloadJSON,
					const std::string &fee,
					const std::string &memo) const {
				WalletPtr wallet = _walletManager->GetWallet();
				ArgInfo("{} {}", wallet->GetWalletID(), GetFunName());
				ArgInfo("inputs: {}", inputsJson.dump());
				ArgInfo("payload: {}", payloadJSON.dump());
				ArgInfo("fee: {}", fee);
				ArgInfo("memo: {}", memo);

				UTXOSet utxo;
				UTXOFromJson(utxo, inputsJson);

				ErrorChecker::CheckParam(payloadJSON.find("Signature") == payloadJSON.end() ||
				payloadJSON["Signature"].get<std::string>() == "",
				Error::InvalidArgument, "invalied signature");

				PayloadPtr payload = PayloadPtr(new UnregisterCR());
				try {
					payload->FromJson(payloadJSON, 0);
				} catch (const nlohmann::detail::exception &e) {
					ErrorChecker::ThrowParamException(Error::JsonFormatError,
							"Payload format err: " + std::string(e.what()));
				}

				BigInt feeAmount;
				feeAmount.setDec(fee);

				TransactionPtr tx = wallet->CreateTransaction(Transaction::unregisterCR, payload, utxo, {}, memo, feeAmount);

				nlohmann::json result;
				EncodeTx(result, tx);

				ArgInfo("r => {}", result.dump());
				return result;
			}

			nlohmann::json MainchainSubWallet::CreateRetrieveCRDepositTransaction(
					const nlohmann::json &inputsJson,
					const std::string &amount,
					const std::string &fee,
					const std::string &memo) const {
							WalletPtr wallet = _walletManager->GetWallet();
				ArgInfo("{} {}", wallet->GetWalletID(), GetFunName());
				ArgInfo("inputs: {}", inputsJson.dump());
							ArgInfo("amount: {}", amount);
				ArgInfo("fee: {}", fee);
				ArgInfo("memo: {}", memo);

				UTXOSet utxo;
				UTXOFromJson(utxo, inputsJson);

				BigInt feeAmount, bgAmount;
				feeAmount.setDec(fee);
				bgAmount.setDec(amount);

							OutputArray outputs;
							Address receiveAddr = (*utxo.begin())->GetAddress();
							outputs.push_back(OutputPtr(new TransactionOutput(bgAmount - feeAmount, receiveAddr)));

				PayloadPtr payload = PayloadPtr(new ReturnDepositCoin());
				TransactionPtr tx = wallet->CreateTransaction(Transaction::returnCRDepositCoin, payload, utxo, outputs, memo, feeAmount, true);

				nlohmann::json result;
				EncodeTx(result, tx);
				ArgInfo("r => {}", result.dump());
				return result;
			}

			std::string MainchainSubWallet::CRCouncilMemberClaimNodeDigest(const nlohmann::json &payload) const {
				WalletPtr wallet = _walletManager->GetWallet();
				ArgInfo("{} {}", wallet->GetWalletID(), GetFunName());
				ArgInfo("payload: {}", payload.dump());


				uint8_t version = CRCouncilMemberClaimNodeVersion;
				CRCouncilMemberClaimNode p;
				try {
					p.FromJsonUnsigned(payload, version);
				} catch (const std::exception &e) {
					ErrorChecker::ThrowParamException(Error::InvalidArgument, "from json");
				}

				if (!p.IsValidUnsigned(version)) {
					ErrorChecker::ThrowParamException(Error::InvalidArgument, "invalid payload");
				}

				std::string digest = p.DigestUnsigned(version).GetHex();

				ArgInfo("r => {}", digest);
				return digest;
			}

			nlohmann::json MainchainSubWallet::CreateCRCouncilMemberClaimNodeTransaction(const nlohmann::json &inputsJson,
																																											 const nlohmann::json &payloadJson,
																																											 const std::string &fee,
																																											 const std::string &memo) const {
				WalletPtr wallet = _walletManager->GetWallet();
				ArgInfo("{} {}", wallet->GetWalletID(), GetFunName());
				ArgInfo("inputs: {}", inputsJson.dump());
				ArgInfo("payload: {}", payloadJson.dump());
							ArgInfo("fee: {}", fee);
				ArgInfo("memo: {}", memo);

				UTXOSet utxo;
				UTXOFromJson(utxo, inputsJson);

				uint8_t version = CRCProposalDefaultVersion;
				PayloadPtr payload(new CRCouncilMemberClaimNode());
				try {
					payload->FromJson(payloadJson, version);
				} catch (const std::exception &e) {
					ErrorChecker::ThrowParamException(Error::InvalidArgument, "from json");
				}

				if (!payload->IsValid(version))
					ErrorChecker::ThrowParamException(Error::InvalidArgument, "invalid payload");

				BigInt feeAmount;
				feeAmount.setDec(fee);

				TransactionPtr tx = wallet->CreateTransaction(Transaction::crCouncilMemberClaimNode, payload, utxo, {}, memo, feeAmount);
				tx->SetPayloadVersion(version);

				nlohmann::json result;
				EncodeTx(result, tx);
				ArgInfo("r => {}", result.dump());

				return result;
			}

			std::string MainchainSubWallet::ProposalOwnerDigest(const nlohmann::json &payload) const {
				ArgInfo("{} {}", _walletManager->GetWallet()->GetWalletID(), GetFunName());
				ArgInfo("payload: {}", payload.dump());

				CRCProposal proposal;
				uint8_t version = CRCProposalDefaultVersion;
				try {
					if (payload.contains(JsonKeyDraftData)) {
						version = CRCProposalVersion01;
					} else {
						version = CRCProposalDefaultVersion;
					}
					proposal.FromJsonNormalOwnerUnsigned(payload, version);
				} catch (const nlohmann::json::exception &e) {
					ErrorChecker::ThrowParamException(Error::InvalidArgument, "convert from json");
				}

				ErrorChecker::CheckParam(!proposal.IsValidNormalOwnerUnsigned(version),
										 Error::InvalidArgument, "invalid payload");

				std::string digest = proposal.DigestNormalOwnerUnsigned(version).GetHex();

				ArgInfo("r => {}", digest);
				return digest;
			}

			std::string MainchainSubWallet::ProposalCRCouncilMemberDigest(const nlohmann::json &payload) const {
				ArgInfo("{} {}", _walletManager->GetWallet()->GetWalletID(), GetFunName());
				ArgInfo("payload: {}", payload.dump());

				CRCProposal proposal;
				uint8_t version = CRCProposalDefaultVersion;
				try {
					if (payload.contains(JsonKeyDraftData)) {
						version = CRCProposalVersion01;
					} else {
						version = CRCProposalDefaultVersion;
					}
					proposal.FromJsonNormalCRCouncilMemberUnsigned(payload, version);
				} catch (const nlohmann::json::exception &e) {
					ErrorChecker::ThrowParamException(Error::InvalidArgument, "convert from json");
				}

				ErrorChecker::CheckParam(!proposal.IsValidNormalCRCouncilMemberUnsigned(version),
										 Error::InvalidArgument, "invalid payload");

				std::string digest = proposal.DigestNormalCRCouncilMemberUnsigned(version).GetHex();

				ArgInfo("r => {}", digest);
				return digest;
			}

			std::string MainchainSubWallet::CalculateProposalHash(const nlohmann::json &payload) const {
				ArgInfo("{} {}", _walletManager->GetWallet()->GetWalletID(), GetFunName());
				ArgInfo("payload: {}", payload.dump());

				PayloadPtr p = PayloadPtr(new CRCProposal());
				uint8_t version = CRCProposalDefaultVersion;
				try {
					if (payload.contains(JsonKeyDraftData)) {
						version = CRCProposalVersion01;
					} else {
						version = CRCProposalDefaultVersion;
					}
					p->FromJson(payload, version);
				} catch (const nlohmann::json::exception &e) {
					ErrorChecker::ThrowParamException(Error::InvalidArgument, "convert from json");
				}

				ErrorChecker::CheckParam(!p->IsValid(version), Error::InvalidArgument, "invalid payload");

				ByteStream stream;
				p->Serialize(stream, version);
				uint256 hash(sha256_2(stream.GetBytes()));
				std::string hashString = hash.GetHex();

				ArgInfo("r => {}", hashString);

				return hashString;
			}

			nlohmann::json MainchainSubWallet::CreateProposalTransaction(const nlohmann::json &inputsJson,
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

				PayloadPtr p = PayloadPtr(new CRCProposal());
				uint8_t version = CRCProposalDefaultVersion;
				try {
					if (payload.contains(JsonKeyDraftData)) {
						version = CRCProposalVersion01;
					} else {
						version = CRCProposalDefaultVersion;
					}
					p->FromJson(payload, version);
				} catch (const nlohmann::json::exception &e) {
					ErrorChecker::ThrowParamException(Error::InvalidArgument, "convert from json");
				}

				ErrorChecker::CheckParam(!p->IsValid(version), Error::InvalidArgument, "invalid payload");

				BigInt feeAmount;
				feeAmount.setDec(fee);

				TransactionPtr tx = wallet->CreateTransaction(Transaction::crcProposal, p, utxo, {}, memo, feeAmount);
				tx->SetPayloadVersion(version);

				nlohmann::json result;
				EncodeTx(result, tx);

				ArgInfo("r => {}", result.dump());
				return result;
			}

			std::string MainchainSubWallet::ProposalReviewDigest(const nlohmann::json &payload) const {
				ArgInfo("{} {}", _walletManager->GetWallet()->GetWalletID(), GetFunName());
				ArgInfo("payload: {}", payload.dump());

				CRCProposalReview proposalReview;
				uint8_t version = CRCProposalReviewDefaultVersion;
				try {
					if (payload.contains(JsonKeyOpinionData)) {
						version = CRCProposalReviewVersion01;
					} else {
						version = CRCProposalReviewDefaultVersion;
					}
					proposalReview.FromJsonUnsigned(payload, version);
				} catch (const nlohmann::json::exception &e) {
					ErrorChecker::ThrowParamException(Error::InvalidArgument, "convert from json");
				}

				if (!proposalReview.IsValidUnsigned(version)) {
					ErrorChecker::ThrowParamException(Error::InvalidArgument, "invalid payload");
				}

				std::string digest = proposalReview.DigestUnsigned(version).GetHex();

				ArgInfo("r => {}", digest);
				return digest;
			}

			nlohmann::json MainchainSubWallet::CreateProposalReviewTransaction(const nlohmann::json &inputsJson,
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

				PayloadPtr p = PayloadPtr(new CRCProposalReview());
				uint8_t version = CRCProposalReviewDefaultVersion;
				try {
					if (payload.contains(JsonKeyOpinionData))
						version = CRCProposalReviewVersion01;
					else
						version = CRCProposalReviewDefaultVersion;
					p->FromJson(payload, version);
				} catch (const nlohmann::json::exception &e) {
					ErrorChecker::ThrowParamException(Error::InvalidArgument, "convert from json");
				}

				if (!p->IsValid(version))
					ErrorChecker::ThrowParamException(Error::InvalidArgument, "invalid payload");

				BigInt feeAmount;
				feeAmount.setDec(fee);

				TransactionPtr tx = wallet->CreateTransaction(Transaction::crcProposalReview, p, utxo, {}, memo, feeAmount);
				tx->SetPayloadVersion(version);

				nlohmann::json result;
				EncodeTx(result, tx);

				ArgInfo("r => {}", result.dump());
				return result;
			}

			std::string MainchainSubWallet::ProposalTrackingOwnerDigest(const nlohmann::json &payload) const {
				ArgInfo("{} {}", _walletManager->GetWallet()->GetWalletID(), GetFunName());
				ArgInfo("payload: {}", payload.dump());

				uint8_t version = CRCProposalTrackingDefaultVersion;
				CRCProposalTracking proposalTracking;
				try {
					if (payload.contains(JsonKeyMessageData))
						version = CRCProposalTrackingVersion01;
					else
						version = CRCProposalTrackingDefaultVersion;
					proposalTracking.FromJsonOwnerUnsigned(payload, version);
				} catch (const nlohmann::json::exception &e) {
					ErrorChecker::ThrowParamException(Error::InvalidArgument, "convert from json");
				}

				if (!proposalTracking.IsValidOwnerUnsigned(version)) {
					ErrorChecker::ThrowParamException(Error::InvalidArgument, "invalid payload");
				}
				std::string digest = proposalTracking.DigestOwnerUnsigned(version).GetHex();

				ArgInfo("r => {}", digest);
				return digest;
			}

			std::string MainchainSubWallet::ProposalTrackingNewOwnerDigest(const nlohmann::json &payload) const {
				ArgInfo("{} {}", _walletManager->GetWallet()->GetWalletID(), GetFunName());
				ArgInfo("payload: {}", payload.dump());

				uint8_t version = CRCProposalTrackingDefaultVersion;
				CRCProposalTracking proposalTracking;
				try {
					if (payload.contains(JsonKeyMessageData))
						version = CRCProposalTrackingVersion01;
					else
						version = CRCProposalTrackingDefaultVersion;
					proposalTracking.FromJsonNewOwnerUnsigned(payload, version);
				} catch (const nlohmann::json::exception &e) {
					ErrorChecker::ThrowParamException(Error::InvalidArgument, "convert from json");
				}

				if (!proposalTracking.IsValidNewOwnerUnsigned(version)) {
					ErrorChecker::ThrowParamException(Error::InvalidArgument, "invalid payload");
				}

				std::string digest = proposalTracking.DigestNewOwnerUnsigned(version).GetHex();

				ArgInfo("r => {}", digest);
				return digest;
			}

			std::string MainchainSubWallet::ProposalTrackingSecretaryDigest(const nlohmann::json &payload) const {
				ArgInfo("{} {}", _walletManager->GetWallet()->GetWalletID(), GetFunName());
				ArgInfo("payload: {}", payload.dump());

				uint8_t version = CRCProposalTrackingDefaultVersion;
				CRCProposalTracking proposalTracking;
				try {
					if (payload.contains(JsonKeyMessageData) && payload.contains(JsonKeySecretaryGeneralOpinionData))
						version = CRCProposalTrackingVersion01;
					else
						version = CRCProposalTrackingDefaultVersion;
					proposalTracking.FromJsonSecretaryUnsigned(payload, version);
				} catch (const nlohmann::json::exception &e) {
					ErrorChecker::ThrowParamException(Error::InvalidArgument, "convert from json");
				}

				if (!proposalTracking.IsValidSecretaryUnsigned(version)) {
					ErrorChecker::ThrowParamException(Error::InvalidArgument, "invalid payload");
				}

				std::string digest = proposalTracking.DigestSecretaryUnsigned(version).GetHex();

				ArgInfo("r => {}", digest);
				return digest;
			}

			nlohmann::json
			MainchainSubWallet::CreateProposalTrackingTransaction(const nlohmann::json &inputsJson,
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

				uint8_t version = CRCProposalTrackingDefaultVersion;
				PayloadPtr p(new CRCProposalTracking());
				try {
					if (payload.contains(JsonKeyMessageData) && payload.contains(JsonKeySecretaryGeneralOpinionData))
						version = CRCProposalTrackingVersion01;
					else
						version = CRCProposalTrackingDefaultVersion;
					p->FromJson(payload, version);
				} catch (const nlohmann::json::exception &e) {
					ErrorChecker::ThrowParamException(Error::InvalidArgument, "convert from json");
				}

				if (!p->IsValid(version))
					ErrorChecker::ThrowParamException(Error::InvalidArgument, "invalid payload");

				BigInt feeAmount;
				feeAmount.setDec(fee);

				TransactionPtr tx = wallet->CreateTransaction(Transaction::crcProposalTracking, p, utxo, {}, memo, feeAmount);
				tx->SetPayloadVersion(version);

				nlohmann::json result;
				EncodeTx(result, tx);
				ArgInfo("r => {}", result.dump());

				return result;
			}

			std::string MainchainSubWallet::ProposalSecretaryGeneralElectionDigest(
				const nlohmann::json &payload) const {
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
					payloadFixed[JsonKeyType] = CRCProposal::secretaryGeneralElection;
					proposal.FromJsonSecretaryElectionUnsigned(payloadFixed, version);
				} catch (const nlohmann::json::exception &e) {
					ErrorChecker::ThrowParamException(Error::InvalidArgument, "from json");
				}

				if (!proposal.IsValidSecretaryElectionUnsigned(version)) {
					ErrorChecker::ThrowParamException(Error::InvalidArgument, "invalid payload");
				}

				std::string digest = proposal.DigestSecretaryElectionUnsigned(version).GetHex();

				ArgInfo("r => {}", digest);
				return digest;
			}

			std::string MainchainSubWallet::ProposalSecretaryGeneralElectionCRCouncilMemberDigest(
				const nlohmann::json &payload) const {
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
					payloadFixed[JsonKeyType] = CRCProposal::secretaryGeneralElection;
					proposal.FromJsonSecretaryElectionCRCouncilMemberUnsigned(payloadFixed, version);
				} catch (const nlohmann::json::exception &e) {
					ErrorChecker::ThrowParamException(Error::InvalidArgument, "from json");
				}

				if (!proposal.IsValidSecretaryElectionCRCouncilMemberUnsigned(version)) {
					ErrorChecker::ThrowParamException(Error::InvalidArgument, "invalid payload");
				}

				std::string digest = proposal.DigestSecretaryElectionCRCouncilMemberUnsigned(version).GetHex();

				ArgInfo("r => {}", digest);
				return digest;
			}

			nlohmann::json MainchainSubWallet::CreateSecretaryGeneralElectionTransaction(
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

				uint8_t version = CRCProposalDefaultVersion;
				PayloadPtr p(new CRCProposal());
				try {
					if (payload.contains(JsonKeyDraftData))
						version = CRCProposalVersion01;
					else
						version = CRCProposalDefaultVersion;
					nlohmann::json payloadFixed = payload;
					payloadFixed[JsonKeyType] = CRCProposal::secretaryGeneralElection;
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

			//////////////////////////////////////////////////
			//             Proposal Change Owner            //
			//////////////////////////////////////////////////
			std::string MainchainSubWallet::ProposalChangeOwnerDigest(const nlohmann::json &payload) const {
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
					payloadFixed[JsonKeyType] = CRCProposal::changeProposalOwner;
					proposal.FromJsonChangeOwnerUnsigned(payloadFixed, version);
				} catch (const nlohmann::json::exception &e) {
					ErrorChecker::ThrowParamException(Error::InvalidArgument, "from json");
				}

				if (!proposal.IsValidChangeOwnerUnsigned(version)) {
					ErrorChecker::ThrowParamException(Error::InvalidArgument, "invalid payload");
				}

				std::string digest = proposal.DigestChangeOwnerUnsigned(version).GetHex();

				ArgInfo("r => {}", digest);
				return digest;
			}

			std::string MainchainSubWallet::ProposalChangeOwnerCRCouncilMemberDigest(const nlohmann::json &payload) const {
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
					payloadFixed[JsonKeyType] = CRCProposal::changeProposalOwner;
					proposal.FromJsonChangeOwnerCRCouncilMemberUnsigned(payloadFixed, version);
				} catch (const nlohmann::json::exception &e) {
					ErrorChecker::ThrowParamException(Error::InvalidArgument, "from json");
				}

				if (!proposal.IsValidChangeOwnerCRCouncilMemberUnsigned(version)) {
					ErrorChecker::ThrowParamException(Error::InvalidArgument, "invalid payload");
				}

				std::string digest = proposal.DigestChangeOwnerCRCouncilMemberUnsigned(version).GetHex();

				ArgInfo("r => {}", digest);
				return digest;
			}

			nlohmann::json MainchainSubWallet::CreateProposalChangeOwnerTransaction(
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

				uint8_t version = CRCProposalDefaultVersion;
				PayloadPtr p(new CRCProposal());
				try {
					if (payload.contains(JsonKeyDraftData))
						version = CRCProposalVersion01;
					else
						version = CRCProposalDefaultVersion;
					nlohmann::json payloadFixed = payload;
					payloadFixed[JsonKeyType] = CRCProposal::changeProposalOwner;
					p->FromJson(payloadFixed, version);
				} catch (const nlohmann::json::exception &e) {
					ErrorChecker::ThrowParamException(Error::InvalidArgument, "from json");
				}

				if (!p->IsValid(version)) {
					ErrorChecker::ThrowParamException(Error::InvalidArgument, "invalid payload");
				}

				BigInt feeAmount;
				feeAmount.setDec(fee);

				TransactionPtr tx = wallet->CreateTransaction(Transaction::crcProposal, p, utxo, {}, memo, feeAmount);
				tx->SetPayloadVersion(version);

				nlohmann::json result;
				EncodeTx(result, tx);
				ArgInfo("r => {}", result.dump());

				return result;
			}

			//////////////////////////////////////////////////
			//           Proposal Terminate Proposal        //
			//////////////////////////////////////////////////
			std::string MainchainSubWallet::TerminateProposalOwnerDigest(const nlohmann::json &payload) const {
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
					payloadFixed[JsonKeyType] = CRCProposal::terminateProposal;
					proposal.FromJsonTerminateProposalOwnerUnsigned(payloadFixed, version);
				} catch (const nlohmann::json::exception &e) {
					ErrorChecker::ThrowParamException(Error::InvalidArgument, "from json");
				}

				if (!proposal.IsValidTerminateProposalOwnerUnsigned(version)) {
					ErrorChecker::ThrowParamException(Error::InvalidArgument, "invalid payload");
				}

				std::string digest = proposal.DigestTerminateProposalOwnerUnsigned(version).GetHex();

				ArgInfo("r => {}", digest);
				return digest;
			}

			std::string MainchainSubWallet::TerminateProposalCRCouncilMemberDigest(const nlohmann::json &payload) const {
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
					payloadFixed[JsonKeyType] = CRCProposal::terminateProposal;
					proposal.FromJsonTerminateProposalCRCouncilMemberUnsigned(payloadFixed, version);
				} catch (const nlohmann::json::exception &e) {
					ErrorChecker::ThrowParamException(Error::InvalidArgument, "from json");
				}

				if (!proposal.IsValidTerminateProposalCRCouncilMemberUnsigned(version)) {
					ErrorChecker::ThrowParamException(Error::InvalidArgument, "invalid payload");
				}

				std::string digest = proposal.DigestTerminateProposalCRCouncilMemberUnsigned(version).GetHex();

				ArgInfo("r => {}", digest);
				return digest;
			}

			nlohmann::json MainchainSubWallet::CreateTerminateProposalTransaction(
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

				uint8_t version = CRCProposalDefaultVersion;
				PayloadPtr p(new CRCProposal());
				try {
					if (payload.contains(JsonKeyDraftData))
						version = CRCProposalVersion01;
					else
						version = CRCProposalDefaultVersion;
					nlohmann::json payloadFixed = payload;
					payloadFixed[JsonKeyType] = CRCProposal::terminateProposal;
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

					//////////////////////////////////////////////////
					//              Reserve Custom ID               //
					//////////////////////////////////////////////////
					std::string MainchainSubWallet::ReserveCustomIDOwnerDigest(const nlohmann::json &payload) const {
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
									payloadFixed[JsonKeyType] = CRCProposal::reserveCustomID;
									proposal.FromJsonReserveCustomIDOwnerUnsigned(payloadFixed, version);
							} catch (const nlohmann::json::exception &e) {
									ErrorChecker::ThrowParamException(Error::InvalidArgument, "from json");
							}

							if (!proposal.IsValidReserveCustomIDOwnerUnsigned(version)) {
									ErrorChecker::ThrowParamException(Error::InvalidArgument, "invalid payload");
							}

							std::string digest = proposal.DigestReserveCustomIDOwnerUnsigned(version).GetHex();

							ArgInfo("r => {}", digest);
							return digest;
					}

					std::string MainchainSubWallet::ReserveCustomIDCRCouncilMemberDigest(const nlohmann::json &payload) const {
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
									payloadFixed[JsonKeyType] = CRCProposal::reserveCustomID;
									proposal.FromJsonReserveCustomIDCRCouncilMemberUnsigned(payloadFixed, version);
							} catch (const nlohmann::json::exception &e) {
									ErrorChecker::ThrowParamException(Error::InvalidArgument, "from json");
							}

							if (!proposal.IsValidReserveCustomIDCRCouncilMemberUnsigned(version)) {
									ErrorChecker::ThrowParamException(Error::InvalidArgument, "invalid payload");
							}

							std::string digest = proposal.DigestReserveCustomIDCRCouncilMemberUnsigned(version).GetHex();

							ArgInfo("r => {}", digest);
							return digest;
					}

					nlohmann::json MainchainSubWallet::CreateReserveCustomIDTransaction(
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

							uint8_t version = CRCProposalDefaultVersion;
							PayloadPtr p(new CRCProposal());
							try {
									if (payload.contains(JsonKeyDraftData))
											version = CRCProposalVersion01;
									else
											version = CRCProposalDefaultVersion;
									nlohmann::json payloadFixed = payload;
									payloadFixed[JsonKeyType] = CRCProposal::reserveCustomID;
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

					//////////////////////////////////////////////////
					//               Receive Custom ID              //
					//////////////////////////////////////////////////
					std::string MainchainSubWallet::ReceiveCustomIDOwnerDigest(const nlohmann::json &payload) const {
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
									payloadFixed[JsonKeyType] = CRCProposal::receiveCustomID;
									proposal.FromJsonReceiveCustomIDOwnerUnsigned(payloadFixed, version);
							} catch (const nlohmann::json::exception &e) {
									ErrorChecker::ThrowParamException(Error::InvalidArgument, "from json");
							}

							if (!proposal.IsValidReceiveCustomIDOwnerUnsigned(version)) {
									ErrorChecker::ThrowParamException(Error::InvalidArgument, "invalid payload");
							}

							std::string digest = proposal.DigestReceiveCustomIDOwnerUnsigned(version).GetHex();

							ArgInfo("r => {}", digest);
							return digest;
					}

					std::string MainchainSubWallet::ReceiveCustomIDCRCouncilMemberDigest(const nlohmann::json &payload) const {
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
									payloadFixed[JsonKeyType] = CRCProposal::receiveCustomID;
									proposal.FromJsonReceiveCustomIDCRCouncilMemberUnsigned(payloadFixed, version);
							} catch (const nlohmann::json::exception &e) {
									ErrorChecker::ThrowParamException(Error::InvalidArgument, "from json");
							}

							if (!proposal.IsValidReceiveCustomIDCRCouncilMemberUnsigned(version)) {
									ErrorChecker::ThrowParamException(Error::InvalidArgument, "invalid payload");
							}

							std::string digest = proposal.DigestReceiveCustomIDCRCouncilMemberUnsigned(version).GetHex();

							ArgInfo("r => {}", digest);
							return digest;
					}

					nlohmann::json MainchainSubWallet::CreateReceiveCustomIDTransaction(
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

							uint8_t version = CRCProposalDefaultVersion;
							PayloadPtr p(new CRCProposal());
							try {
									if (payload.contains(JsonKeyDraftData))
											version = CRCProposalVersion01;
									else
											version = CRCProposalDefaultVersion;
									nlohmann::json payloadFixed = payload;
									payloadFixed[JsonKeyType] = CRCProposal::receiveCustomID;
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

					//////////////////////////////////////////////////
					//              Change Custom ID Fee            //
					//////////////////////////////////////////////////
					std::string MainchainSubWallet::ChangeCustomIDFeeOwnerDigest(const nlohmann::json &payload) const {
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
									payloadFixed[JsonKeyType] = CRCProposal::changeCustomIDFee;
									proposal.FromJsonChangeCustomIDFeeOwnerUnsigned(payloadFixed, version);
							} catch (const nlohmann::json::exception &e) {
									ErrorChecker::ThrowParamException(Error::InvalidArgument, "from json");
							}

							if (!proposal.IsValidChangeCustomIDFeeOwnerUnsigned(version)) {
									ErrorChecker::ThrowParamException(Error::InvalidArgument, "invalid payload");
							}

							std::string digest = proposal.DigestChangeCustomIDFeeOwnerUnsigned(version).GetHex();

							ArgInfo("r => {}", digest);
							return digest;
					}

					std::string MainchainSubWallet::ChangeCustomIDFeeCRCouncilMemberDigest(const nlohmann::json &payload) const {
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
									payloadFixed[JsonKeyType] = CRCProposal::changeCustomIDFee;
									proposal.FromJsonChangeCustomIDFeeCRCouncilMemberUnsigned(payloadFixed, version);
							} catch (const nlohmann::json::exception &e) {
									ErrorChecker::ThrowParamException(Error::InvalidArgument, "from json");
							}

							if (!proposal.IsValidChangeCustomIDFeeCRCouncilMemberUnsigned(version)) {
									ErrorChecker::ThrowParamException(Error::InvalidArgument, "invalid payload");
							}

							std::string digest = proposal.DigestChangeCustomIDFeeCRCouncilMemberUnsigned(version).GetHex();

							ArgInfo("r => {}", digest);
							return digest;
					}

					nlohmann::json MainchainSubWallet::CreateChangeCustomIDFeeTransaction(
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
									payloadFixed[JsonKeyType] = CRCProposal::changeCustomIDFee;
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
