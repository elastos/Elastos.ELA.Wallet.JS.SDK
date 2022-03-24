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

import { MasterWallet } from "./MasterWallet";
import { CoinInfo } from "../walletcore/CoinInfo";
import { Log } from "../common/Log";
import {
  IEthSidechainSubWallet,
  EthereumAmountUnit
} from "./IEthSidechainSubWallet";
import { SubWallet } from "./SubWallet";
import { uint64_t, json } from "../types";
import { ErrorChecker, Error } from "../common/ErrorChecker";
import { DeterministicKey } from "../walletcore/deterministickey";
import { HDKey, KeySpec } from "../walletcore/hdkey";

export class EthSidechainSubWallet
  extends SubWallet
  implements IEthSidechainSubWallet
{
  createTransfer(
    targetAddress: string,
    amount: string,
    amountUnit: EthereumAmountUnit,
    gasPrice: string,
    gasPriceUnit: EthereumAmountUnit,
    gasLimit: string,
    nonce: uint64_t
  ): json {
    /*
    ArgInfo("{} {}", GetSubWalletID(), GetFunName());
    ArgInfo("target: {}", targetAddress);
    ArgInfo("amount: {}", amount);
    ArgInfo("amountUnit: {}", amountUnit);
    ArgInfo("nonce: {}", nonce);
    
		if (amountUnit != EthereumAmountUnit.TOKEN_DECIMAL &&
			amountUnit != EthereumAmountUnit.TOKEN_INTEGER &&
			amountUnit != EthereumAmountUnit.ETHER_WEI &&
			amountUnit != EthereumAmountUnit.ETHER_GWEI &&
			amountUnit != EthereumAmountUnit.ETHER_ETHER) {
			ErrorChecker.throwParamException(Error.Code.InvalidArgument, "invalid amount amtUnit");
		}

		EthereumAmount::Unit amtUnit = EthereumAmount::Unit(amountUnit);
		EthereumAmount::Unit gasUnit = EthereumAmount::Unit(gasPriceUnit);
		nlohmann::json j;
		EthereumTransferPtr tx = _client->_ewm->getWallet()->createTransfer(targetAddress, amount, amtUnit, gasPrice, gasUnit, gasLimit, nonce);

		let rawtx: string = tx->RlpEncode(_client->_ewm->getNetwork()->getRaw(), RLP_TYPE_TRANSACTION_UNSIGNED);

		j["TxUnsigned"] = rawtx;
		j["Fee"] = tx->getFee(amtUnit);
		j["Unit"] = tx->getDefaultUnit();

		ArgInfo("r => {}", j.dump());

		return j;
		*/
  }

  createTransferGeneric(
    targetAddress: string,
    amount: string,
    amountUnit: EthereumAmountUnit,
    gasPrice: string,
    gasPriceUnit: EthereumAmountUnit,
    gasLimit: string,
    data: string,
    nonce: uint64_t
  ): json {
    // ArgInfo("{} {}", GetSubWalletID(), GetFunName());
    // ArgInfo("target: {}", targetAddress);
    // ArgInfo("amount: {}", amount);
    // ArgInfo("amountUnit: {}", amountUnit);
    // ArgInfo("gasPrice: {}", gasPrice);
    // ArgInfo("gasPriceUnit: {}", gasPriceUnit);
    // ArgInfo("gasLimit: {}", gasLimit);
    // ArgInfo("data: {}", data);
    // ArgInfo("nonce: {}", nonce);

    /*
			if (amountUnit != TOKEN_DECIMAL &&
				amountUnit != TOKEN_INTEGER &&
				amountUnit != ETHER_WEI &&
				amountUnit != ETHER_GWEI &&
				amountUnit != ETHER_ETHER) {
				ErrorChecker::ThrowParamException(Error::InvalidArgument, "invalid amount unit");
			}

			EthereumAmount::Unit unit = EthereumAmount::Unit(amountUnit);
			EthereumAmount::Unit gasUnit = EthereumAmount::Unit(gasPriceUnit);
			nlohmann::json j;
			EthereumTransferPtr tx = _client->_ewm->getWallet()->createTransferGeneric(targetAddress,
																					   amount,
																					   unit,
																					   gasPrice,
																					   gasUnit,
																					   gasLimit,
																					   data,
																					   nonce);

            std::string rawtx = tx->RlpEncode(_client->_ewm->getNetwork()->getRaw(), RLP_TYPE_TRANSACTION_UNSIGNED);

			j["TxUnsigned"] = rawtx;
			j["Fee"] = tx->getFee(unit);
			j["Unit"] = tx->getDefaultUnit();

			ArgInfo("r => {}", j.dump());

			return j;
			*/
    return {};
  }

  exportPrivateKey(payPassword: string): string {
    // ArgInfo("{} {}", GetSubWalletID(), GetFunName());
    // ArgInfo("payPasswd: *");
    let k: HDKey = this.getPrivateKey(payPassword);
    const prvkeystring: string = k.getPrivateKeyBytes().toString();
    // ArgInfo("r => *");
    return prvkeystring;
  }

  /*
        EthSidechainSubWallet::EthSidechainSubWallet(const CoinInfoPtr &info,
													 const ChainConfigPtr &config,
													 MasterWallet *parent,
													 const std::string &netType) :
													 SubWallet(info, config, parent) {
			AccountPtr account = _parent->GetAccount();
			bytes_t pubkey = account->GetETHSCPubKey();
			if (pubkey.empty()) {
				if (!account->HasMnemonic() || account->Readonly()) {
					ErrorChecker::ThrowParamException(Error::UnsupportOperation, "unsupport operation: ethsc pubkey is empty");
				} else {
                    ErrorChecker::ThrowParamException(Error::Other, "need to call IMasterWallet::VerifyPayPassword() or re-import wallet first");
				}
			}

            std::string netName = info->GetChainID() + "-" + netType;
            BREthereumNetwork net = FindEthereumNetwork(netName.c_str());
            ErrorChecker::CheckParam(net == NULL, Error::InvalidArgument, "network config not found");
            EthereumNetworkPtr network(new EthereumNetwork(net));
			_client = ClientPtr(new EthereumClient(network, parent->GetDataPath(), pubkey));
			_client->_ewm->getWallet()->setDefaultGasPrice(5000000000);
		}

		/*
		nlohmann::json EthSidechainSubWallet::GetBasicInfo() const {
			ArgInfo("{} {}", GetSubWalletID(), GetFunName());

			EthereumWalletPtr wallet = _client->_ewm->getWallet();
			nlohmann::json j, jinfo;

			jinfo["Symbol"] = wallet->getSymbol();
			jinfo["GasLimit"] = wallet->getDefaultGasLimit();
			jinfo["GasPrice"] = wallet->getDefaultGasPrice();
			jinfo["Account"] = wallet->getAccount()->getPrimaryAddress();
			jinfo["HoldsEther"] = wallet->walletHoldsEther();

			j["Info"] = jinfo;
			j["ChainID"] = _info->GetChainID();

			ArgInfo("r => {}", j.dump());
			return j;
		}

        nlohmann::json EthSidechainSubWallet::GetAddresses(uint32_t index, uint32_t count, bool internal) const {
            ArgInfo("{} {}", GetSubWalletID(), GetFunName());

            std::string addr = _client->_ewm->getWallet()->getAccount()->getPrimaryAddress();
            nlohmann::json j;
            j.push_back(addr);

            ArgInfo("r => {}", j.dump());

            return j;
		}

        nlohmann::json EthSidechainSubWallet::GetPublicKeys(uint32_t index, uint32_t count, bool internal) const {
			ArgInfo("{} {}", GetSubWalletID(), GetFunName());
			ArgInfo("index: {}", index);
			ArgInfo("count: {}", count);
			ArgInfo("internal: {}", internal);

			std::string pubkey = _client->_ewm->getWallet()->getAccount()->getPrimaryAddressPublicKey().getHex();
			nlohmann::json j;
			j.push_back(pubkey);

			ArgInfo("r => {}", j.dump());

			return j;
		}

		nlohmann::json EthSidechainSubWallet::SignTransaction(const nlohmann::json &tx, const std::string &passwd) const {
			ArgInfo("{} {}", GetSubWalletID(), GetFunName());
			ArgInfo("tx: {}", tx.dump());
			ArgInfo("passwd: *");

			std::string rlptx;
			EthereumTransferPtr transfer;
            EthereumAmount::Unit amountUnit;

			try {
				rlptx = tx["TxUnsigned"].get<std::string>();
                amountUnit = EthereumAmount::Unit(tx["Unit"].get<int>());

                BREthereumTransaction transaction = transactionRlpHexDecode (_client->_ewm->getNetwork()->getRaw(), RLP_TYPE_TRANSACTION_UNSIGNED, rlptx.c_str());
                BREthereumTransfer brtransfer = transferCreateWithTransactionOriginating (
                        transaction,
                        (_client->_ewm->getWallet()->walletHoldsEther()
                         ? TRANSFER_BASIS_TRANSACTION
                         : TRANSFER_BASIS_LOG));
                transfer = EthereumTransferPtr(new EthereumTransfer(_client->_ewm.get(), brtransfer, amountUnit));
			} catch (const std::exception &e) {
				ErrorChecker::ThrowParamException(Error::InvalidArgument, "get 'ID' of json failed");
			}

            BRKey prvkey = GetBRPrivateKey(passwd);
			_client->_ewm->getWallet()->signWithPrivateKey(transfer, prvkey);

            std::string rawtx = transfer->RlpEncode(_client->_ewm->getNetwork()->getRaw(), RLP_TYPE_TRANSACTION_SIGNED);
			nlohmann::json j;
			j["Hash"] = transfer->getOriginationTransactionHash();
			j["Fee"] = transfer->getFee(amountUnit);
			j["Unit"] = amountUnit;
            j["TxSigned"] = rawtx;

			ArgInfo("r => {}", j.dump());
			return j;
		}

        std::string EthSidechainSubWallet::SignDigest(const std::string &address, const std::string &digest, const std::string &passwd) const {
		    ArgInfo("{} {}", GetSubWalletID(), GetFunName());
		    ArgInfo("address: {}", address);
		    ArgInfo("digest: {}", digest);
		    ArgInfo("passwd: *");

            std::string addr = _client->_ewm->getWallet()->getAccount()->getPrimaryAddress();
            ErrorChecker::CheckParam(addr != address, Error::InvalidArgument, "Invalid address");

            Key k = GetPrivateKey(passwd);
            std::string sig = k.SignDER(uint256(digest)).getHex();

            ArgInfo("r => {}", sig);

            return sig;
		}

        bool EthSidechainSubWallet::VerifyDigest(const std::string &pubkey, const std::string &digest, const std::string &signature) const {
            ArgInfo("{} {}", GetSubWalletID(), GetFunName());
            ArgInfo("pubkey: {}", pubkey);
            ArgInfo("digest: {}", digest);
            ArgInfo("signature: {}", signature);

            Key k(CTBitcoin, pubkey);
            bool r = k.VerifyDER(uint256(digest), signature);

            ArgInfo("r => {}", r);

            return r;
		}

        BRKey EthSidechainSubWallet::GetBRPrivateKey(const std::string &passwd) const {
		    Key k = GetPrivateKey(passwd);
            BRKey prvkey;

            BRKeySetSecret(&prvkey, (UInt256 *) k.PrvKey().data(), 0);
            BRKeyPubKey(&prvkey, NULL, 0);

            return prvkey;
		}
*/
  getPrivateKey(passwd: string): HDKey {
    let k: HDKey;
    let seed: Buffer = this._parent.getAccount().getSeed(passwd);
    if (seed.length !== 0) {
      seed = this._parent.getAccount().getSeed(passwd);
      let masterKey: HDKey = HDKey.fromMasterSeed(
        seed,
        KeySpec.Bitcoin
      ).deriveWithPath("44'/60'/0'/0/0");
      k = masterKey;
    } else {
      let ethprvkey: Buffer = this._parent
        .getAccount()
        .getSinglePrivateKey(passwd);
      ErrorChecker.checkParam(
        ethprvkey.length != 32,
        Error.Code.Sign,
        "private key not found"
      );
      const key = new DeterministicKey(DeterministicKey.BITCOIN_VERSIONS);
      key.privateKey = ethprvkey;
      k = HDKey.fromKey(key, KeySpec.Bitcoin);
    }
    return k;
  }
}
