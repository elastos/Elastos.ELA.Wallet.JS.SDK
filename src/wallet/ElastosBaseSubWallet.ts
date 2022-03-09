import BigNumber from "bignumber.js";
import { ByteStream } from "../common/bytestream";
import { Error, ErrorChecker } from "../common/ErrorChecker";
import { Transaction, TransactionType } from "../transactions/Transaction";
import { TransactionOutput } from "../transactions/TransactionOutput";
import { bytes_t, json, uint32_t, uint64_t } from "../types";
import { Address } from "../walletcore/Address";
import { IElastosBaseSubWallet } from "./IElastosBaseSubWallet";
import { SubWallet } from "./SubWallet";
import { CHAINID_IDCHAIN, CHAINID_MAINCHAIN, CHAINID_TOKENCHAIN } from "./WalletCommon";

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

type WalletManagerPtr = SpvService;

export class ElastosBaseSubWallet extends SubWallet implements IElastosBaseSubWallet {
    protected _walletManager: WalletManagerPtr;

    /* ElastosBaseSubWallet::ElastosBaseSubWallet(
            const CoinInfoPtr &info,
            const ChainConfigPtr &config,
            MasterWallet *parent,
            const std::string &netType) :
            SubWallet(info, config, parent) {

        ErrorChecker::CheckParam(_parent->GetAccount()->MasterPubKeyHDPMString().empty(), Error::UnsupportOperation, "unsupport to create elastos based wallet");
        boost::filesystem::path subWalletDBPath = _parent->GetDataPath();
        subWalletDBPath /= _info->GetChainID() + ".db";

        SubAccountPtr subAccount = SubAccountPtr(new SubAccount(_parent->GetAccount()));
        _walletManager = WalletManagerPtr(
                new SpvService(_parent->GetID(), _info->GetChainID(), subAccount, subWalletDBPath,
                               _config, netType));
    }

    const WalletManagerPtr &ElastosBaseSubWallet::GetWalletManager() const {
        return _walletManager;
    }

    void ElastosBaseSubWallet::FlushData() {
        _walletManager->DatabaseFlush();
    }*/

    //default implement ISubWallet
    public GetBasicInfo(): json {
        //ArgInfo("{} {}", GetSubWalletID(), GetFunName());

        return {
            Info: this._walletManager.getWallet().getBasicInfo(),
            ChainID: this._info.getChainID()
        };
    }

    public getAddresses(index: uint32_t, count: uint32_t, internal: boolean): string[] {
        //ArgInfo("{} {}", GetSubWalletID(), GetFunName());
        //ArgInfo("index: {}", index);
        //ArgInfo("count: {}", count);
        //ArgInfo("internal: {}", internal);

        ErrorChecker.CheckParam(index + count <= index, Error.Code.InvalidArgument, "index & count overflow");

        let addresses: Address[] = [];
        this._walletManager.getWallet().getAddresses(addresses, index, count, internal);

        let addressStrings: string[] = [];
        for (let address of addresses)
            addressStrings.push(address.String());

        //ArgInfo("r => {}", j.dump());

        return addressStrings;
    }

    public getPublicKeys(index: uint32_t, count: uint32_t, internal: boolean): json {
        //ArgInfo("{} {}", GetSubWalletID(), GetFunName());
        //ArgInfo("index: {}", index);
        //ArgInfo("count: {}", count);
        //ArgInfo("internal: {}", internal);

        ErrorChecker.CheckParam(index + count <= index, Error.Code.InvalidArgument, "index & count overflow");

        nlohmann::json j;
        this._walletManager.getWallet().getPublickeys(j, index, count, internal);

        //ArgInfo("r => {}", j.dump());
        return j;
    }

    public createTransaction(inputsJson: json, outputsJson: json, fee: string, memo: string): json {
        //ArgInfo("{} {}", GetSubWalletID(), GetFunName());
        //ArgInfo("inputs: {}", inputsJson.dump());
        //ArgInfo("outputs: {}", outputsJson.dump());
        //ArgInfo("fee: {}", fee);
        //ArgInfo("memo: {}", memo);

        let wallet = this._walletManager.getWallet();

        UTXOSet utxos;
        this.UTXOFromJson(utxos, inputsJson);

        OutputArray outputs;
        this.OutputsFromJson(outputs, outputsJson);

        let feeAmount = new BigNumber(fee);

        let payload = new TransferAsset();
        let tx = wallet.createTransaction(TransactionType.transferAsset, payload, utxos, outputs, memo, feeAmount);

        let result: json = {};
        this.encodeTx(result, tx);

        //ArgInfo("r => {}", result.dump());
        return result;
    }

    public SignTransaction(tx: json, payPassword: string): json {
        /* ArgInfo("{} {}", GetSubWalletID(), GetFunName());
        ArgInfo("tx: {}", tx.dump());
        ArgInfo("passwd: *"); */

        let txn = this.DecodeTx(tx);

        this._walletManager.GetWallet().SignTransaction(txn, payPassword);

        let result: json;
        this.encodeTx(result, txn);

        //ArgInfo("r => {}", result.dump());
        return result;
    }

    /*std::string ElastosBaseSubWallet::SignDigest(const std::string &address, const std::string &digest, const std::string &payPassword) const {
        ArgInfo("{} {}", GetSubWalletID(), GetFunName());
        ArgInfo("address: {}", address);
        ArgInfo("digest: {}", digest);
        ArgInfo("payPasswd: *");

        ErrorChecker::CheckParam(digest.size() != 64, Error::InvalidArgument, "invalid digest");
        Address didAddress(address);
        std::string signature = _walletManager->GetWallet()->SignDigestWithAddress(didAddress, uint256(digest), payPassword);

        ArgInfo("r => {}", signature);

        return signature;
    }

    bool ElastosBaseSubWallet::VerifyDigest(const std::string &publicKey, const std::string &digest, const std::string &signature) const {
        ArgInfo("{} {}", GetSubWalletID(), GetFunName());
        ArgInfo("publicKey: {}", publicKey);
        ArgInfo("digest: {}", digest);
        ArgInfo("signature: {}", signature);

        Key k(CTElastos, bytes_t(publicKey));
        bool r = k.Verify(uint256(digest), bytes_t(signature));

        ArgInfo("r => {}", r);
        return r;
    }

    nlohmann::json ElastosBaseSubWallet::GetTransactionSignedInfo(const nlohmann::json &encodedTx) const {
        ArgInfo("{} {}", GetSubWalletID(), GetFunName());
        ArgInfo("tx: {}", encodedTx.dump());

        TransactionPtr tx = DecodeTx(encodedTx);

        nlohmann::json info = tx->GetSignedInfo();

        ArgInfo("r => {}", info.dump());

        return info;
    }

    std::string ElastosBaseSubWallet::ConvertToRawTransaction(const nlohmann::json &tx) {
        ArgInfo("{} {}", GetSubWalletID(), GetFunName());
        ArgInfo("tx: {}", tx.dump());

        TransactionPtr txn = DecodeTx(tx);
        ByteStream stream;
        txn->Serialize(stream);
        std::string rawtx = stream.GetBytes().getHex();

        ArgInfo("r => {}", rawtx);

        return rawtx;
    }*/

    // TODO: result as return value
    protected encodeTx(result: json, tx: Transaction) {
        let stream = new ByteStream();
        tx.Serialize(stream);
        const bytes_t & hex = stream.GetBytes();

        result["Algorithm"] = "base64";
        result["ID"] = tx.getHash().GetHex().substr(0, 8);
        result["Data"] = hex.getBase64();
        result["ChainID"] = this.GetChainID();
        result["Fee"] = tx.GetFee();
    }

    // TODO: replace json with structured type
    protected DecodeTx(encodedTx: json): Transaction {
        if (!("Algorithm" in encodedTx) ||
            !("Data" in encodedTx) ||
            !("ChainID" in encodedTx)) {
            ErrorChecker.ThrowParamException(Error.Code.InvalidArgument, "Invalid input");
        }

        let algorithm: string, data: string, chainID: string;
        let fee: uint64_t = new BigNumber(0);

        try {
            algorithm = encodedTx["Algorithm"] as string;
            data = encodedTx["Data"] as string;
            chainID = encodedTx["ChainID"] as string;
            if ("Fee" in encodedTx)
                fee = new BigNumber(encodedTx["Fee"] as string); // WAS encodedTx["Fee"].get<uint64_t>();
        } catch (e) {
            ErrorChecker.ThrowParamException(Error.Code.InvalidArgument, "Invalid input: " + e);
        }

        if (chainID != this.getChainID()) {
            ErrorChecker.ThrowParamException(Error.Code.InvalidArgument,
                "Invalid input: tx is not belongs to current subwallet");
        }

        let tx: Transaction = null;
        if (this.getChainID() == CHAINID_MAINCHAIN) {
            tx = new Transaction();
        } else if (this.getChainID() == CHAINID_IDCHAIN || this.getChainID() == CHAINID_TOKENCHAIN) {
            // TODO tx = new IDTransaction();
        }

        let rawHex: bytes_t;
        if (algorithm == "base64") {
            rawHex.setBase64(data);
        } else {
            ErrorChecker.CheckCondition(true, Error.Code.InvalidArgument, "Decode tx with unknown algorithm");
        }

        let stream = new ByteStream(rawHex);
        ErrorChecker.CheckParam(!tx.deserialize(stream), Error.Code.InvalidArgument, "Invalid input: deserialize fail");
        tx.SetFee(fee);

        //SPVLOG_DEBUG("decoded tx: {}", tx->ToJson().dump(4));
        return tx;
    }

    /*bool ElastosBaseSubWallet::UTXOFromJson(UTXOSet &utxo, const nlohmann::json &j) const {
        for (nlohmann::json::const_iterator it = j.cbegin(); it != j.cend(); ++it) {
            if (!(*it).contains("TxHash") ||
                !(*it).contains("Index") ||
                !(*it).contains("Address") ||
                !(*it).contains("Amount")) {
                ErrorChecker::ThrowParamException(Error::InvalidArgument, "invalid inputs");
            }

            uint256 hash;
            hash.SetHex((*it)["TxHash"].get<std::string>());
            uint16_t n = (*it)["Index"].get<uint16_t>();

            Address address((*it)["Address"].get<std::string>());
            ErrorChecker::CheckParam(!address.Valid(), Error::InvalidArgument, "invalid address of inputs");

            BigInt amount;
            amount.setDec((*it)["Amount"].get<std::string>());
            ErrorChecker::CheckParam(amount < 0, Error::InvalidArgument, "invalid amount of inputs");

            utxo.insert(UTXOPtr(new UTXO(hash, n, address, amount)));
        }
        return true;
    }*/

    private OutputsFromJson(outputs: TransactionOutput[], j: json): json {
        for (nlohmann:: json::const_iterator it = j.cbegin(); it != j.cend(); ++it) {
            BigInt amount;
            amount.setDec((* it)["Amount"].get < std:: string > ());
            ErrorChecker.CheckParam(amount < 0, Error.Code.InvalidArgument, "invalid amount of outputs");

            Address address((* it)["Address"].get < std:: string > ());
            ErrorChecker.CheckParam(!address.Valid(), Error:: InvalidArgument, "invalid address of outputs");

            let output = new TransactionOutput(amount, address);
            outputs.push_back(output);
        }
        return true;
    }

}