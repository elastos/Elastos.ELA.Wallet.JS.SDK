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

import { ByteStream } from "../common/bytestream";
import { Error, ErrorChecker } from "../common/ErrorChecker";
import { Log } from "../common/Log";
import { Transaction } from "../transactions/Transaction";
import { bytes_t, json, size_t, uint256, uint32_t } from "../types";
import { Address, Prefix, SignType } from "../walletcore/Address";
import { HDKeychain, SEQUENCE_EXTERNAL_CHAIN, SEQUENCE_INTERNAL_CHAIN } from "../walletcore/HDKeychain";
import { Key } from "../walletcore/Key";
import { Account, MAX_MULTISIGN_COSIGNERS, SignType as AccountSignType } from "./Account";

export class SubAccount {
    private _chainAddressCached: Map<uint32_t, Address[]> = new Map();
    private _depositAddress: Address;
    private _ownerAddress: Address;
    private _crDepositAddress: Address;

    private _parent: Account;

    constructor(parent: Account) {
        this._parent = parent;

        this._chainAddressCached.set(SEQUENCE_EXTERNAL_CHAIN, []);
        this._chainAddressCached.set(SEQUENCE_INTERNAL_CHAIN, []);

        if (this._parent.getSignType() != AccountSignType.MultiSign) {
            let ownerPubKey = this._parent.ownerPubKey();
            this._depositAddress = Address.newWithPubKey(Prefix.PrefixDeposit, ownerPubKey);
            this._ownerAddress = Address.newWithPubKey(Prefix.PrefixStandard, ownerPubKey);

            let mpk: HDKeychain = this._parent.masterPubKey();
            this._crDepositAddress = Address.newWithPubKey(Prefix.PrefixDeposit, mpk.getChild(0).getChild(0).pubkey());
        }
    }

    public getBasicInfo(): json {
        return {
            Account: this._parent.getBasicInfo()
        }
    }

    public isSingleAddress(): boolean {
        return this._parent.singleAddress();
    }

    /* bool SubAccount::IsProducerDepositAddress(const Address &address) const {
         return _depositAddress.Valid() && _depositAddress == address;
     }

     bool SubAccount::IsOwnerAddress(const Address &address) const {
         return _ownerAddress.Valid() && _ownerAddress == address;
     }

     bool SubAccount::IsCRDepositAddress(const Address &address) const {
         return _crDepositAddress.Valid() && _crDepositAddress == address;
     }

     void SubAccount::GetCID(Address[] &cids, uint32_t index, size_t count, bool internal) const {
         if (_parent->GetSignType() != IAccount::MultiSign) {
             Address[] addresses;
             GetAddresses(addresses, index, count, internal);

             for (Address addr : addresses) {
                 Address cid(addr);
                 cid.ChangePrefix(PrefixIDChain);
                 cids.push_back(cid);
             }
         }
     }*/

    public getPublickeys(jout: json, index: uint32_t, count: size_t, internal: boolean) {
        if (this._parent.singleAddress()) {
            index = 0;
            count = 1;
            internal = false;
        }

        /* 
        TODO

        uint32_t chain = internal ? SEQUENCE_INTERNAL_CHAIN : SEQUENCE_EXTERNAL_CHAIN;
        if (_parent->GetSignType() == Account::MultiSign) {
            std::vector<HDKeychain> allKeychains;
            HDKeychain mineKeychain;

            if (count > 0) {
                for (const HDKeychainPtr &keychain : _parent->MultiSignCosigner())
                    allKeychains.push_back(keychain->getChild(chain));
                mineKeychain = _parent->MultiSignSigner()->getChild(chain);
            }

            if (allKeychains.empty()) {
                count = 0;
                Log::error("keychains is empty when derivate address");
            }

            jout["m"] = _parent->GetM();
            nlohmann::json jpubkeys;
            while (count--) {
                std::vector<std::string> pubkeys;
                nlohmann::json j;
                for (const HDKeychain &signer : allKeychains)
                    pubkeys.push_back(signer.getChild(index).pubkey().getHex());

                j["me"] = mineKeychain.getChild(index).pubkey().getHex();
                j["all"] = pubkeys;
                jpubkeys.push_back(j);
                index++;
            }
            jout["pubkeys"] = jpubkeys;
        } else {
            HDKeychain keychain = _parent->MasterPubKey()->getChild(chain);

            while (count--)
                jout.push_back(keychain.getChild(index++).pubkey().getHex());
        } */
    }

    public getAddresses(addresses: Address[] /* (out TODO) */, index: uint32_t, count: uint32_t, internal: boolean) {
        if (this._parent.singleAddress()) {
            index = 0;
            count = 1;
            internal = false;
        }

        let chain: uint32_t = internal ? SEQUENCE_INTERNAL_CHAIN : SEQUENCE_EXTERNAL_CHAIN;
        let addrChain = this._chainAddressCached.get(chain);
        let derivateCount = (index + count > addrChain.length) ? (index + count - addrChain.length) : 0;

        if (this._parent.getSignType() == AccountSignType.MultiSign) {
            let keychains: HDKeychain[] = [];

            if (derivateCount > 0)
                for (let keychain of this._parent.multiSignCosigner())
                    keychains.push(keychain.getChild(chain));

            if (keychains.length === 0) {
                derivateCount = 0;
                Log.error("keychains is empty when derivate address");
            }

            while (derivateCount--) {
                let pubkeys: bytes_t[] = [];
                for (let signer of keychains)
                    pubkeys.push(signer.getChild(addrChain.length).pubkey());

                let addr = Address.newWithPubKeys(Prefix.PrefixMultiSign, pubkeys, this._parent.getM());
                if (!addr.valid()) {
                    Log.error("derivate invalid multi-sig address");
                    break;
                }
                addrChain.push(addr);
            }
        } else {
            let keychain = this._parent.masterPubKey().getChild(chain);

            while (derivateCount--) {
                let addr = Address.newWithPubKey(Prefix.PrefixStandard, keychain.getChild(addrChain.length).pubkey());
                if (!addr.valid()) {
                    Log.error("derivate invalid address");
                    break;
                }
                addrChain.push(addr);
            }
        }

        addresses.length = 0;
        for (let i = index; i < index + count; i++)
            addresses.push(addrChain[i]);
        // WAS addresses.assign(addrChain.begin() + index, addrChain.begin() + index + count);
    }

    /*bytes_t SubAccount::OwnerPubKey() const {
        return _parent->OwnerPubKey();
    }

    bytes_t SubAccount::DIDPubKey() const {
        return _parent->MasterPubKey()->getChild(0).getChild(0).pubkey();
    }*/

    private findPrivateKey(key: Key, type: SignType, pubkeys: bytes_t[], payPasswd: string): boolean {
        let root = this._parent.rootKey(payPasswd);
        // for special path
        if (this._parent.getSignType() != AccountSignType.MultiSign) {
            for (let pubkey of pubkeys) {
                if (pubkey.equals(this._parent.ownerPubKey())) {
                    key = root.getChild("44'/0'/1'/0/0");
                    return true;
                }
            }
        }

        let bipkeys: HDKeychain[] = [];
        bipkeys.push(root.getChild("44'/0'/0'"));
        if (type == SignType.SignTypeMultiSign) {
            let bip45: HDKeychain = root.getChild("45'");
            if (this._parent.getSignType() == AccountSignType.MultiSign) {
                bipkeys.push(bip45.getChild(this._parent.cosignerIndex()));
            } else {
                for (let index = 0; index < MAX_MULTISIGN_COSIGNERS; ++index)
                    bipkeys.push(bip45.getChild(index));
            }
        }

        for (let bipkey of bipkeys) {
            for (let [chain, addresses] of this._chainAddressCached.entries()) {
                let bipkeyChain: HDKeychain = bipkey.getChild(chain);
                for (let index = addresses.length; index > 0; index--) {
                    let bipkeyIndex: HDKeychain = bipkeyChain.getChild(index - 1);
                    for (let p of pubkeys) {
                        if (bipkeyIndex.pubkey() == p) {
                            key = bipkeyIndex;
                            return true;
                        }
                    }
                }
            }
        }

        return false;
    }

    public signTransaction(tx: Transaction, payPasswd: string) {
        let addr: string;
        let key: Key;
        let signature: bytes_t;
        let stream = new ByteStream();

        ErrorChecker.checkParam(this._parent.readonly(), Error.Code.Sign, "Readonly wallet can not sign tx");
        ErrorChecker.checkParam(tx.isSigned(), Error.Code.AlreadySigned, "Transaction signed");
        ErrorChecker.checkParam(!tx.getPrograms(), Error.Code.InvalidTransaction, "Invalid transaction program");

        let md: uint256 = tx.getShaData();

        let programs = tx.getPrograms();
        for (let i = 0; i < programs.length; ++i) {
            let publicKeys: bytes_t[] = [];
            let type: SignType = programs[i].decodePublicKey(publicKeys);
            ErrorChecker.checkLogic(type != SignType.SignTypeMultiSign && type != SignType.SignTypeStandard, Error.Code.InvalidArgument, "Invalid redeem script");

            let found = this.findPrivateKey(key, type, publicKeys, payPasswd);
            ErrorChecker.checkLogic(!found, Error.Code.PrivateKeyNotFound, "Private key not found");

            stream.reset();
            if (programs[i].getParameter().length > 0) {
                let verifyStream = new ByteStream(programs[i].getParameter());
                while (verifyStream.readVarBytes(signature)) {
                    ErrorChecker.checkLogic(key.verify(md, signature), Error.Code.AlreadySigned, "Already signed");
                }
                stream.writeBytes(programs[i].getParameter());
            }

            signature = key.sign(md);
            stream.writeVarBytes(signature);
            programs[i].setParameter(stream.getBytes());
        }
    }

    /*Key SubAccount::GetKeyWithAddress(const Address &addr, const std::string &payPasswd) const {
        if (_parent->GetSignType() != IAccount::MultiSign) {
            for (auto it = _chainAddressCached.begin(); it != _chainAddressCached.end(); ++it) {
                uint32_t chain = it->first;
                Address[] &chainAddr = it->second;
                for (uint32_t i = 0; i < chainAddr.size(); ++i) {
                    Address cid(chainAddr[i]);
                    cid.ChangePrefix(PrefixIDChain);

                    Address did(cid);
                    did.ConvertToDID();

                    if (addr == chainAddr[i] || addr == cid || addr == did) {
                        return _parent->RootKey(payPasswd)->getChild("44'/0'/0'").getChild(chain).getChild(i);
                    }
                }
            }
        }

        ErrorChecker::ThrowLogicException(Error::PrivateKeyNotFound, "private key not found");
        return Key();
    }

    Key SubAccount::DeriveOwnerKey(const std::string &payPasswd) {
        // 44'/coinIndex'/account'/change/index
        return _parent->RootKey(payPasswd)->getChild("44'/0'/1'/0/0");
    }

    Key SubAccount::DeriveDIDKey(const std::string &payPasswd) {
        return _parent->RootKey(payPasswd)->getChild("44'/0'/0'/0/0");
    }
*/
    getCode(addr: Address, code: bytes_t): boolean {
        let index: uint32_t;
        let pubKey: bytes_t;

        if (this.isProducerDepositAddress(addr)) {
            // "44'/0'/1'/0/0";
            code = this._depositAddress.redeemScript();
            return true;
        }

        if (this.isOwnerAddress(addr)) {
            // "44'/0'/1'/0/0";
            code = this._ownerAddress.redeemScript();
            return true;
        }

        if (this.isCRDepositAddress(addr)) {
            // "44'/0'/0'/0/0";
            code = this._crDepositAddress.redeemScript();
            return true;
        }

        for (let chainAddr of Object.values(this._chainAddressCached)) {
            for (index = chainAddr.length; index > 0; index--) {
                if (chainAddr[index - 1] == addr) {
                    code = chainAddr[index - 1].RedeemScript();
                    return true;
                }

                if (this._parent.getSignType() != AccountSignType.MultiSign) {
                    let cid = Address.newFromAddress(chainAddr[index - 1]);
                    cid.changePrefix(PrefixIDChain);
                    if (addr == cid) {
                        code = cid.redeemScript();
                        return true;
                    }

                    let did = Address.newFromAddress(cid);
                    did.convertToDID();
                    if (addr == did) {
                        code = did.redeemScript();
                        return true;
                    }
                }
            }
        }

        Log.error("Can't find code and path for address:", addr.string());

        return false;
    }

    public parent(): Account {
        return this._parent;
    }
}
