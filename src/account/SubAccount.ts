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

import { Buffer } from "buffer";
import { ByteStream } from "../common/bytestream";
import { Error, ErrorChecker } from "../common/ErrorChecker";
import { Log } from "../common/Log";
import { Transaction } from "../transactions/Transaction";
import { bytes_t, size_t, uint32_t } from "../types";
import { Address, AddressArray, Prefix, SignType } from "../walletcore/Address";
import { EcdsaSigner } from "../walletcore/ecdsasigner";
import {
  HDKey,
  SEQUENCE_EXTERNAL_CHAIN,
  SEQUENCE_INTERNAL_CHAIN
} from "../walletcore/hdkey";
import {
  Account,
  MAX_MULTISIGN_COSIGNERS,
  SignType as AccountSignType,
  AccountBasicInfo
} from "./Account";

export type PublickeyItem = { me: string; all: string[] };
export type PublickeysInfo = {
  m: number; // Multisign - number of requested signatures
  pubkeys: PublickeyItem[];
};

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
      this._depositAddress = Address.newWithPubKey(
        Prefix.PrefixDeposit,
        ownerPubKey
      );

      this._ownerAddress = Address.newWithPubKey(
        Prefix.PrefixStandard,
        ownerPubKey
      );

      let mpk: HDKey = this._parent.masterPubKey();
      this._crDepositAddress = Address.newWithPubKey(
        Prefix.PrefixDeposit,
        mpk.deriveWithIndex(0).deriveWithIndex(0).getPublicKeyBytes()
      );
    }
  }

  public getChainAddressCachedAmount(chain: number): number {
    return this._chainAddressCached.get(chain).length;
  }

  public getBasicInfo(): { Account: AccountBasicInfo } {
    return {
      Account: this._parent.getBasicInfo()
    };
  }

  public isSingleAddress(): boolean {
    return this._parent.singleAddress();
  }

  isProducerDepositAddress(address: Address): boolean {
    return (
      this._depositAddress &&
      this._depositAddress.valid() &&
      this._depositAddress.equals(address)
    );
  }

  isOwnerAddress(address: Address): boolean {
    return (
      this._ownerAddress &&
      this._ownerAddress.valid() &&
      this._ownerAddress.equals(address)
    );
  }

  isCRDepositAddress(address: Address): boolean {
    return (
      this._crDepositAddress &&
      this._crDepositAddress.valid() &&
      this._crDepositAddress.equals(address)
    );
  }

  getCID(cids: Address[], index: uint32_t, count: size_t, internal: boolean) {
    if (this._parent.getSignType() !== AccountSignType.MultiSign) {
      const addresses: Address[] = this.getAddresses(index, count, internal);

      for (let addr of addresses) {
        const cid = Address.newFromAddress(addr);
        cid.changePrefix(Prefix.PrefixIDChain);
        cids.push(cid);
      }
    }
  }

  public getPublickeys(
    index: uint32_t,
    count: size_t,
    internal: boolean
  ): PublickeysInfo | string[] {
    if (this._parent.singleAddress()) {
      index = 0;
      count = 1;
      internal = false;
    }

    const chain: uint32_t = internal
      ? SEQUENCE_INTERNAL_CHAIN
      : SEQUENCE_EXTERNAL_CHAIN;
    if (this._parent.getSignType() == AccountSignType.MultiSign) {
      let allKeychains: HDKey[] = [];
      let mineKeychain: HDKey;

      if (count > 0) {
        for (let keychain of this._parent.multiSignCosigner()) {
          allKeychains.push(keychain.deriveWithIndex(chain));
        }

        mineKeychain = this._parent.multiSignSigner().deriveWithIndex(chain);
      }

      if (allKeychains.length === 0) {
        count = 0;
        Log.error("keychains is empty when derivate address");
      }
      let jout = <PublickeysInfo>{};
      jout["m"] = this._parent.getM();
      let jpubkeys: PublickeyItem[] = [];
      while (count--) {
        let pubkeys: string[] = [];
        let j = <PublickeyItem>{};
        for (let signer of allKeychains) {
          pubkeys.push(
            signer.deriveWithIndex(index).getPublicKeyBytes().toString("hex")
          );
        }

        j["me"] = mineKeychain
          .deriveWithIndex(index)
          .getPublicKeyBytes()
          .toString("hex");
        j["all"] = pubkeys;
        jpubkeys.push(j);
        index++;
      }
      jout["pubkeys"] = jpubkeys;
      return jout;
    } else {
      let keychain: HDKey = this._parent.masterPubKey().deriveWithIndex(chain);
      let jout: string[] = [];
      while (count--) {
        jout.push(
          keychain
            .deriveWithIndex(index++)
            .getPublicKeyBytes()
            .toString("hex")
        );
      }
      return jout;
    }
  }

  public getAddresses(
    index: uint32_t,
    count: uint32_t,
    internal: boolean
  ): AddressArray {
    if (this._parent.singleAddress()) {
      index = 0;
      count = 1;
      internal = false;
    }

    let chain: number = internal
      ? SEQUENCE_INTERNAL_CHAIN
      : SEQUENCE_EXTERNAL_CHAIN;
    let addrChain = this._chainAddressCached.get(chain);
    let derivateCount =
      index + count > addrChain.length ? index + count - addrChain.length : 0;
    if (this._parent.getSignType() == AccountSignType.MultiSign) {
      let keychains: HDKey[] = [];
      if (derivateCount > 0) {
        for (let keychain of this._parent.multiSignCosigner()) {
          keychains.push(keychain.deriveWithIndex(chain));
        }
        if (keychains.length === 0) {
          derivateCount = 0;
          Log.error("keychains is empty when derivate address");
        }
      }

      while (derivateCount--) {
        let pubkeys: bytes_t[] = [];
        for (let signer of keychains)
          pubkeys.push(
            signer.deriveWithIndex(addrChain.length).getPublicKeyBytes()
          );

        let addr = Address.newWithPubKeys(
          Prefix.PrefixMultiSign,
          pubkeys,
          this._parent.getM()
        );
        if (!addr.valid()) {
          Log.error("derivate invalid multi-sig address");
          break;
        }
        addrChain.push(addr);
        this._chainAddressCached.set(chain, addrChain);
      }
    } else {
      let keychain = this._parent.masterPubKey().deriveWithIndex(chain);

      while (derivateCount--) {
        let addr = Address.newWithPubKey(
          Prefix.PrefixStandard,
          keychain.deriveWithIndex(addrChain.length).getPublicKeyBytes()
        );
        if (!addr.valid()) {
          Log.error("derivate invalid address");
          break;
        }
        addrChain.push(addr);
        this._chainAddressCached.set(chain, addrChain);
      }
    }
    let addresses: Address[] = [];
    for (let i = index; i < index + count; i++) {
      addresses.push(addrChain[i]);
    }

    return addresses;
  }

  ownerPubKey(): bytes_t {
    return this._parent.ownerPubKey();
  }

  didPubKey(): bytes_t {
    return this._parent
      .masterPubKey()
      .deriveWithIndex(0)
      .deriveWithIndex(0)
      .getPublicKeyBytes();
  }

  private async findPrivateKey(
    type: SignType,
    pubkeys: bytes_t[],
    payPasswd: string
  ): Promise<{ found: boolean; key?: HDKey }> {
    let key: HDKey;
    let root = await this._parent.rootKey(payPasswd);

    // for special path
    if (this._parent.getSignType() != AccountSignType.MultiSign) {
      for (let pubkey of pubkeys) {
        if (pubkey.equals(this._parent.ownerPubKey())) {
          key = root.deriveWithPath("m/44'/0'/1'/0/0");
          return { found: true, key };
        }
      }
    }

    let bipkeys: HDKey[] = [];
    bipkeys.push(root.deriveWithPath("m/44'/0'/0'"));
    if (type == SignType.SignTypeMultiSign) {
      let bip45: HDKey = root.deriveWithPath("m/45'");
      if (this._parent.getSignType() == AccountSignType.MultiSign) {
        bipkeys.push(bip45.deriveWithIndex(this._parent.cosignerIndex()));
      } else {
        for (let index = 0; index < MAX_MULTISIGN_COSIGNERS; ++index)
          bipkeys.push(bip45.deriveWithIndex(index));
      }
    }

    for (let bipkey of bipkeys) {
      for (let [chain, addresses] of this._chainAddressCached.entries()) {
        let bipkeyChain: HDKey = bipkey.deriveWithIndex(chain);
        for (let index = addresses.length; index > 0; index--) {
          let bipkeyIndex: HDKey = bipkeyChain.deriveWithIndex(index - 1);
          for (let p of pubkeys) {
            if (bipkeyIndex.getPublicKeyBytes().equals(p)) {
              key = bipkeyIndex;
              return { found: true, key };
            }
          }
        }
      }
    }

    return { found: false };
  }

  public async signTransaction(tx: Transaction, payPasswd: string) {
    ErrorChecker.checkParam(
      this._parent.readonly(),
      Error.Code.Sign,
      "Readonly wallet can not sign tx"
    );
    ErrorChecker.checkParam(
      tx.isSigned(),
      Error.Code.AlreadySigned,
      "Transaction signed"
    );
    ErrorChecker.checkParam(
      !tx.getPrograms(),
      Error.Code.InvalidTransaction,
      "Invalid transaction program"
    );

    let md = tx.getShaData();
    let programs = tx.getPrograms();
    for (let i = 0; i < programs.length; ++i) {
      let publicKeys: bytes_t[] = [];
      let type: SignType = programs[i].decodePublicKey(publicKeys);
      ErrorChecker.checkLogic(
        type != SignType.SignTypeMultiSign && type != SignType.SignTypeStandard,
        Error.Code.InvalidArgument,
        "Invalid redeem script"
      );

      let rs: { found: boolean; key?: HDKey } = await this.findPrivateKey(
        type,
        publicKeys,
        payPasswd
      );
      ErrorChecker.checkLogic(
        !rs.found,
        Error.Code.PrivateKeyNotFound,
        "Private key not found"
      );

      let signature: bytes_t;
      let stream = new ByteStream();
      stream.reset();

      if (programs[i].getParameter().length > 0) {
        let verifyStream = new ByteStream(programs[i].getParameter());
        let publicKey = rs.key.getPublicKeyBytes();
        signature = verifyStream.readVarBytes(signature);
        while (signature) {
          ErrorChecker.checkLogic(
            EcdsaSigner.verify(publicKey, signature, Buffer.from(md, "hex")),
            Error.Code.AlreadySigned,
            "Already signed"
          );
          signature = verifyStream.readVarBytes(signature);
        }
        stream.writeBytes(programs[i].getParameter());
      }

      let privateKey: bytes_t = rs.key.getPrivateKeyBytes();
      signature = EcdsaSigner.sign(privateKey, Buffer.from(md, "hex"));
      stream.writeVarBytes(signature);
      programs[i].setParameter(stream.getBytes());
    }
  }

  async getKeyWithAddress(
    addr: Address,
    payPasswd: string
  ): Promise<bytes_t | null> {
    const rootKey = await this._parent.rootKey(payPasswd);
    if (this._parent.getSignType() != AccountSignType.MultiSign) {
      for (let [key, value] of this._chainAddressCached) {
        let chain: uint32_t = key;
        let chainAddr: Address[] = value;
        for (let i = 0; i < chainAddr.length; i++) {
          let address = chainAddr[i];
          let cid = Address.newFromAddress(address);
          cid.changePrefix(Prefix.PrefixIDChain);
          let did = Address.newFromAddress(cid);
          did.convertToDID();
          if (addr.equals(address) || addr.equals(cid) || addr.equals(did)) {
            const privateKey = rootKey
              .deriveWithPath("m/44'/0'/0'")
              .deriveWithIndex(chain)
              .deriveWithIndex(i)
              .getPrivateKeyBytes();
            return privateKey;
          }
        }
      }
    }

    ErrorChecker.throwLogicException(
      Error.Code.PrivateKeyNotFound,
      "private key not found"
    );
    return null;
  }

  async deriveOwnerKey(payPasswd: string): Promise<HDKey> {
    // 44'/coinIndex'/account'/change/index
    const rootKey = await this._parent.rootKey(payPasswd);
    return rootKey.deriveWithPath("m/44'/0'/1'/0/0");
  }

  async deriveDIDKey(payPasswd: string): Promise<HDKey> {
    const rootKey = await this._parent.rootKey(payPasswd);
    return rootKey.deriveWithPath("m/44'/0'/0'/0/0");
  }

  getCode(addr: Address): Buffer | null {
    let code: bytes_t;
    if (this.isProducerDepositAddress(addr)) {
      // "44'/0'/1'/0/0";
      return (code = this._depositAddress.redeemScript());
    }

    if (this.isOwnerAddress(addr)) {
      // "44'/0'/1'/0/0";
      return (code = this._ownerAddress.redeemScript());
    }

    if (this.isCRDepositAddress(addr)) {
      // "44'/0'/0'/0/0";
      return (code = this._crDepositAddress.redeemScript());
    }

    for (let chainAddr of this._chainAddressCached.values()) {
      for (let index = chainAddr.length; index > 0; index--) {
        if (chainAddr[index - 1].equals(addr)) {
          return (code = chainAddr[index - 1].redeemScript());
        }
        if (this._parent.getSignType() != AccountSignType.MultiSign) {
          let cid = Address.newFromAddress(chainAddr[index - 1]);
          cid.changePrefix(Prefix.PrefixIDChain);
          if (addr.equals(cid)) {
            return (code = cid.redeemScript());
          }

          let did = Address.newFromAddress(cid);
          did.convertToDID();
          if (addr.equals(did)) {
            return (code = did.redeemScript());
          }
        }
      }
    }

    Log.error("Can't find code and path for address:", addr.string());

    return null;
  }

  public parent(): Account {
    return this._parent;
  }
}
