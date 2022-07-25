// Copyright (c) 2012-2022 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

import {
  BitcoreWalletClientJson,
  BitcoreWalletClientInfo
} from "./BitcoreWalletClientJson";

export interface ElaWebWalletInfo extends BitcoreWalletClientInfo {
  mnemonic: string;
}

export class ElaWebWalletJson extends BitcoreWalletClientJson {
  protected _mnemonic: string;

  constructor() {
    super();
  }

  destroy() {
    this._mnemonic = "";
  }

  mnemonic(): string {
    return this._mnemonic;
  }

  setMnemonic(m: string) {
    this._mnemonic = m;
  }

  toJson(withPrivKey: boolean) {
    let j = super.toJson(withPrivKey);
    if (withPrivKey) j["mnemonic"] = this._mnemonic;
    return j as ElaWebWalletInfo;
  }

  fromJson(j: BitcoreWalletClientInfo) {
    super.fromJson(j);
    if (j["mnemonic"]) this._mnemonic = j["mnemonic"];
  }
}
