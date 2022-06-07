// Copyright (c) 2012-2022 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

export type ChainIDInfo = {
  ChainID: string;
};
export class CoinInfo {
  private _chainID = "";

  public getChainID(): string {
    return this._chainID;
  }

  public setChainID(id: string) {
    this._chainID = id;
  }

  public toJson(): ChainIDInfo {
    return {
      ChainID: this._chainID
    };
  }

  public fromJson(j: ChainIDInfo): CoinInfo {
    this._chainID = j["ChainID"] as string;
    if (this._chainID === "IdChain") this._chainID = "IDChain";

    return this;
  }
}
