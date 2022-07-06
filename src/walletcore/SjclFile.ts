// Copyright (c) 2012-2022 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

import { uint32_t } from "../types";

export type SjclFileInfo = {
  iv: string;
  v: uint32_t;
  iter: uint32_t;
  ks: uint32_t;
  ts: uint32_t;
  mode: string;
  adata: string;
  cipher: string;
  salt: string;
  ct: string;
};

export class SjclFile {
  private _iv: string;
  private _v: uint32_t;
  private _iter: uint32_t;
  private _ks: uint32_t;
  private _ts: uint32_t;
  private _mode: string;
  private _adata: string;
  private _cipher: string;
  private _salt: string;
  private _ct: string;

  getIv(): string {
    return this._iv;
  }

  setIv(iv: string) {
    this._iv = iv;
  }

  getV(): uint32_t {
    return this._v;
  }

  setV(value: uint32_t) {
    this._v = value;
  }

  getIter(): uint32_t {
    return this._iter;
  }

  setIter(value: uint32_t) {
    this._iter = value;
  }

  getKs(): uint32_t {
    return this._ks;
  }

  setKs(value: uint32_t) {
    this._ks = value;
  }

  getTs(): uint32_t {
    return this._ts;
  }

  setTs(value: uint32_t) {
    this._ts = value;
  }

  getMode(): string {
    return this._mode;
  }

  setMode(mode: string) {
    this._mode = mode;
  }

  getAdata(): string {
    return this._adata;
  }

  setAdata(adata: string) {
    this._adata = adata;
  }

  getCipher(): string {
    return this._cipher;
  }

  setCipher(cipher: string) {
    this._cipher = cipher;
  }

  getSalt(): string {
    return this._salt;
  }

  setSalt(salt: string) {
    this._salt = salt;
  }

  getCt(): string {
    return this._ct;
  }

  setCt(ct: string) {
    this._ct = ct;
  }

  toJson(): SjclFileInfo {
    let j = <SjclFileInfo>{};
    j["iv"] = this._iv;
    j["v"] = this._v;
    j["iter"] = this._iter;
    j["ks"] = this._ks;
    j["ts"] = this._ts;
    j["mode"] = this._mode;
    j["adata"] = this._adata;
    j["cipher"] = this._cipher;
    j["salt"] = this._salt;
    j["ct"] = this._ct;
    return j;
  }

  fromJson(j: SjclFileInfo) {
    this._iv = j["iv"];
    this._v = j["v"];
    this._iter = j["iter"];
    this._ks = j["ks"];
    this._ts = j["ts"];
    this._mode = j["mode"];
    this._adata = j["adata"];
    this._cipher = j["cipher"];
    this._salt = j["salt"];
    this._ct = j["ct"];
  }
}
