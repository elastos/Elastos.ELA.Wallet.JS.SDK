// Copyright (c) 2012-2022 The Elastos Open Source Project
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// import * as fs from "fs";
// import { ErrorChecker, Error } from "../common/ErrorChecker";
// import { SjclFile, SjclFileInfo } from "./SjclFile";
import { ElaNewWalletJson, ElaNewWalletInfo } from "./ElaNewWalletJson";
import { AESDecrypt, AESEncrypt } from "./aes";

// const AES_DEFAULT_ITER = 10000;
// const AES_DEFAULT_KS = 128;

export type KeyStoreInfo = {
  ciphertext: string;
};

export class KeyStore {
  private _walletJson: ElaNewWalletJson;

  static newFromParams(walletjson: ElaNewWalletJson) {
    let keyStore = new KeyStore();
    keyStore._walletJson = walletjson;
    return keyStore;
  }

  walletJson(): ElaNewWalletJson {
    return this._walletJson;
  }

  open(path: string, password: string) {
    // TODO
    // const data = fs.readFileSync(path, {
    //   encoding: "utf8",
    //   flag: "r"
    // });
    // return this.import(JSON.parse(data), password);
  }

  importReadonly(j: ElaNewWalletInfo) {
    this._walletJson.fromJson(j);
    return true;
  }

  import(json: KeyStoreInfo, passwd: string) {
    // let sjcl = new SjclFile();

    // sjcl.fromJson(json);

    // if (sjcl.getMode() != "ccm") {
    //   ErrorChecker.checkCondition(
    //     true,
    //     Error.Code.KeyStore,
    //     "Keystore is not ccm mode"
    //   );
    //   return false;
    // }

    // bytes_t plaintext = AES::DecryptCCM(
    // 	sjcl.getCt(),
    // 	passwd,
    // 	sjcl.getSalt(),
    // 	sjcl.getIv(),
    // 	sjcl.getAdata(),
    // 	sjcl.getKs()
    // );

    let content = AESDecrypt(json["ciphertext"], passwd);
    this._walletJson.fromJson(JSON.parse(content));

    return true;
  }

  save(path: string, password: string, withPrivKey: boolean): boolean {
    // TODO
    // let json = this.export(password, withPrivKey);
    // fs.writeFileSync(path, JSON.stringify(json, null, 2));
    return true;
  }

  exportReadonly() {
    let roJson = this._walletJson.toJson(false);
    return roJson;
  }

  export(passwd: string, withPrivKey: boolean) {
    let plaintextJson = this._walletJson.toJson(withPrivKey);

    // let salt = AES::RandomSalt().getBase64();
    // let iv = AES::RandomIV().getBase64();

    // let ciphertext = AES::EncryptCCM(bytes_t(plaintext.c_str(), plaintext.size()), passwd, salt, iv);

    // let sjcl = new SjclFile();
    // sjcl.setIv(iv);
    // sjcl.setV(1);
    // sjcl.setIter(AES_DEFAULT_ITER);
    // sjcl.setKs(AES_DEFAULT_KS);
    // sjcl.setTs(64);
    // sjcl.setMode("ccm");
    // sjcl.setAdata("");
    // sjcl.setCipher("aes");
    // sjcl.setSalt(salt);
    // sjcl.setCt(ciphertext);

    // return sjcl.toJson();

    return {
      ciphertext: AESEncrypt(JSON.stringify(plaintextJson), passwd)
    };
  }
}
