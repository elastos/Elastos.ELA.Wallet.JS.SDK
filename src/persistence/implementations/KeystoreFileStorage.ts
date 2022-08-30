import * as fs from "fs";
import { ErrorChecker, Error } from "../../common/ErrorChecker";
import { KeystoreStorage } from "../KeystoreStorage";
import { KeystoreInfo } from "../../walletcore/keystore";

export class KeystoreFileStorage implements KeystoreStorage {
  loadStore(keystoreID: string): Promise<KeystoreInfo> {
    let dirPath = `/essentials-keystore/${keystoreID}`;
    if (!fs.existsSync(dirPath)) {
      ErrorChecker.throwLogicException(
        Error.Code.MasterWalletNotExist,
        "master wallet keystore " + keystoreID + " not exist"
      );
    }
    let data = fs.readFileSync(`${dirPath}/keystore.json`, "utf8");
    return Promise.resolve(JSON.parse(data) as KeystoreInfo);
  }

  saveStore(keystoreID: string, j: KeystoreInfo): Promise<void> {
    let dirPath = `/essentials-keystore/${keystoreID}`;
    if (!fs.existsSync(dirPath)) {
      fs.mkdirSync(dirPath);
    }
    let rs = fs.writeFileSync(
      `${dirPath}/keystore.json`,
      JSON.stringify(j, null, 2),
      "utf8"
    );
    return Promise.resolve(rs);
  }

  removeStore(keystoreID: string): Promise<void> {
    let dirPath = `/essentials-keystore/${keystoreID}`;
    if (!fs.existsSync(dirPath)) {
      ErrorChecker.throwLogicException(
        Error.Code.MasterWalletNotExist,
        "master wallet keystore " + keystoreID + " not exist"
      );
    }

    fs.unlinkSync(`${dirPath}/keystore.json`);
    let rs = fs.rmdirSync(dirPath);
    return Promise.resolve(rs);
  }

  getKeystoreIDs(): Promise<string[]> {
    let path = "/essentials-keystore";
    let keystoreIDs = [];
    let files = fs.readdirSync(path);
    files.forEach(function (file) {
      let isValid = fs.existsSync(`${path}/${file}/keystore.json`);
      if (isValid) {
        keystoreIDs.push(file);
      }
    });
    return Promise.resolve(keystoreIDs);
  }
}
