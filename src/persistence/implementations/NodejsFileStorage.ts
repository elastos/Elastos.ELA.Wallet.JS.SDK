import * as fs from "fs";
import { WalletStorage } from "../WalletStorage";
import { LocalStoreInfo } from "../LocalStore";
import { ErrorChecker, Error } from "../../common/ErrorChecker";

export class NodejsFileStorage implements WalletStorage {
  loadStore(masterWalletID: string, path: string): Promise<LocalStoreInfo> {
    let dirPath = `${path}/${masterWalletID}`;
    if (!fs.existsSync(dirPath)) {
      ErrorChecker.throwLogicException(
        Error.Code.MasterWalletNotExist,
        "master wallet " + masterWalletID + " not exist"
      );
    }
    let data = fs.readFileSync(`${dirPath}/masterWalletStore.json`, "utf8");
    return Promise.resolve(JSON.parse(data) as LocalStoreInfo);
  }

  saveStore(
    masterWalletID: string,
    j: LocalStoreInfo,
    path: string
  ): Promise<void> {
    let dirPath = `${path}/${masterWalletID}`;
    if (!fs.existsSync(dirPath)) {
      fs.mkdirSync(dirPath);
    }
    let rs = fs.writeFileSync(
      `${dirPath}/masterWalletStore.json`,
      JSON.stringify(j, null, 2),
      "utf8"
    );
    return Promise.resolve(rs);
  }

  removeStore(masterWalletID: string, path: string): Promise<void> {
    let dirPath = `${path}/${masterWalletID}`;
    if (!fs.existsSync(dirPath)) {
      ErrorChecker.throwLogicException(
        Error.Code.MasterWalletNotExist,
        "master wallet " + masterWalletID + " not exist"
      );
    }

    fs.unlinkSync(`${dirPath}/masterWalletStore.json`);
    let rs = fs.rmdirSync(dirPath);
    return Promise.resolve(rs);
  }

  getMasterWalletIDs(path: string): Promise<string[]> {
    if (!fs.existsSync(path)) {
      ErrorChecker.throwLogicException(
        Error.Code.MasterWalletNotExist,
        "master wallet path" + path + " not exist"
      );
    }
    let masterWalletIDs = [];
    let files = fs.readdirSync(path);
    files.forEach(function (file) {
      let isValid = fs.existsSync(`${path}/${file}/masterWalletStore.json`);
      if (isValid) {
        masterWalletIDs.push(file);
      }
    });
    return Promise.resolve(masterWalletIDs);
  }
}
