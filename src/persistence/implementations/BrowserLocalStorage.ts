import { WalletStorage } from "../WalletStorage";
import { LocalStoreInfo } from "../LocalStore";
import { ErrorChecker, Error } from "../../common/ErrorChecker";

export class BrowserLocalStorage implements WalletStorage {
  loadStore(masterWalletID: string): Promise<LocalStoreInfo> {
    let data = localStorage.getItem(masterWalletID);
    return Promise.resolve(data && JSON.parse(data));
  }

  saveStore(masterWalletID: string, j: LocalStoreInfo): Promise<void> {
    const data = localStorage.getItem("masterWalletIDs");
    if (data) {
      const masterWalletIDs = JSON.parse(data);
      if (!masterWalletIDs.includes(masterWalletID)) {
        masterWalletIDs.push(masterWalletID);
        localStorage.setItem(
          "masterWalletIDs",
          JSON.stringify(masterWalletIDs)
        );
      }
    } else {
      localStorage.setItem("masterWalletIDs", JSON.stringify([masterWalletID]));
    }
    return Promise.resolve(
      localStorage.setItem(masterWalletID, JSON.stringify(j))
    );
  }

  async removeStore(masterWalletID: string): Promise<void> {
    localStorage.removeItem(masterWalletID);
    let masterWalletIDs = await this.getMasterWalletIDs();
    masterWalletIDs = masterWalletIDs.filter((id) => id !== masterWalletID);
    localStorage.setItem("masterWalletIDs", JSON.stringify(masterWalletIDs));
  }

  getMasterWalletIDs(): Promise<string[]> {
    const data = localStorage.getItem("masterWalletIDs");
    return Promise.resolve(data && JSON.parse(data));
  }
}
