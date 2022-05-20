import { WalletStorage } from "../WalletStorage";
import { LocalStoreInfo } from "../LocalStore";

export class BrowserLocalStorage implements WalletStorage {
  loadStore(masterWalletID: string): Promise<LocalStoreInfo> {
    let data = localStorage.getItem(masterWalletID);
    return Promise.resolve(data && JSON.parse(data));
  }

  saveStore(masterWalletID: string, j: LocalStoreInfo): Promise<void> {
    const data = localStorage.getItem("masterWalletIDs");
    if (data) {
      try {
        const masterWalletIDs = JSON.parse(data);
        if (!masterWalletIDs.includes(masterWalletID)) {
          masterWalletIDs.push(masterWalletID);
        }
        localStorage.setItem(
          "masterWalletIDs",
          JSON.stringify(masterWalletIDs)
        );
      } catch (err) {
        return Promise.reject(err);
      }
    } else {
      localStorage.setItem("masterWalletIDs", JSON.stringify([masterWalletID]));
    }
    return Promise.resolve(
      localStorage.setItem(masterWalletID, JSON.stringify(j))
    );
  }

  removeStore(masterWalletID: string): Promise<void> {
    return Promise.resolve(localStorage.removeItem(masterWalletID));
  }

  getMasterWalletIDs(): Promise<string[]> {
    const data = localStorage.getItem("masterWalletIDs");
    return Promise.resolve(data && JSON.parse(data));
  }
}
