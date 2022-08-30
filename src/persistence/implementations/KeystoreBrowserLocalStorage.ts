import { KeystoreStorage } from "../KeystoreStorage";
import { KeystoreInfo } from "../../walletcore/keystore";

export class KeystoreBrowserLocalStorage implements KeystoreStorage {
  loadStore(keystoreID: string): Promise<KeystoreInfo> {
    let data = localStorage.getItem(keystoreID);
    return Promise.resolve(data && JSON.parse(data));
  }

  saveStore(keystoreID: string, j: KeystoreInfo): Promise<void> {
    const data = localStorage.getItem("keystoreIDs");
    if (data) {
      const keystoreIDs = JSON.parse(data);
      if (!keystoreIDs.includes(keystoreID)) {
        keystoreIDs.push(keystoreID);
        localStorage.setItem("keystoreIDs", JSON.stringify(keystoreIDs));
      }
    } else {
      localStorage.setItem("keystoreIDs", JSON.stringify([keystoreID]));
    }
    return Promise.resolve(localStorage.setItem(keystoreID, JSON.stringify(j)));
  }

  async removeStore(keystoreID: string): Promise<void> {
    localStorage.removeItem(keystoreID);
    let keystoreIDs = await this.getKeystoreIDs();
    keystoreIDs = keystoreIDs.filter((id) => id !== keystoreID);
    localStorage.setItem("keystoreIDs", JSON.stringify(keystoreIDs));
  }

  getKeystoreIDs(): Promise<string[]> {
    const data = localStorage.getItem("keystoreIDs");
    return Promise.resolve(data && JSON.parse(data));
  }
}
