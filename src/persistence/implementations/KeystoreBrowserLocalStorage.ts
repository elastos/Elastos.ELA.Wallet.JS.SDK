import { KeystoreStorage } from "../KeystoreStorage";
import { KeyStoreInfo } from "../../walletcore/keystore";

export class KeyStoreBrowserLocalStorage implements KeystoreStorage {
  loadStore(storageID: string): Promise<KeyStoreInfo> {
    let data = localStorage.getItem(storageID);
    return Promise.resolve(data && JSON.parse(data));
  }

  saveStore(storageID: string, j: KeyStoreInfo): Promise<void> {
    const data = localStorage.getItem("keystoreIDs");
    if (data) {
      const storageIDs = JSON.parse(data);
      if (!storageIDs.includes(storageID)) {
        storageIDs.push(storageID);
        localStorage.setItem("storageIDs", JSON.stringify(storageIDs));
      }
    } else {
      localStorage.setItem("storageIDs", JSON.stringify([storageID]));
    }
    return Promise.resolve(localStorage.setItem(storageID, JSON.stringify(j)));
  }

  async removeStore(storageID: string): Promise<void> {
    localStorage.removeItem(storageID);
    let storageIDs = await this.getKeystoreIDs();
    storageIDs = storageIDs.filter((id) => id !== storageID);
    localStorage.setItem("keystoreIDs", JSON.stringify(storageIDs));
  }

  getKeystoreIDs(): Promise<string[]> {
    const data = localStorage.getItem("keystoreIDs");
    return Promise.resolve(data && JSON.parse(data));
  }
}
