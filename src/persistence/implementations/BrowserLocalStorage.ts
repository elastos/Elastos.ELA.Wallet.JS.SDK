import { json } from "../../types";
import { WalletStorage } from "../WalletStorage";

export class BrowserLocalStorage implements WalletStorage {
  private currentMasterWalletID: string | undefined;

  constructor(id?: string) {
    this.currentMasterWalletID = id;
  }

  setActiveMasterWalletID(id: string): Promise<void> {
    this.currentMasterWalletID = id;
    return Promise.resolve();
  }

  getActiveMasterWalletID(): Promise<string> {
    return Promise.resolve(this.currentMasterWalletID);
  }

  loadStore(id?: string): Promise<json> {
    let data: string | null = "";
    if (id) {
      data = localStorage.getItem(id);
    } else if (this.currentMasterWalletID) {
      data = localStorage.getItem(this.currentMasterWalletID);
    }
    return Promise.resolve(data && JSON.parse(data));
  }

  saveStore(j: json): Promise<void> {
    if (!this.currentMasterWalletID) {
      return Promise.reject("no master wallet ID");
    }
    const data = localStorage.getItem("masterWalletIDs");
    if (data) {
      try {
        const masterWalletIDs = JSON.parse(data);
        if (!masterWalletIDs.includes(this.currentMasterWalletID)) {
          masterWalletIDs.push(this.currentMasterWalletID);
        }
        localStorage.setItem(
          "masterWalletIDs",
          JSON.stringify(masterWalletIDs)
        );
      } catch (err) {
        return Promise.reject(err);
      }
    } else {
      localStorage.setItem(
        "masterWalletIDs",
        JSON.stringify([this.currentMasterWalletID])
      );
    }
    return Promise.resolve(
      localStorage.setItem(this.currentMasterWalletID, JSON.stringify(j))
    );
  }

  getMasterWalletIDs(): Promise<string[]> {
    const data = localStorage.getItem("masterWalletIDs");
    return Promise.resolve(data && JSON.parse(data));
  }
}
