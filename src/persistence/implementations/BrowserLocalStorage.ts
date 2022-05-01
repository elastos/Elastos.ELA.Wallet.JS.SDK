import { json, JSONObject } from "../../types";
import { WalletStorage } from "../WalletStorage";

export class BrowserLocalStorage implements WalletStorage {
  currentMasterWalletID: string;
  static masterWalletIDs: string[] = [];

  constructor(id?: string) {
    this.currentMasterWalletID = id;
  }

  loadStore(id?: string): json {
    const data = localStorage.getItem(id ? id : this.currentMasterWalletID);
    if (!data) return {};
    try {
      return JSON.parse(data);
    } catch (err) {
      console.log("loadStore err", err);
    }
  }

  saveStore(j: JSONObject) {
    // use local storage to save wallet info and setup masterWalletID
    localStorage.setItem(this.currentMasterWalletID, JSON.stringify(j));
    if (
      !BrowserLocalStorage.masterWalletIDs.includes(this.currentMasterWalletID)
    ) {
      BrowserLocalStorage.masterWalletIDs.push(this.currentMasterWalletID);
    }
  }

  getMasterWalletIDs(): string[] {
    return BrowserLocalStorage.masterWalletIDs;
  }
}
