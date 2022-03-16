import { json, JSONObject } from "../../types";
import { WalletStorage } from "../WalletStorage";

export class BrowserLocalStorage implements WalletStorage {
  masterWalletID = null;

  constructor(id: string) {
    this.masterWalletID = id;
  }

  public loadStore(): json {
    const data = window.localStorage.getItem(this.masterWalletID);
    if (!data) return {};
    try {
      return JSON.parse(data);
    } catch (err) {
      console.log("loadStore err", err);
    }
  }

  public saveStore(j: JSONObject) {
    // use local storage to save wallet info and setup masterWalletID
    window.localStorage.setItem(this.masterWalletID, JSON.stringify(j));
  }
}
