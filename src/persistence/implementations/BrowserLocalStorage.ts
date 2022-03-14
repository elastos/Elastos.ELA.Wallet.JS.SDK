import { json, JSONObject } from "../../types";
import { WalletStorage } from "../WalletStorage";

export class BrowserLocalStorage implements WalletStorage {
  masterWalletID = null;
  public loadStore(): json {
    return {}; // TODO
  }

  public saveStore(j: JSONObject) {
    // use local storage to save wallet info and setup masterWalletID
  }
}
