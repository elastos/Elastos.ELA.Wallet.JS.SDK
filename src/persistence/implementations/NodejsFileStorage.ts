import { json, JSONObject } from "../../types";
import { WalletStorage } from "../WalletStorage";

export class NodejsFileStorage implements WalletStorage {
  currentMasterWalletID: string;

  public loadStore(): json {
    /* TODO fs::path filepath = _path;
  filepath /= LOCAL_STORE_FILE;
  if (!fs:: exists(filepath)) {
    filepath = _path;
    filepath /= MASTER_WALLET_STORE_FILE;
    if (!fs:: exists(filepath)) {
      ErrorChecker:: ThrowLogicException(Error:: MasterWalletNotExist, "master wallet " +
        filepath.parent_path().filename().string() + " not exist");
    }
  }

  std::ifstream is(filepath.string());
  nlohmann::json j;
  is >> j;
*/
    return {}; // TODO
  }

  public saveStore(j: JSONObject) {
    /* TODO nlohmann::json j = ToJson();

    if (!j.is_null() && !j.empty() && !_path.empty()) {
      boost:: filesystem::path path = _path;
      if (!boost:: filesystem:: exists(path))
      boost:: filesystem:: create_directory(path);

      path /= LOCAL_STORE_FILE;
      std::ofstream o(path.string());
      o << j;
      o.flush();
    } */
  }

  getMasterWalletIDs(): string[] {
    return;
  }
}
