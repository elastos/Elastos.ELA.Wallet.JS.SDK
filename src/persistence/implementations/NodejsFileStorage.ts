import { WalletStorage } from "../WalletStorage";
import { LocalStoreInfo } from "../LocalStore";

export class NodejsFileStorage implements WalletStorage {
  loadStore(masterWalletID: string): Promise<LocalStoreInfo> {
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
    return Promise.resolve({} as LocalStoreInfo);
  }

  saveStore(masterWalletID: string, j: LocalStoreInfo): Promise<void> {
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
    return Promise.resolve();
  }

  getMasterWalletIDs(): Promise<string[]> {
    return;
  }
}
