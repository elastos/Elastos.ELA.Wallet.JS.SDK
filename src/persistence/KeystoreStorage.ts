import { KeyStoreInfo } from "../walletcore/keystore";

/**
 * Base interface to store persitant wallet keystore data.
 */
export interface KeystoreStorage {
  /**
   * Loads a saved store and returns it as json.
   */
  loadStore(keystoreID: string): Promise<KeyStoreInfo>;
  /**
   * Saves the given local store JSON representation to persistent storage.
   */
  saveStore(keystoreID: string, j: KeyStoreInfo): Promise<void>;
  /**
   * remove a saved store from persistent storage.
   */
  removeStore(keystoreID: string): Promise<void>;
  /**
   * get all saved store IDs from persistent storage.
   */
  getKeystoreIDs(): Promise<string[]>;
}
