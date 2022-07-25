import { KeystoreInfo } from "../walletcore/keystore";

/**
 * Base interface to store persitant wallet keystore data.
 */
export interface KeystoreStorage {
  /**
   * Loads a saved store and returns it as json.
   */
  loadStore(keystoreID: string): Promise<KeystoreInfo>;
  /**
   * Saves the given local store JSON representation to persistent storage.
   */
  saveStore(keystoreID: string, j: KeystoreInfo): Promise<void>;
  /**
   * remove a saved store from persistent storage.
   */
  removeStore(keystoreID: string): Promise<void>;
  /**
   * get all saved store IDs from persistent storage.
   */
  getKeystoreIDs(): Promise<string[]>;
}
