import { LocalStoreInfo } from "./LocalStore";

/**
/**
 * Base interface to store persitant wallet data.
 */
export interface WalletStorage {
  /**
   * Loads a saved store and returns it as json.
   */
  loadStore(masterWalletID: string): Promise<LocalStoreInfo>;
  /**
   * Saves the given local store JSON representation to persistent storage.
   */
  saveStore(masterWalletID: string, j: LocalStoreInfo): Promise<void>;

  getMasterWalletIDs(): Promise<string[]>;
}
