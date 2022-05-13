import { json } from "../types";

/**
/**
 * Base interface to store persitant wallet data.
 */
export interface WalletStorage {
  setActiveMasterWalletID(masterWalletID?: string): Promise<void>;

  getActiveMasterWalletID(): Promise<string>;
  /**
   * Loads a saved store and returns it as json.
   */
  loadStore(masterWalletID?: string): Promise<json>;
  /**
   * Saves the given local store JSON representation to persistent storage.
   */
  saveStore(j: json): Promise<void>;

  getMasterWalletIDs(): Promise<string[]>;
}
