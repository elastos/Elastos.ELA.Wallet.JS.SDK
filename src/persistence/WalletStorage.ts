import { json } from "../types";

/**
 * Base interface to store persitant wallet data.
 */
export interface WalletStorage {
  // The unique identification of a wallet
  currentMasterWalletID: string | null;
  masterWalletIDs: string[] | null;
  /**
   * Loads a saved store and returns it as json.
   */
  loadStore(masterWalletID?: string): json;
  /**
   * Saves the given local store JSON representation to persistent storage.
   */
  saveStore(j: json): void;
}
