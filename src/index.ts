import { BrowserLocalStorage } from "./persistence/implementations/BrowserLocalStorage";
import { WalletStorage } from "./persistence/WalletStorage";
import { MainchainSubWallet } from "./wallet/MainchainSubWallet";
import { MasterWallet } from "./wallet/MasterWallet";
import { MasterWalletManager } from "./wallet/MasterWalletManager";
import { SubWallet } from "./wallet/SubWallet";
import { HDKey, KeySpec } from "./walletcore/hdkey";
import { Mnemonic } from "./walletcore/mnemonic";
import { WalletErrorException } from "./common/exceptions/walleterror.exception";

export {
  BrowserLocalStorage,
  // Crypto
  Mnemonic,
  KeySpec,
  HDKey,
  // Wallets
  MasterWallet,
  MasterWalletManager,
  SubWallet,
  MainchainSubWallet,
  WalletErrorException
};
export type { WalletStorage };
