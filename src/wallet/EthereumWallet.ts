import { EthereumNetworkRecord } from "./EthereumNetwork";
import { DeterministicKey } from "../walletcore/deterministickey";
import { HDKey, KeySpec } from "../walletcore/hdkey";
import { BigNumber } from "ethers";

export class EthereumWallet {
  private _network: EthereumNetworkRecord;
  private _publicKey: Buffer;
  private _defaultGasPrice: BigNumber;
  private _defaultGasLimit: BigNumber;

  constructor(network: EthereumNetworkRecord, publicKey: Buffer) {
    this._network = network;
    this._publicKey = publicKey;
  }

  getPrimaryAddress() {
    const deterministicKey = new DeterministicKey(
      DeterministicKey.ETHEREUM_VERSIONS
    );
    deterministicKey.publicKey = this._publicKey;
    const hdkey = HDKey.fromKey(deterministicKey, KeySpec.Ethereum);
    const address = hdkey.getAddress();
    return address;
  }

  getPrimaryAddressPublicKey() {
    return this._publicKey.toString("hex");
  }

  setDefaultGasPrice(gasPrice: BigNumber) {
    this._defaultGasPrice = gasPrice;
  }

  getDefaultGasPrice(): BigNumber {
    return this._defaultGasPrice;
  }

  getDefaultGasLimit(): BigNumber {
    return this._defaultGasLimit;
  }

  getSymbol(): string {
    return "Ether";
  }

  walletHoldsEther(): boolean {
    return true;
  }

  getChainID(): string {
    return this._network.name.split("-")[0];
  }
}
