export type EthereumNetworkRecord = {
  name: string;
  chainId: number;
  networkId: number;
};

export class EthereumNetworks {
  static ethereumNetworks: EthereumNetworkRecord[] = [];

  static networkGetChainId(network: EthereumNetworkRecord) {
    return network.chainId;
  }

  static networkGetNetworkId(network: EthereumNetworkRecord) {
    return network.networkId;
  }

  static networkGetName(network: EthereumNetworkRecord) {
    return network.name;
  }

  static networkCopyNameAsLowercase(network: EthereumNetworkRecord) {
    return network.name.toLowerCase();
  }

  static insertEthereumNetwork(
    name: string,
    chainId: number,
    networkId: number
  ) {
    if (!name || this.findEthereumNetwork(name) !== null) {
      return;
    }
    let network = {} as EthereumNetworkRecord;
    network.name = name;
    network.chainId = chainId;
    network.networkId = networkId;
    this.ethereumNetworks.push(network);
  }

  static findEthereumNetwork(name: string): EthereumNetworkRecord | null {
    for (let i = 0; i < this.ethereumNetworks.length; ++i) {
      if (this.ethereumNetworks[i].name === name) {
        return this.ethereumNetworks[i];
      }
    }
    return null;
  }
}

export class EthereumNetwork {
  private _network: EthereumNetworkRecord;

  constructor(network: EthereumNetworkRecord) {
    this._network = network;
  }

  getRaw() {
    return this._network;
  }
}
