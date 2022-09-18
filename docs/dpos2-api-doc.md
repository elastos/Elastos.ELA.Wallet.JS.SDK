## DPoS 2.0 APIs

### Methods

- [createStakeTransaction](dpos2-api-doc.md#createStakeTransaction)
- [createDPoSV2VoteTransaction](dpos2-api-doc.md#createDPoSV2VoteTransaction)
- [getDPoSV2ClaimRewardDigest](dpos2-api-doc.md#getDPoSV2ClaimRewardDigest)
- [createDPoSV2ClaimRewardTransaction](dpos2-api-doc.md#createDPoSV2ClaimRewardTransaction)
- [unstakeDigest](dpos2-api-doc.md#unstakeDigest)
- [createUnstakeTransaction](dpos2-api-doc.md#createUnstakeTransaction)

### createStakeTransaction

▸ **createStakeTransaction**(`inputs`: UTXOInput[], `payload`: PayloadStakeInfo, `lockAddress`: string, `amount`: string, `fee`: string, `memo`: string ): EncodedTx

_Defined in [src/wallet/MainchainSubWallet.ts:3581](https://github.com/elastos/Elastos.ELA.Wallet.JS.SDK/blob/wip/src/wallet/MainchainSubWallet.ts#L3581)_

**Parameters:**

| Name          | Type             | Description                |
| ------------- | ---------------- | -------------------------- |
| `inputs`      | UTXOInput[]      | inputs as an array of UTXO |
| `payload`     | PayloadStakeInfo | stake payload info         |
| `lockAddress` | string           | stake pool address         |
| `amount`      | string           | stake amount(SELA)         |
| `fee`         | string           | transaction fee            |
| `memo`        | string           | a short message            |

**Returns:** EncodedTx

#### Example &mdash; create an stake transaction

```js
import {
  MasterWalletManager,
  MainchainSubWallet,
  PayloadStakeInfo
} from "@elastosfoundation/wallet-js-sdk";
import { BrowserLocalStorage } from "your/implementation/BrowserLocalStorage";

const netType = "TestNet";
const browserStorage = new BrowserLocalStorage();
const netConfig = { NetType: netType, ELA: {} };

const masterWalletManager = await MasterWalletManager.create(
  browserStorage,
  netType,
  netConfig
);
const mnemonic = `your_wallet_mnemonic`;

const passphrase = "";
const passwd = "11111111";
const singleAddress = true;
const masterWalletID = "master-wallet-id-1";
const masterWallet = await masterWalletManager.createMasterWallet(
  masterWalletID,
  mnemonic,
  passphrase,
  passwd,
  singleAddress
);

let subWallet = (await masterWallet.createSubWallet(
  "ELA"
)) as MainchainSubWallet;

const addresses = subWallet.getAddresses(0, 1, false);

const inputs = [
  {
    Address: addresses[0],
    Amount: "999999988000",
    TxHash: "f7ef97040667cda4bdc08a8a8c49029e86422b43e15796ad84782f59271392e3",
    Index: 1
  }
];
const fee = "10000";
const memo = "DPoS 2.0 stake transaction";

// get a wallet's stake address
const stakeAddr = subWallet.getOwnerStakeAddress();
const payload: PayloadStakeInfo = {
  Version: 0,
  StakeAddress: stakeAddr
};
// lock address on LRW newtork
const lockAddress = "STAKEPooLXXXXXXXXXXXXXXXXXXXpP1PQ2";
const amount = "5000000000";
// create a stake transation
const tx = subWallet.createStakeTransaction(
  inputs,
  payload,
  lockAddress,
  amount,
  fee,
  memo
);
```

---

### createDPoSV2VoteTransaction

▸ **createDPoSV2VoteTransaction**(`inputs`: UTXOInput[], `payload`: VotingInfo, `fee`: string, `memo`: string): EncodedTx

_Defined in [src/wallet/MainchainSubWallet.ts:3687](https://github.com/elastos/Elastos.ELA.Wallet.JS.SDK/blob/wip/src/wallet/MainchainSubWallet.ts#L3687)_

**Parameters:**

| Name      | Type        | Description                |
| --------- | ----------- | -------------------------- |
| `inputs`  | UTXOInput[] | inputs as an array of UTXO |
| `payload` | VotingInfo  | vote payload info          |
| `fee`     | string      | transaction fee            |
| `memo`    | string      | a short message            |

**Returns:** EncodedTx

### Examples

Fristly, call this `getvoterights` API to check if you get vote rights

**Example call**

```
curl -X POST --data '{
  "jsonrpc": "2.0",
  "method" : "getvoterights",
  "params": {
    "stakeaddresses":["SZiBkTmn7jrrk7YEtkg75mUoDzSzvqFzov"], // replace with your wallet stake address
  }
}' -H 'content-type:application/json;' 'https://your_elastos_rpc_endpoint'
```

**Example response**

```json
{
  "jsonrpc": "2.0",
  "result": [
    {
      "stakeaddress": "SZiBkTmn7jrrk7YEtkg75mUoDzSzvqFzov",
      "totalvotesright": "0",
      "usedvotesinfo": {
        "useddposv2votes": [],
        "useddposvotes": [],
        "usedcrvotes": [],
        "usdedcrimpeachmentvotes": [],
        "usedcrcproposalvotes": []
      },
      "remainvoteright": ["0", "0", "0", "0", "0"] // non-zero represents you have vote rights
    }
  ],
  "id": null,
  "error": null
}
```

#### Example 1 &mdash; create a vote transaction

```js
// ... ignore code of creating the masterWallet
const subWallet = (await masterWallet.createSubWallet(
  "ELA"
)) as MainchainSubWallet;
const addresses = subWallet.getAddresses(0, 1, false);

const inputsJson = [
  {
    Address: addresses[0],
    Amount: "99980000",
    TxHash:
      "1e0238c62a7e5854cf75fc5f38f7f31147e5b418d2e7ef9fc12db868e159ff8b",
    Index: 0
  }
];

const voteContents: VotesContentInfo[] = [
  {
    VoteType: VoteContentType.DposV2,
    VotesInfo: [
      {
        Candidate:
          "02270a0997e6096434eb4793f10d7d8f29b046e69e6c28e9a5755c577f6dd60273",
        Votes: "100000000",
        Locktime: 22800
      }
    ]
  }
];
const fee = "10000";
const memo = "the vote transaction";

// payload version 0
const payload: VotingInfo = {
  Version: 0,
  Contents: voteContents
};

const tx: EncodedTx = subWallet.createDPoSV2VoteTransaction(
  inputsJson,
  payload,
  fee,
  memo
);
```

#### Example 2 &mdash; create a renewal vote transaction

Firstly, call this `getalldetaileddposv2votesget` API to get all refKeys of a wallet's stake address.

**Example call**

```
curl -X POST --data '{
  "jsonrpc": "2.0",
  "method": "getalldetaileddposv2votes",
  "params": {
    "stakeaddress":"SZiBkTmn7jrrk7YEtkg75mUoDzSzvqFzov" // replace with your stake address
  }
}' -H 'content-type:application/json;' 'https://your_elastos_rpc_endpoint'
```

**Example response**

```json
{
  "jsonrpc": "2.0",
  "result": [
    {
      "producerownerkey": "033d4537b7dbc3b36e572f2d5e34d562ae2d185f58009a1703653e436a92ba5168",
      "producernodekey": "024d9226369b3e8ef85af2836dbfc3e28be1aa94aff6d10ca8859938ef444e8d2e",
      "referkey": "fd96f02b66c2d36febdc04398bad243cead79c74aafd5aabb874bf881ef41d3d",
      "stakeaddress": "SZiBkTmn7jrrk7YEtkg75mUoDzSzvqFzov",
      "transactionhash": "9420d3d6ba4342df49c4cda55afaa31ec43abe1d92b6a65c30fa467555d77e5e",
      "blockheight": 15518,
      "payloadversion": 0,
      "votetype": 4,
      "info": {
        "candidate": "033d4537b7dbc3b36e572f2d5e34d562ae2d185f58009a1703653e436a92ba5168",
        "votes": "1",
        "locktime": 30000
      },
      "DPoSV2VoteRights": "3918.48150366"
    },
    {
      "producerownerkey": "02b3471905903b657c9ff91479f82476d4bb780b8a7844893eedcd96ac05da150b",
      "producernodekey": "02b7336cac9930c8777c611a2ada1a45cae8b6b8182e88151484358b0633b5aeaf",
      "referkey": "f13fbe121e2c6c63b0381bd4fe629e2748779b33cd99de831ba8a9c6f0ab8587",
      "stakeaddress": "SZiBkTmn7jrrk7YEtkg75mUoDzSzvqFzov",
      "transactionhash": "9420d3d6ba4342df49c4cda55afaa31ec43abe1d92b6a65c30fa467555d77e5e",
      "blockheight": 15518,
      "payloadversion": 0,
      "votetype": 4,
      "info": {
        "candidate": "02b3471905903b657c9ff91479f82476d4bb780b8a7844893eedcd96ac05da150b",
        "votes": "1",
        "locktime": 30000
      },
      "DPoSV2VoteRights": "3918.48150366"
    },
    ...
  ]
}
```

Secondly, create a renewal vote transaction

```js
// ... ignore code creating the masterWallet
const subWallet = (await masterWallet.createSubWallet(
  "ELA"
)) as MainchainSubWallet;
const addresses = subWallet.getAddresses(0, 1, false);

const inputsJson = [
  {
    Address: addresses[0],
    Amount: "99980000",
    TxHash:
      "1e0238c62a7e5854cf75fc5f38f7f31147e5b418d2e7ef9fc12db868e159ff8b",
    Index: 0
  }
];

// payload version 1
const payload = {
  Version: 1,
  RenewalVotesContent: [
    {
      ReferKey:
        "a9cf4c4dce306964bf8dc032980324763c14574eed6059f6d865a4608e5ac61e",
      VoteInfo: {
        Candidate:
          "0217f1279db6e4b3d6b5c0e06041dee6be1f5145daf7c83db88755af7cd3b653b0",
        Votes: "100000000",
        Locktime: 15500
      }
    }
  ]
};

const tx: EncodedTx = subWallet.createDPoSV2VoteTransaction(
  inputsJson,
  payload,
  fee,
  memo
);
```

---

### getDPoSV2ClaimRewardDigest

▸ **getDPoSV2ClaimRewardDigest**(`payload`: DPoSV2ClaimRewardInfo): string

_Defined in [src/wallet/MainchainSubWallet.ts:3743](https://github.com/elastos/Elastos.ELA.Wallet.JS.SDK/blob/wip/src/wallet/MainchainSubWallet.ts#L3743)_

Return digest of the DPoSV2ClaimRewardInfo payload v0

**Parameters:**

| Name      | Type                  | Description              |
| --------- | --------------------- | ------------------------ |
| `payload` | DPoSV2ClaimRewardInfo | payload info(payload v0) |

**Returns:** string

#### Example &mdash; Get a DPoSV2ClaimRewardInfo payload digest

```js
  // ... ignore the code of creating the masterWalet
  const subWallet = (await masterWallet.createSubWallet(
    "ELA"
  )) as MainchainSubWallet;
  const addresses = subWallet.getAddresses(0, 1, false);
  let code = subWallet.getCodeofOwnerStakeAddress();
  // claim reward payload version v0
  let digest = subWallet.getDPoSV2ClaimRewardDigest({
    ToAddress: addresses[0],
    Code: code,
    Value: "30000"
  });
```

---

### createDPoSV2ClaimRewardTransaction

▸ **createDPoSV2ClaimRewardTransaction**(`inputs`: UTXOInput[], `payload`: DPoSV2ClaimRewardInfo, `fee`: string, `memo`: string): EncodedTx

_Defined in [src/wallet/MainchainSubWallet.ts:3790](https://github.com/elastos/Elastos.ELA.Wallet.JS.SDK/blob/wip/src/wallet/MainchainSubWallet.ts#L3790)_

**Parameters:**

| Name      | Type        | Description                                          |
| --------- | ----------- | ---------------------------------------------------- |
| `inputs`  | UTXOInput[] | inputs as an array of UTXO                           |
| `payload` | VotingInfo  | vote payload info(support payload version v0 and v1) |
| `fee`     | string      | transaction fee                                      |
| `memo`    | string      | a short message                                      |

**Returns:** EncodedTx

#### Examples

Firstly, call this `dposv2rewardinfo` API to get the info how many rewards in your wallet.

**Example call**

```
curl -X POST --data '{
  "jsonrpc": "2.0",
  "method" : "dposv2rewardinfo",
  "params": {
    "address":"8TW3SaMpAd1RwcGLnsgmG8EPuHrYsMUSop", // replace with your wallet address
    "spendable":false
  }
}' -H 'content-type:application/json;' 'https://your_elastos_rpc_endpoint'
```

**Example response**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "address": "8TW3SaMpAd1RwcGLnsgmG8EPuHrYsMUSop",
    "claimable": "0",
    "claiming": "0",
    "claimed": "0"
  },
  "id": null,
  "error": null
}
```

#### Example 1 &mdash; create a claim reward transaction with a standard wallet

```js
  // ... ignore the code of creating the masterWallet
  const subWallet = (await masterWallet.createSubWallet(
    "ELA"
  )) as MainchainSubWallet;
  const addresses = subWallet.getAddresses(0, 1, false);
  const code = subWallet.getCodeofOwnerStakeAddress();
  const digest = subWallet.getDPoSV2ClaimRewardDigest({
    ToAddress: addresses[0],
    Code: code,
    Value: "30000" // the amount you wanna claim
  });

  const signature = await subWallet.signDigest(addresses[0], digest, passwd);
  const payload = {
    ToAddress: addresses[0],
    Code: code,
    Value: "30000",
    Signature: signature
  };

  const inputs = [
    {
      Address: addresses[0],
      Amount: "949999968000",
      TxHash:
        "424b8829732183b95f12d464f7da6f896790d0a2b0a1c2ea67c8951b17e1d84f",
      Index: 0
    }
  ];
  const fee = "10000";
  const memo = "standard wallet claim reward transaction";

  const tx = subWallet.createDPoSV2ClaimRewardTransaction(
    inputs,
    payload,
    fee,
    memo
  );
```

#### Example 2 &mdash; create a claim reward transaction with a multisig wallet

```js
  const netType = "TestNet";
  const browserStorage = new BrowserLocalStorage();
  const netConfig = { NetType: netType, ELA: {} };

  const masterWalletManager = await MasterWalletManager.create(
    browserStorage,
    netType,
    netConfig
  );

  const passphrase = "";
  const payPassword = "11111111";
  const singleAddress = false;

  const masterWalletID = "master-wallet-id-2";
  const mnemonic = `your_wallet_mnemonic`;

  const masterWallet = await masterWalletManager.createMasterWallet(
    masterWalletID,
    mnemonic,
    passphrase,
    payPassword,
    singleAddress
  );

  const xPubKey = masterWallet.getPubKeyInfo().xPubKeyHDPM;
  const subWallet = (await masterWallet.createSubWallet(
    "ELA"
  )) as MainchainSubWallet;
  const addresses = subWallet.getAddresses(0, 1, false);
  // [ 'EfKiUnAeATTf7UbnMGf5EjAqYNKiG7ZH4L' ]
  console.log("addresses...", addresses);

  const mnemonic1 = `your_wallet_mnemonic`;

  const masterWallet1 = await masterWalletManager.createMasterWallet(
    "master-wallet-id-3",
    mnemonic1,
    passphrase,
    payPassword,
    singleAddress
  );

  const subWallet1 = (await masterWallet1.createSubWallet(
    "ELA"
  )) as MainchainSubWallet;
  const addresses1 = subWallet1.getAddresses(0, 1, false);
  // [ 'EKJtTjmfJUaUsAoGQUtBjkzSoRtD211cGw' ]
  console.log("addresses1...", addresses1);
  const xPubKey1 = masterWallet1.getPubKeyInfo().xPubKeyHDPM;

  const mnemonic2 = `your_wallet_mnemonic`;
  const masterWallet2 = await masterWalletManager.createMasterWallet(
    "master-wallet-id-4",
    mnemonic2,
    passphrase,
    payPassword,
    singleAddress
  );

  const subWallet2 = (await masterWallet2.createSubWallet(
    "ELA"
  )) as MainchainSubWallet;
  const addresses2 = subWallet2.getAddresses(0, 1, false);
  // [ 'EHvbf5bwLwdKF8CNzgiqgL7CYhttm7Uezo' ]
  console.log("addresses2...", addresses2);
  const xPubKey2 = masterWallet2.getPubKeyInfo().xPubKeyHDPM;

  const mnemonic3 = `your_wallet_mnemonic`;
  const cosigners = [xPubKey, xPubKey1, xPubKey2];
  console.log("cosigners...", cosigners);
  const m = 3;
  const masterWallet3 =
    await masterWalletManager.createMultiSignMasterWalletWithMnemonic(
      "master-wallet-id-5",
      mnemonic3,
      passphrase,
      payPassword,
      cosigners,
      m,
      false
    );

  const subWallet3 = (await masterWallet3.createSubWallet(
    "ELA"
  )) as MainchainSubWallet;
  const addresses3 = subWallet3.getAddresses(0, 1, false);
  //['8TW3SaMpAd1RwcGLnsgmG8EPuHrYsMUSop']
  console.log("addresses3", addresses3);

  const publicKeyInfo = masterWallet3.getPubKeyInfo();

  const code = subWallet3.getCodeofOwnerStakeAddress();
  const digest = subWallet3.getDPoSV2ClaimRewardDigest({
    ToAddress: addresses3[0],
    Code: code,
    Value: "50000"
  });

  const signature3 = await subWallet3.signDigestWithxPubKey(
    publicKeyInfo.xPubKeyHDPM,
    publicKeyInfo.publicKeyRing,
    digest,
    payPassword
  );

  const signature1 = await subWallet1.signDigestWithxPubKey(
    xPubKey1,
    publicKeyInfo.publicKeyRing,
    digest,
    payPassword
  );

  const signature2 = await subWallet2.signDigestWithxPubKey(
    xPubKey2,
    publicKeyInfo.publicKeyRing,
    digest,
    payPassword
  );

  const istream = new ByteStream();
  istream.writeVarBytes(Buffer.from(signature3, "hex"));
  istream.writeVarBytes(Buffer.from(signature1, "hex"));
  istream.writeVarBytes(Buffer.from(signature2, "hex"));

  const signature = istream.getBytes().toString("hex");
  // claim reward payload v0
  const payload = {
    ToAddress: addresses3[0],
    Code: code,
    Value: "50000",
    Signature: signature
  };

  const inputs = [
    {
      Address: addresses3[0],
      Amount: "989999960000",
      TxHash:
        "b417e8cd9a0ca8feba7f0a36d6673224813b0dd3d86e5e6930297c1c61563d19",
      Index: 0
    }
  ];
  const fee = "10000";
  const memo = "multisign claim reward transaction";

  const tx = subWallet3.createDPoSV2ClaimRewardTransaction(
    inputs,
    payload,
    fee,
    memo
  );
```

#### Example 3 &mdash; create a claim reward payload v1 transaction with a multisig wallet

```js
// ignore code of creating the multisig wallet masterWallet3, please view the example 2
  const subWallet3 = (await masterWallet3.createSubWallet(
    "ELA"
  )) as MainchainSubWallet;
  const addresses3 = subWallet3.getAddresses(0, 1, false);

  const inputs = [
    {
      Address: addresses3[0],
      Amount: "99980000",
      TxHash:
        "9420d3d6ba4342df49c4cda55afaa31ec43abe1d92b6a65c30fa467555d77e5e",
      Index: 0
    }
  ];
  const fee = "10000";
  const memo = "multisign new claim reward transaction";

  // claim reward payload version v1
  const payload = {
    Value: "43875",
    ToAddress: "8TW3SaMpAd1RwcGLnsgmG8EPuHrYsMUSop"
  };

  const tx = subWallet3.createDPoSV2ClaimRewardTransaction(
    inputs,
    payload,
    fee,
    memo
  );
```

---

### unstakeDigest

▸ **unstakeDigest**(`payload`: UnstakeInfo): string

_Defined in [src/wallet/MainchainSubWallet.ts:3916](https://github.com/elastos/Elastos.ELA.Wallet.JS.SDK/blob/wip/src/wallet/MainchainSubWallet.ts#L3916)_

Return digest of the unstake payload v0

**Parameters:**

| Name      | Type        | Description                      |
| --------- | ----------- | -------------------------------- |
| `payload` | UnstakeInfo | unstake payload info(payload v0) |

**Returns:** string

#### Example &mdash; Get a unstake payload digest

```js
  // ... ignore the code of creating the masterWallet
  const subWallet = (await masterWallet.createSubWallet(
    "ELA"
  )) as MainchainSubWallet;
  const addresses = subWallet.getAddresses(0, 1, false);
  const code = subWallet.getCodeofOwnerStakeAddress();
  // payload version v0
  const payload: UnstakeInfo = {
    ToAddress: addresses[0],
    Code: code,
    Value: "2000000000"
  };
  const digest = subWallet.unstakeDigest(payload);
```

---

### createUnstakeTransaction

▸ **createUnstakeTransaction**(`inputs`: UTXOInput[], `payload`: UnstakeInfo, `fee`: string, `memo`: string): EncodedTx

_Defined in [src/wallet/MainchainSubWallet.ts:3957](https://github.com/elastos/Elastos.ELA.Wallet.JS.SDK/blob/wip/src/wallet/MainchainSubWallet.ts#L3957)_

**Parameters:**

| Name      | Type        | Description                                          |
| --------- | ----------- | ---------------------------------------------------- |
| `inputs`  | UTXOInput[] | inputs as an array of UTXO                           |
| `payload` | UnstakeInfo | unstake payload info(support two versions v0 and v1) |
| `fee`     | string      | transaction fee                                      |
| `memo`    | string      | a short message                                      |

**Returns:** EncodedTx

#### Example 1 &mdash; create an unstake transaction with a standard wallet

```js
  const netType = "TestNet";
  const browserStorage = new BrowserLocalStorage();
  const netConfig = { NetType: netType, ELA: {} };
  const masterWalletManager = await MasterWalletManager.create(
    browserStorage,
    netType,
    netConfig
  );

  const mnemonic = `your_wallet_mnemonic`;
  const passphrase = "";
  const passwd = "11111111";
  const singleAddress = true;
  const masterWalletID = "master-wallet-id-6";
  const masterWallet = await masterWalletManager.createMasterWallet(
    masterWalletID,
    mnemonic,
    passphrase,
    passwd,
    singleAddress
  );
  const subWallet = (await masterWallet.createSubWallet(
    "ELA"
  )) as MainchainSubWallet;
  const addresses = subWallet.getAddresses(0, 1, false);

  const code = subWallet.getCodeofOwnerStakeAddress();
  // unstake payload version v0
  const payload: UnstakeInfo = {
    ToAddress: addresses[0],
    Code: code,
    Value: "2000000000"
  };
  const digest = subWallet.unstakeDigest(payload);
  const signature = await subWallet.signDigest(addresses[0], digest, passwd);
  payload.Signature = signature;

  const inputs = [
    {
      Address: addresses[0],
      Amount: "949999958000",
      TxHash:
        "6dd37e03dca9baa60ed0f22dc8b7474ffd7e9670dcd38ab6e23270fc550819da",
      Index: 0
    }
  ];
  const fee = "10000";
  const memo = "standard wallet unstake transaction";
  const tx = subWallet.createUnstakeTransaction(inputs, payload, fee, memo);
```

#### Example 2 &mdash; create an unstake transaction with a multisig wallet

```js
  const netType = "TestNet";
  const browserStorage = new BrowserLocalStorage();
  const netConfig = { NetType: netType, ELA: {} };

  const masterWalletManager = await MasterWalletManager.create(
    browserStorage,
    netType,
    netConfig
  );

  const passphrase = "";
  const payPassword = "11111111";
  const singleAddress = false;
  const masterWalletID = "master-wallet-id-7";
  const mnemonic = `your_wallet_mnemonic`;
  const masterWallet = await masterWalletManager.createMasterWallet(
    masterWalletID,
    mnemonic,
    passphrase,
    payPassword,
    singleAddress
  );
  const xPubKey = masterWallet.getPubKeyInfo().xPubKeyHDPM;
  const subWallet = (await masterWallet.createSubWallet(
    "ELA"
  )) as MainchainSubWallet;
  const addresses = subWallet.getAddresses(0, 1, false);
  // [ 'EfKiUnAeATTf7UbnMGf5EjAqYNKiG7ZH4L' ]
  console.log("addresses...", addresses);

  const mnemonic1 = `your_wallet_mnemonic`;
  const masterWallet1 = await masterWalletManager.createMasterWallet(
    "master-wallet-id-8",
    mnemonic1,
    passphrase,
    payPassword,
    singleAddress
  );
  const subWallet1 = (await masterWallet1.createSubWallet(
    "ELA"
  )) as MainchainSubWallet;
  const addresses1 = subWallet1.getAddresses(0, 1, false);
  // [ 'EKJtTjmfJUaUsAoGQUtBjkzSoRtD211cGw' ]
  console.log("addresses1...", addresses1);
  const xPubKey1 = masterWallet1.getPubKeyInfo().xPubKeyHDPM;

  const mnemonic2 = `your_wallet_mnemonic`;
  const masterWallet2 = await masterWalletManager.createMasterWallet(
    "master-wallet-id-9",
    mnemonic2,
    passphrase,
    payPassword,
    singleAddress
  );
  const subWallet2 = (await masterWallet2.createSubWallet(
    "ELA"
  )) as MainchainSubWallet;
  const addresses2 = subWallet2.getAddresses(0, 1, false);
  const xPubKey2 = masterWallet2.getPubKeyInfo().xPubKeyHDPM;

  const mnemonic3 = `your_wallet_mnemonic`;
  const cosigners = [xPubKey, xPubKey1, xPubKey2];
  const m = 3;
  const masterWallet3 =
    await masterWalletManager.createMultiSignMasterWalletWithMnemonic(
      "master-wallet-id-10",
      mnemonic3,
      passphrase,
      payPassword,
      cosigners,
      m,
      false
    );

  const subWallet3 = (await masterWallet3.createSubWallet(
    "ELA"
  )) as MainchainSubWallet;
  const addresses3 = subWallet3.getAddresses(0, 1, false);
  //['8TW3SaMpAd1RwcGLnsgmG8EPuHrYsMUSop']

  const code = subWallet3.getCodeofOwnerStakeAddress();
  // unstake payload version v0
  const payload: UnstakeInfo = {
    ToAddress: "8TW3SaMpAd1RwcGLnsgmG8EPuHrYsMUSop",
    Code: code,
    Value: "1000000",
    Signature: signature
  };
  const digest = subWallet3.unstakeDigest(payload);

  const publicKeyInfo = masterWallet3.getPubKeyInfo();
  const signature3 = await subWallet3.signDigestWithxPubKey(
    publicKeyInfo.xPubKeyHDPM,
    publicKeyInfo.publicKeyRing,
    digest,
    payPassword
  );

  const signature1 = await subWallet1.signDigestWithxPubKey(
    xPubKey1,
    publicKeyInfo.publicKeyRing,
    digest,
    payPassword
  );

  const signature2 = await subWallet2.signDigestWithxPubKey(
    xPubKey2,
    publicKeyInfo.publicKeyRing,
    digest,
    payPassword
  );

  const istream = new ByteStream();
  istream.writeVarBytes(Buffer.from(signature3, "hex"));
  istream.writeVarBytes(Buffer.from(signature1, "hex"));
  istream.writeVarBytes(Buffer.from(signature2, "hex"));

  const signature = istream.getBytes().toString("hex");
  payload.Signature = signature;

  const inputs = [
    {
      Address: addresses3[0],
      Amount: "989999980000",
      TxHash:
        "587bcca7e17ec3d8b5c11a659dd81bf8a60f1ccf0ae9a003873d6405677080f1",
      Index: 0
    }
  ];
  const fee = "10000";
  const memo = "multisign stake transaction";

  const tx = subWallet3.createUnstakeTransaction(inputs, payload, fee, memo);
```

#### Example 3 &mdash; create an unstake payload v1 transaction with a multisig wallet

```js
  // ... ignore the code of creating a mulisig wallet, please check the example 2
  const subWallet3 = (await masterWallet3.createSubWallet(
    "ELA"
  )) as MainchainSubWallet;
  const addresses3 = subWallet3.getAddresses(0, 1, false);
  //['8TW3SaMpAd1RwcGLnsgmG8EPuHrYsMUSop']
  const inputs = [
    {
      Address: addresses3[0],
      Amount: "989999990000",
      TxHash:
        "0e0e1eab0e54cf9903b3477dee5c2840b838c36b797fb8670c6edcdf7e7e417e",
      Index: 1
    }
  ];

  const fee = "10000";
  const memo = "multisign v1 unstake transaction";

  // unstake payload version v1
  const payload: UnstakeInfo = {
    ToAddress: "8TW3SaMpAd1RwcGLnsgmG8EPuHrYsMUSop",
    Value: "100000000"
  };

  const tx = subWallet3.createUnstakeTransaction(inputs, payload, fee, memo);
```
