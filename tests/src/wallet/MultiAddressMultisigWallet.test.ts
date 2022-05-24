import {
  MasterWalletManager,
  BrowserLocalStorage,
  SubWallet,
  EncodedTx,
  SignedInfo
} from "@elastosfoundation/wallet-js-sdk";

export const multisigWallet = async () => {
  let masterWalletManager: MasterWalletManager;
  const netType = "TestNet";

  const browserStorage = new BrowserLocalStorage();
  const netConfig = { NetType: netType, ELA: {} };

  masterWalletManager = await MasterWalletManager.create(
    browserStorage,
    netType,
    netConfig
  );

  const passphrase = "";
  const payPassword = "11111111";
  const singleAddress = false;

  const masterWalletID = "master-wallet-id-4";
  const mnemonic = `moon always junk crash fun exist stumble shift over benefit fun toe`;

  const masterWallet = await masterWalletManager.createMasterWallet(
    masterWalletID,
    mnemonic,
    passphrase,
    payPassword,
    singleAddress
  );
  console.log("masterWallet...", masterWallet);
  const xPubKey = masterWallet.getPubKeyInfo().xPubKeyHDPM;
  console.log("xPubKey...", xPubKey);
  const subWallet: any = await masterWallet.createSubWallet("ELA");
  const addresses = subWallet.getAddresses(0, 3, false);
  console.log("addresses...", addresses);

  const mnemonic1 = `response soft uphold fun ride cable biology raccoon exchange loyal yellow elegant`;
  const masterWallet1 = await masterWalletManager.createMasterWallet(
    "master-wallet-id-5",
    mnemonic1,
    passphrase,
    payPassword,
    singleAddress
  );

  const subWallet1: SubWallet = await masterWallet1.createSubWallet("ELA");
  const addresses1 = subWallet1.getAddresses(0, 3, false);
  console.log("addresses1...", addresses1);
  const xPubKey1 = masterWallet1.getPubKeyInfo().xPubKeyHDPM;
  console.log("xPubKey1...", xPubKey1);

  const mnemonic2 = `cheap exotic web cabbage discover camera vanish damage version allow merge scheme`;
  const masterWallet2 = await masterWalletManager.createMasterWallet(
    "master-wallet-id-6",
    mnemonic2,
    passphrase,
    payPassword,
    singleAddress
  );

  const subWallet2: any = await masterWallet2.createSubWallet("ELA");
  const addresses2 = subWallet2.getAddresses(0, 3, false);
  console.log("addresses2...", addresses2);
  const xPubKey2 = masterWallet2.getPubKeyInfo().xPubKeyHDPM;
  console.log("xPubKey2...", xPubKey2);

  const mnemonic3 = `multiple always junk crash fun exist stumble shift over benefit fun toe`;
  const cosigners = [xPubKey, xPubKey1, xPubKey2];
  const m = 3;
  const masterWallet3 =
    await masterWalletManager.createMultiSignMasterWalletWithMnemonic(
      "master-wallet-id-7",
      mnemonic3,
      passphrase,
      payPassword,
      cosigners,
      m,
      false
    );

  const subWallet3: any = await masterWallet3.createSubWallet("ELA");
  const addresses3 = subWallet3.getAddresses(0, 3, false);

  const inputsJson = [
    {
      Address: addresses3[0],
      Amount: "100000000",
      TxHash:
        "b9bf4f41d1844c5f76cc86f82e5c3e113388ed97fa48e78051c367e1d9399f9b",
      Index: 0
    },
    {
      Address: addresses3[1],
      Amount: "100000000",
      TxHash:
        "b9bf4f41d1844c5f76cc86f82e5c3e113388ed97fa48e78051c367e1d9399f9b",
      Index: 0
    }
  ];
  const outputsJson = [
    {
      Address: "EfKiUnAeATTf7UbnMGf5EjAqYNKiG7ZH4L",
      Amount: "120000000"
    }
  ];
  const fee = "10000";
  const memo = "test creating a multisign transaction";

  const tx: EncodedTx = subWallet3.createTransaction(
    inputsJson,
    outputsJson,
    fee,
    memo
  );
  const signedTx: EncodedTx = await subWallet3.signTransaction(tx, payPassword);
  const signedTx1: EncodedTx = await subWallet1.signTransaction(
    signedTx,
    payPassword
  );
  const signedTx2: EncodedTx = await subWallet2.signTransaction(
    signedTx1,
    payPassword
  );
  const info: SignedInfo[] = subWallet2.getTransactionSignedInfo(signedTx2);
  console.log("multisig signedInfo...", info);

  expect(info.length).toEqual(2);
  expect(info[0].SignType).toEqual("MultiSign");
  expect(info[0].M).toEqual(3);
  expect(info[0].N).toEqual(4);
  expect(info[0].Signers.length).toEqual(3);
};
