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

  const masterWalletID = "master-wallet-id-14";
  const mnemonic = `moon always junk crash fun exist stumble shift over benefit fun toe`;

  const masterWallet = await masterWalletManager.createMasterWallet(
    masterWalletID,
    mnemonic,
    passphrase,
    payPassword,
    singleAddress
  );

  const xPubKey = masterWallet.getPubKeyInfo().xPubKeyHDPM;
  expect(xPubKey).toEqual(
    "xpub68yaz1bGWJkFwmWwotAyWXrWdMuQLnjzhs2wEAFtWuVcqpRBnXfLttDaEkP4YtwyPFBf2eAjHk7kjpAUnn7gzkcwfeznsN6F9LqRSFdfEKx"
  );

  const subWallet: any = await masterWallet.createSubWallet("ELA");
  subWallet.getAddresses(0, 3, false);

  const mnemonic1 = `response soft uphold fun ride cable biology raccoon exchange loyal yellow elegant`;
  const masterWallet1 = await masterWalletManager.createMasterWallet(
    "master-wallet-id-15",
    mnemonic1,
    passphrase,
    payPassword,
    singleAddress
  );

  const subWallet1: SubWallet = await masterWallet1.createSubWallet("ELA");
  subWallet1.getAddresses(0, 3, false);

  const xPubKey1 = masterWallet1.getPubKeyInfo().xPubKeyHDPM;
  expect(xPubKey1).toEqual(
    "xpub68yaz1bGWJkFwmWwotAyWXrWdMuQLnjzhs2wEAFtWuVcqpRBnXfLttDaEkP4YtwyPFBf2eAjHk7kjpAUnn7gzkcwfeznsN6F9LqRSFdfEKx"
  );

  const mnemonic2 = `cheap exotic web cabbage discover camera vanish damage version allow merge scheme`;
  const masterWallet2 = await masterWalletManager.createMasterWallet(
    "master-wallet-id-16",
    mnemonic2,
    passphrase,
    payPassword,
    singleAddress
  );

  const subWallet2: any = await masterWallet2.createSubWallet("ELA");
  subWallet2.getAddresses(0, 3, false);

  const xPubKey2 = masterWallet2.getPubKeyInfo().xPubKeyHDPM;
  expect(xPubKey2).toEqual(
    "xpub67uvyrCFhKSTqmmv9TsrPc5S85DvdPS8Vg2xCfXr8ALB8YCyRo2hUwLxt6H2pT6GrinwVFFmUuAJijSsUKi9ze5FKmz1PtFapTSUXk6GBR5"
  );

  const mnemonic3 = `multiple always junk crash fun exist stumble shift over benefit fun toe`;
  const cosigners = [xPubKey, xPubKey1, xPubKey2];
  const m = 3;
  const masterWallet3 =
    await masterWalletManager.createMultiSignMasterWalletWithMnemonic(
      "master-wallet-id-17",
      mnemonic3,
      passphrase,
      payPassword,
      cosigners,
      m,
      false
    );

  const subWallet3: any = await masterWallet3.createSubWallet("ELA");
  const addresses3 = subWallet3.getAddresses(0, 3, false);

  expect(addresses3.length).toEqual(3);
  expect(addresses3[0]).toEqual("8TW3SaMpAd1RwcGLnsgmG8EPuHrYsMUSop");
  expect(addresses3[1]).toEqual("8P45GV9vgZzdtZCvXhSyxMEMgfjyGZznVr");
  expect(addresses3[2]).toEqual("8G138byd9xu82scunFEFqFMgpqdz4RrS6d");

  const inputsJson = [
    {
      Address: addresses3[0],
      Amount: "3000000",
      TxHash:
        "5b9d23e65a9521bf321f0d956a4a1da3301082cd0188a55b3ed3d5b778667258",
      Index: 0
    },
    {
      Address: addresses3[1],
      Amount: "4950000",
      TxHash:
        "b33297128dc47573ab8ec0fd8a28846a4dd216cd2a418242819c9b2f1f90c3d6",
      Index: 0
    },
    {
      Address: addresses3[2],
      Amount: "1990000",
      TxHash:
        "5b9d23e65a9521bf321f0d956a4a1da3301082cd0188a55b3ed3d5b778667258",
      Index: 1
    }
  ];
  const outputsJson = [
    {
      Address: "EfKiUnAeATTf7UbnMGf5EjAqYNKiG7ZH4L",
      Amount: "9930000"
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
  expect(info.length).toEqual(3);

  expect(info[0].SignType).toEqual("MultiSign");
  expect(info[0].M).toEqual(3);
  expect(info[0].N).toEqual(4);
  expect(info[0].Signers.length).toEqual(3);
  expect(info[0].Signers[0]).toEqual(
    "02ba6d6332cc4b2d499c24b7516a891a9021924fed5028380df6714438476b718a"
  );
  expect(info[0].Signers[1]).toEqual(
    "023ceb84fc0655dfdefe56b2292411429c45fc8a8ac98ed8fca23d59ef744f60ab"
  );
  expect(info[0].Signers[2]).toEqual(
    "0337a4fac5255cae5d3e4c3c85608c2f340117c1eceb527d485e865ffdd1e4ac27"
  );

  expect(info[1].SignType).toEqual("MultiSign");
  expect(info[1].M).toEqual(3);
  expect(info[1].N).toEqual(4);
  expect(info[1].Signers.length).toEqual(3);
  expect(info[1].Signers[0]).toEqual(
    "0230cb604996b32780e29e8d21300335175c3c20d1d4a9b3f8cab8ac4b5b8bf38c"
  );
  expect(info[1].Signers[1]).toEqual(
    "03b310497c8d6e6a4a3fc23a96815067e7fc784d37cde9b497eb635b2a720acad5"
  );
  expect(info[1].Signers[2]).toEqual(
    "03cfdc3f70c04b460a21c766c43bb35eac47eeeeb56ea55ff67dda84ba78095507"
  );

  expect(info[2].SignType).toEqual("MultiSign");
  expect(info[2].M).toEqual(3);
  expect(info[2].N).toEqual(4);
  expect(info[2].Signers.length).toEqual(3);
  expect(info[2].Signers[0]).toEqual(
    "03a37a0035df199582e0b0e3309a2db0188ee9d9d5c6c4d2f6e69732c2428d8361"
  );
  expect(info[2].Signers[1]).toEqual(
    "02fb8192bb89422fbf068e22a85348babde99e527673ab6259b713180e72bb0dbd"
  );
  expect(info[2].Signers[2]).toEqual(
    "0294a47a757b02c26cee0263cb37c771dc750ef8fc7148a6d379922fee40cb16fa"
  );
};
