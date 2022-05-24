import {
  BrowserLocalStorage,
  MasterWalletManager,
  SignedInfo,
  EncodedTx
} from "@elastosfoundation/wallet-js-sdk";

export const singleWallet = async () => {
  const netType = "TestNet";
  const storage = new BrowserLocalStorage();
  const netConfig = { NetType: netType, ELA: {} };

  let masterWalletManager = await MasterWalletManager.create(
    storage,
    netType,
    netConfig
  );

  const masterWalletID = "master-wallet-id-3";
  let seed = `3c6f6c0a5aba9e1456a827587f36a45430812ef04aa8cac4774a7d533ecb486dca476c004ae65271305f8907128583d2112e1648a902d44e61d942b02121c2a4`;
  const passphrase = "";
  const passwd = "11111111";
  const singleAddress = false;
  const masterWallet = await masterWalletManager?.importWalletWithSeed(
    masterWalletID,
    seed,
    passwd,
    singleAddress,
    "",
    passphrase
  );
  const subWallet: any = await masterWallet.createSubWallet("ELA");

  const addresses = subWallet.getAddresses(0, 3, false);
  expect(addresses.length).toEqual(3);
  expect(addresses[0]).toEqual("EfKiUnAeATTf7UbnMGf5EjAqYNKiG7ZH4L");
  expect(addresses[1]).toEqual("EJsxRrKdQ1mVGhqXUpAwF9DUsLC2LDUn2y");
  expect(addresses[2]).toEqual("EQ8NnNwGv6fFyDSAjrsofGDCYoWAC94WaY");

  const inputsJson = [
    {
      Address: addresses[0],
      Amount: "960000",
      TxHash:
        "ef699deec22d52d98f87f211d10778896fd2001ff71b740f321bf9d8564900a6",
      Index: 1
    },
    {
      Address: addresses[1],
      Amount: "9000000",
      TxHash:
        "ef699deec22d52d98f87f211d10778896fd2001ff71b740f321bf9d8564900a6",
      Index: 0
    }
  ];
  const outputsJson = [
    {
      Address: addresses[2],
      Amount: "9900000"
    }
  ];
  const fee = "10000";
  const memo = "test creating a transaction";

  const tx: EncodedTx = subWallet.createTransaction(
    inputsJson,
    outputsJson,
    fee,
    memo
  );
  const signedTx: EncodedTx = await subWallet.signTransaction(tx, passwd);
  const signedInfo: SignedInfo[] = subWallet.getTransactionSignedInfo(signedTx);
  expect(signedInfo.length).toEqual(2);
  expect(signedInfo[0].SignType).toEqual("Standard");
  expect(signedInfo[0].Signers.length).toEqual(1);
  expect(signedInfo[0].Signers[0]).toEqual(
    "02abb13a00e3de666bb84a5a70875e3423150f4ce6ab2eb4d187dcf319b34be188"
  );
};
