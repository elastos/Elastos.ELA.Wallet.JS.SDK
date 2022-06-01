/*
 * Copyright (c) 2022 Elastos Foundation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

import {
  MasterWalletManager,
  BrowserLocalStorage
} from "@elastosfoundation/wallet-js-sdk";

describe("MasterWalletManager Tests", () => {
  let masterWalletManager: MasterWalletManager;

  test("create a multisign wallet", async () => {
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
    const singleAddress = true;

    const masterWalletID = "master-wallet-id-8";
    const seed = `3c6f6c0a5aba9e1456a827587f36a45430812ef04aa8cac4774a7d533ecb486dca476c004ae65271305f8907128583d2112e1648a902d44e61d942b02121c2a4`;
    const masterWallet = await masterWalletManager.importWalletWithSeed(
      masterWalletID,
      seed,
      payPassword,
      singleAddress,
      "",
      passphrase
    );
    const xPubKey = masterWallet.getPubKeyInfo().xPubKeyHDPM;
    const subWallet: any = await masterWallet.createSubWallet("ELA");
    const addresses = subWallet.getAddresses(0, 1, false);
    expect(addresses[0]).toEqual("EfKiUnAeATTf7UbnMGf5EjAqYNKiG7ZH4L");

    const seed1 = `9d6c79835481f5ce97a7396f7f474151b28f8183c9be2ddbcacbcc32e0480c5849d0bfe5ca8884277dc4f07c5eda3ec97298ebc1e8c7e67ce41f914fa47fee05`;
    const masterWallet1 = await masterWalletManager.importWalletWithSeed(
      "master-wallet-id-9",
      seed1,
      payPassword,
      singleAddress,
      "",
      passphrase
    );
    const xPubKey1 = masterWallet1.getPubKeyInfo().xPubKeyHDPM;
    const subWallet1: any = await masterWallet1.createSubWallet("ELA");
    const addresses1 = subWallet1.getAddresses(0, 1, false);
    expect(addresses1[0]).toEqual("EKJtTjmfJUaUsAoGQUtBjkzSoRtD211cGw");

    const seed2 = `26acf44706d7d81ffac1cbe5ca2eea3df134bc9708f4938704bb2773b4fa49a76e2d9dd54989c5d6e9a2bedff72820be798b92ee83d4411dac535422387357e7`;
    const masterWallet2 = await masterWalletManager.importWalletWithSeed(
      "master-wallet-id-10",
      seed2,
      payPassword,
      singleAddress,
      "",
      passphrase
    );
    const xPubKey2 = masterWallet2.getPubKeyInfo().xPubKeyHDPM;
    const subWallet2: any = await masterWallet2.createSubWallet("ELA");
    const addresses2 = subWallet2.getAddresses(0, 1, false);
    expect(addresses2[0]).toEqual("EHvbf5bwLwdKF8CNzgiqgL7CYhttm7Uezo");

    const seed3 = `0960dd6877cf94a07837e590337ea29e19713de8a6cad64035fd36b6de1d0745a9e7c135a6e0555be0dd1d39f0c0139611951b1929c6df3bcb2208ee4eeb08fd`;

    const cosigners = [xPubKey, xPubKey1, xPubKey2];
    const m = 2;
    const masterWallet3 =
      await masterWalletManager.createMultiSignMasterWalletWithSeed(
        "master-wallet-id-11",
        seed3,
        payPassword,
        cosigners,
        m,
        singleAddress
      );

    const subWallet3: any = await masterWallet3.createSubWallet("ELA");
    const addresses3 = subWallet3.getAddresses(0, 1, false);
    expect(addresses3[0]).toEqual("8XPn7aHnFos8y5aaddi5ciNKmzNVDoaF5n");

    const inputsJson = [
      {
        Address: addresses3[0],
        Amount: "100000000",
        TxHash:
          "3fba8615b62a95104f0e65131d0db353c5def1afd84664ce3f00b0faf5812dbf",
        Index: 0
      }
    ];
    const outputsJson = [
      {
        Address: "EfKiUnAeATTf7UbnMGf5EjAqYNKiG7ZH4L",
        Amount: "10000000"
      }
    ];
    const fee = "10000";
    const memo = "test creating a multisign transaction";

    const tx = subWallet3.createTransaction(inputsJson, outputsJson, fee, memo);
    console.log("multisig tx", tx);
    const signedTx = await subWallet3.signTransaction(tx, payPassword);
    console.log("multisig signedTx...", signedTx);
    const signedTx1 = await subWallet1.signTransaction(signedTx, payPassword);
    console.log("multisig signedTx1...", signedTx1);

    const signedInfo = subWallet1.getTransactionSignedInfo(signedTx1);
    console.log("multisig signedInfo", signedInfo);
    const rawTx = subWallet1.convertToRawTransaction(signedTx1);
    console.log("multisig rawTx", rawTx);
    // then call rpc 'sendrawtransaction' to send the rawTx to the ela testnet
  });
});
