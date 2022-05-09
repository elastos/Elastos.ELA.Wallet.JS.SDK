/*
 * Copyright (c) 2019 Elastos Foundation
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
  BrowserLocalStorage,
  Mnemonic
} from "@elastosfoundation/wallet-js-sdk";

describe("MasterWalletManager Tests", () => {
  let masterWalletManager: MasterWalletManager;

  test("create a multisign wallet", () => {
    const netType = "TestNet";

    const browserStorage = new BrowserLocalStorage();
    const netConfig = { NetType: netType, ELA: {} };

    masterWalletManager = new MasterWalletManager(
      browserStorage,
      netType,
      netConfig
    );

    const passphrase = "";
    const payPassword = "11111111";
    const singleAddress = true;

    const masterWalletID = "master-wallet-id-8";
    const mnemonic = `moon always junk crash fun exist stumble shift over benefit fun toe`;
    const masterWallet = masterWalletManager.createMasterWallet(
      masterWalletID,
      mnemonic,
      passphrase,
      payPassword,
      singleAddress
    );

    const localStore = browserStorage.loadStore(masterWalletID);
    console.log("localStore.xPubKeyHDPM....", localStore.xPubKeyHDPM);

    const subWallet: any = masterWallet.createSubWallet("ELA");
    const addresses = subWallet.getAddresses(0, 1, false);
    // [ 'EfKiUnAeATTf7UbnMGf5EjAqYNKiG7ZH4L' ]
    console.log("addresses...", addresses);

    const ids = browserStorage.getMasterWalletIDs();
    console.log("ids...", ids);

    const mnemonic1 = `response soft uphold fun ride cable biology raccoon exchange loyal yellow elegant`;
    const masterWallet1 = masterWalletManager.createMasterWallet(
      "master-wallet-id-9",
      mnemonic1,
      passphrase,
      payPassword,
      singleAddress
    );

    const localStore1 = browserStorage.loadStore("master-wallet-id-9");
    console.log("localStore1.xPubKeyHDPM....", localStore1.xPubKeyHDPM);

    const ids1 = browserStorage.getMasterWalletIDs();
    console.log("ids1...", ids1);

    const subWallet1: any = masterWallet1.createSubWallet("ELA");
    const addresses1 = subWallet1.getAddresses(0, 1, false);
    // [ 'EKJtTjmfJUaUsAoGQUtBjkzSoRtD211cGw' ]
    console.log("addresses1...", addresses1);

    const mnemonic2 = `cheap exotic web cabbage discover camera vanish damage version allow merge scheme`;
    const masterWallet2 = masterWalletManager.createMasterWallet(
      "master-wallet-id-10",
      mnemonic2,
      passphrase,
      payPassword,
      singleAddress
    );

    const localStore2 = browserStorage.loadStore("master-wallet-id-10");

    console.log("localStore2.xPubKeyHDPM....", localStore2.xPubKeyHDPM);

    const ids2 = browserStorage.getMasterWalletIDs();
    console.log("ids2...", ids2);

    const subWallet2: any = masterWallet2.createSubWallet("ELA");
    const addresses2 = subWallet2.getAddresses(0, 1, false);
    // [ 'EHvbf5bwLwdKF8CNzgiqgL7CYhttm7Uezo' ]
    console.log("addresses2...", addresses2);

    const mnemonic3 = `multiple always junk crash fun exist stumble shift over benefit fun toe`;
    const seed = Mnemonic.toSeed(mnemonic3, "").toString("hex");
    console.log("seed...", seed);
    expect(seed).toEqual(
      "0960dd6877cf94a07837e590337ea29e19713de8a6cad64035fd36b6de1d0745a9e7c135a6e0555be0dd1d39f0c0139611951b1929c6df3bcb2208ee4eeb08fd"
    );
    const cosigners = [
      localStore.xPubKeyHDPM as string,
      localStore1.xPubKeyHDPM as string,
      localStore2.xPubKeyHDPM as string
    ];
    const m = 2;
    const masterWallet3 =
      masterWalletManager.createMultiSignMasterWalletWithSeed(
        "master-wallet-id-11",
        seed,
        payPassword,
        cosigners,
        m,
        singleAddress
      );

    const localStore3 = browserStorage.loadStore("master-wallet-id-11");
    console.log("localStore3...", localStore3);

    const ids3 = browserStorage.getMasterWalletIDs();
    console.log("ids3...", ids3);

    const subWallet3: any = masterWallet3.createSubWallet("ELA");
    const addresses3 = subWallet3.getAddresses(0, 1, false);
    //['8XPn7aHnFos8y5aaddi5ciNKmzNVDoaF5n']
    console.log("addresses3...", addresses3);

    const inputsJson = [
      {
        Address: addresses3[0],
        Amount: "100000000",
        TxHash:
          "b9bf4f41d1844c5f76cc86f82e5c3e113388ed97fa48e78051c367e1d9399f9b",
        Index: 0
      }
    ];
    const outputsJson = [
      {
        Address: "EfKiUnAeATTf7UbnMGf5EjAqYNKiG7ZH4L",
        Amount: "40000000"
      }
    ];
    const fee = "10000";
    const memo = "test creating a multisign transaction";

    const tx = subWallet3.createTransaction(inputsJson, outputsJson, fee, memo);
    console.log("multisig tx", tx);
    const signedTx = subWallet1.signTransaction(tx, payPassword);
    console.log("multisig signedTx...", signedTx);
    const signedTx1 = subWallet2.signTransaction(signedTx, payPassword);
    console.log("multisig signedTx1...", signedTx1);

    const signedInfo = subWallet.getTransactionSignedInfo(signedTx1);
    console.log("multisig signedInfo", signedInfo);
    const rawTx = subWallet.convertToRawTransaction(signedTx1);
    console.log("multisig rawTx", rawTx);
    // then call rpc 'sendrawtransaction' to send the rawTx to the ela testnet
  });
});
