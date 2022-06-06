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
  MasterWallet,
  MasterWalletManager,
  BrowserLocalStorage,
  EncodedTx,
  SignedInfo
} from "@elastosfoundation/wallet-js-sdk";

describe("MasterWalletManager Tests", () => {
  let masterWalletManager: MasterWalletManager;

  test("create and sign a tx", async () => {
    const netType = "TestNet";
    const masterWalletID = "master-wallet-id-3";
    const browserStorage = new BrowserLocalStorage();
    const netConfig = { NetType: netType, ELA: {} };

    masterWalletManager = await MasterWalletManager.create(
      browserStorage,
      netType,
      netConfig
    );
    expect(masterWalletManager).toBeInstanceOf(MasterWalletManager);

    const mnemonic = `cloth always junk crash fun exist stumble shift over benefit fun toe`;
    const passphrase = "";
    const passwd = "11111111";
    const singleAddress = true;
    const masterWallet = await masterWalletManager.createMasterWallet(
      masterWalletID,
      mnemonic,
      passphrase,
      passwd,
      singleAddress
    );
    expect(masterWallet).toBeInstanceOf(MasterWallet);

    const subWallet: any = await masterWallet.createSubWallet("ELA");
    const addresses = subWallet.getAddresses(0, 1, false);
    expect(addresses[0]).toBe("EUL3gVZCdJaj6oRfGfzYu8v41ecZvE1Unz");

    const digest = `88486f91981d11adf53c327e7ab2556b00c8f89b18f56eab8ff72f940c6d8889`;

    const sigHex = `50cdc759396d1c229852f373d985abb06283c72153032e4b9716dfe426c94cfb45ca4807f6aa6930ef404d631afaaef5c0be48acfddb624a3990e19958aef646`;

    const signature = await subWallet.signDigest(addresses[0], digest, passwd);
    expect(signature).toBe(sigHex);

    const pubKeyData = [
      "031f56955cc005122f11cec5264ea5968240a90f01434fb0a1b7429be4b9157d46"
    ];

    const pubKeys = subWallet.getPublicKeys(0, 1, false);
    expect(pubKeys[0]).toBe(pubKeyData[0]);

    const pubKey = pubKeys[0];
    const rs = subWallet.verifyDigest(pubKey, digest, sigHex);
    expect(rs).toBe(true);

    const inputsJson = [
      {
        Address: addresses[0],
        Amount: "99960000",
        TxHash:
          "b9bf4f41d1844c5f76cc86f82e5c3e113388ed97fa48e78051c367e1d9399f9b",
        Index: 1
      }
    ];
    const outputsJson = [
      {
        Address: "EfKiUnAeATTf7UbnMGf5EjAqYNKiG7ZH4L",
        Amount: "99950000"
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
    const info: SignedInfo[] = subWallet.getTransactionSignedInfo(signedTx);
    expect(info.length).toEqual(1);
    expect(info[0].SignType).toEqual("Standard");
    expect(info[0].Signers.length).toEqual(1);
    expect(info[0].Signers[0]).toEqual(
      "031f56955cc005122f11cec5264ea5968240a90f01434fb0a1b7429be4b9157d46"
    );
    const rawTx = subWallet.convertToRawTransaction(signedTx);
    console.log("rawTx", rawTx);
    // then call rpc `sendrawtransaction` to send the rawTx to the ela testnet
  });
});
