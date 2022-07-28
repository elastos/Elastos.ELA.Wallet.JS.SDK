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

describe("MasterWallet Tests", () => {
  test("test some apis", async () => {
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

    let xPrivateKey = await masterWallet.exportPrivateKey(payPassword);
    expect(xPrivateKey).toBe(
      "xprv9s21ZrQH143K3uKo1oZyaVHkoF8DjZk6jcSMfb4hbJUu6bG8oLEL6NyPxu4sKihDoxSdFPm5drE2tv1ngdBWBhhP6Dn2hFMu1AcrpxqxodS"
    );

    let exportedMnemonic = await masterWallet.exportMnemonic(payPassword);
    expect(exportedMnemonic).toEqual(mnemonic);

    let masterPublicKey = masterWallet.exportMasterPublicKey();
    expect(masterPublicKey).toBe(
      "xpub6CTnJPzTxyn95eAr1iD4t91Xt9cgrb4FczDwGh9VuXmfEP7XhcBZ1BShEa3A9kAGHJcmA1gj3UBWzA4zQurtBkY7uYZgY7RztH1j4ZoC1tb"
    );

    let isValidPassPhrase = await masterWallet.verifyPassPhrase(
      "",
      payPassword
    );
    expect(isValidPassPhrase).toBe(true);

    let isValidPayPassword = await masterWallet.verifyPayPassword(payPassword);
    expect(isValidPayPassword).toBe(true);

    let isValidPrivateKey = masterWallet.verifyPrivateKey(mnemonic, passphrase);
    expect(isValidPrivateKey).toBe(true);

    let isValidAddr = masterWallet.isAddressValid(
      "EfKiUnAeATTf7UbnMGf5EjAqYNKiG7ZH4L"
    );
    expect(isValidAddr).toBe(true);

    let newPasswd = "22222222";
    await masterWallet.changePassword(payPassword, newPasswd);
    let isValidNewPassword = await masterWallet.verifyPayPassword(newPasswd);
    expect(isValidNewPassword).toBe(true);

    await masterWallet.resetPassword(mnemonic, passphrase, payPassword);
    let isValidOldPassword = await masterWallet.verifyPayPassword(payPassword);
    expect(isValidOldPassword).toBe(true);

    let readOnlyData = masterWallet.exportReadonlyWallet();
    let singleAccount = masterWallet.getAccount();
    let rs = singleAccount.importReadonlyWallet(
      readOnlyData as { Data: string }
    );
    expect(rs).toBe(true);
  });
});
