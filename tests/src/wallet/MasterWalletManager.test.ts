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
  MasterWallet,
  MasterWalletManager,
  BrowserLocalStorage
} from "@elastosfoundation/wallet-js-sdk";

describe("MasterWalletManager Tests", () => {
  let masterWalletManager: MasterWalletManager;

  test("instantiating with constructor should throw error", () => {
    const netType = "mainnet";
    const browserStorage = new BrowserLocalStorage("master-wallet-id-3");
    const netConfig = { NetType: "MainNet", ELA: {} };
    const t = () => {
      new MasterWalletManager(browserStorage, netType, netConfig);
    };
    const error = { Code: 20001, Message: "invalid NetType" };
    expect(t).toThrow(JSON.stringify(error));
  });

  test("create a master wallet on mainnet", () => {
    const netType = "MainNet";
    const masterWalletID = "master-wallet-id-3";
    const browserStorage = new BrowserLocalStorage(masterWalletID);
    const netConfig = { NetType: "MainNet", ELA: {} };

    masterWalletManager = new MasterWalletManager(
      browserStorage,
      netType,
      netConfig
    );
    expect(masterWalletManager).toBeInstanceOf(MasterWalletManager);

    const mnemonic = `student borrow old later combine acoustic donkey media ensure symbol science salad`;
    const passphrase = "11111111";
    const passwd = "11111111";
    const singleAddress = true;
    const masterWallet = masterWalletManager.createMasterWallet(
      masterWalletID,
      mnemonic,
      passphrase,
      passwd,
      singleAddress
    );
    expect(masterWallet).toBeInstanceOf(MasterWallet);
  });

  test("get master wallet IDs", () => {});
});
