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
  SignedInfo,
  MainchainSubWallet,
  KeystoreInfo
} from "@elastosfoundation/wallet-js-sdk";

describe("Standard Wallet Payment Tests", () => {
  let masterWalletManager: MasterWalletManager;
  beforeEach(async () => {
    const netType = "TestNet";

    const browserStorage = new BrowserLocalStorage();
    const netConfig = { NetType: netType, ELA: {} };

    masterWalletManager = await MasterWalletManager.create(
      browserStorage,
      netType,
      netConfig
    );
  });

  test("use a single-address wallet to create and sign a transaction", async () => {
    const mnemonic = `cloth always junk crash fun exist stumble shift over benefit fun toe`;
    const passphrase = "";
    const passwd = "11111111";
    const singleAddress = true;
    const masterWalletID = "master-wallet-id-3";
    const masterWallet = await masterWalletManager.createMasterWallet(
      masterWalletID,
      mnemonic,
      passphrase,
      passwd,
      singleAddress
    );
    expect(masterWallet).toBeInstanceOf(MasterWallet);

    const subWallet = (await masterWallet.createSubWallet(
      "ELA"
    )) as MainchainSubWallet;
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

    await masterWalletManager.destroyWallet(masterWalletID);
  });

  test("use a multi-address wallet to create and sign a transaction ", async () => {
    const masterWalletID = "master-wallet-id-12";
    let seed = `3c6f6c0a5aba9e1456a827587f36a45430812ef04aa8cac4774a7d533ecb486dca476c004ae65271305f8907128583d2112e1648a902d44e61d942b02121c2a4`;
    const passphrase = "";
    const passwd = "11111111";
    const singleAddress = false;
    const masterWallet = await masterWalletManager.importWalletWithSeed(
      masterWalletID,
      seed,
      passwd,
      singleAddress,
      "",
      passphrase
    );
    expect(masterWallet).toBeInstanceOf(MasterWallet);

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
    const signedInfo: SignedInfo[] =
      subWallet.getTransactionSignedInfo(signedTx);
    expect(signedInfo.length).toEqual(2);

    expect(signedInfo[0].SignType).toEqual("Standard");
    expect(signedInfo[0].Signers.length).toEqual(1);
    expect(signedInfo[0].Signers[0]).toEqual(
      "02abb13a00e3de666bb84a5a70875e3423150f4ce6ab2eb4d187dcf319b34be188"
    );

    expect(signedInfo[1].SignType).toEqual("Standard");
    expect(signedInfo[1].Signers.length).toEqual(1);
    expect(signedInfo[1].Signers[0]).toEqual(
      "035ddbb21dd78b19b887f7f10e82848e4ea57663082e990878946972ce12f3967a"
    );
  });

  test("create a wallet with keystore", async () => {
    const masterWalletID = "master-wallet-id-43";
    let seed = `3c6f6c0a5aba9e1456a827587f36a45430812ef04aa8cac4774a7d533ecb486dca476c004ae65271305f8907128583d2112e1648a902d44e61d942b02121c2a4`;
    const passphrase = "";
    const passwd = "11111111";
    const singleAddress = true;
    const masterWallet = await masterWalletManager.importWalletWithSeed(
      masterWalletID,
      seed,
      passwd,
      singleAddress,
      "",
      passphrase
    );

    let backupPassword = "11111111";
    let keystoreInfo: KeystoreInfo = await masterWallet.exportKeystore(
      backupPassword,
      passwd
    );

    await masterWalletManager.destroyWallet(masterWalletID);

    const masterWallet1 = await masterWalletManager.importWalletWithKeystore(
      "master-wallet-id-44",
      keystoreInfo,
      backupPassword,
      passwd
    );

    const subWallet = (await masterWallet1.createSubWallet(
      "ELA"
    )) as MainchainSubWallet;
    const addresses = subWallet.getAddresses(0, 1, false);
    const inputsJson = [
      {
        Address: addresses[0],
        Amount: "999970000",
        TxHash:
          "d13bb3b0b0032886661e40adf5fec9807f9452e0a38ef9b6e73f5bbc5df55207",
        Index: 0
      }
    ];
    const outputsJson = [
      {
        Address: "8TW3SaMpAd1RwcGLnsgmG8EPuHrYsMUSop",
        Amount: "200000000"
      }
    ];
    const fee = "10000";
    const memo = "keystore";

    const tx: EncodedTx = subWallet.createTransaction(
      inputsJson,
      outputsJson,
      fee,
      memo
    );
    const signedTx = await subWallet.signTransaction(tx, passwd);
    const info: SignedInfo[] = subWallet.getTransactionSignedInfo(signedTx);
    expect(info[0].Signers[0]).toEqual(
      "035ddbb21dd78b19b887f7f10e82848e4ea57663082e990878946972ce12f3967a"
    );
  });
});
