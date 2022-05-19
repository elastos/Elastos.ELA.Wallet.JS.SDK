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

    const masterWalletID = "master-wallet-id-4";
    const mnemonic = `moon always junk crash fun exist stumble shift over benefit fun toe`;
    const masterWallet = await masterWalletManager.createMasterWallet(
      masterWalletID,
      mnemonic,
      passphrase,
      payPassword,
      singleAddress
    );

    const xPubKey = masterWallet.getPubKeyInfo().xPubKeyHDPM;
    const subWallet: any = await masterWallet.createSubWallet("ELA");
    const addresses = subWallet.getAddresses(0, 1, false);
    expect(addresses[0]).toEqual("EfKiUnAeATTf7UbnMGf5EjAqYNKiG7ZH4L");

    const mnemonic1 = `response soft uphold fun ride cable biology raccoon exchange loyal yellow elegant`;
    const masterWallet1 = await masterWalletManager.createMasterWallet(
      "master-wallet-id-5",
      mnemonic1,
      passphrase,
      payPassword,
      singleAddress
    );

    const xPubKey1 = masterWallet1.getPubKeyInfo().xPubKeyHDPM;
    const subWallet1: any = await masterWallet1.createSubWallet("ELA");
    const addresses1 = subWallet1.getAddresses(0, 1, false);
    expect(addresses1[0]).toEqual("EKJtTjmfJUaUsAoGQUtBjkzSoRtD211cGw");

    const mnemonic2 = `cheap exotic web cabbage discover camera vanish damage version allow merge scheme`;
    const masterWallet2 = await masterWalletManager.createMasterWallet(
      "master-wallet-id-6",
      mnemonic2,
      passphrase,
      payPassword,
      singleAddress
    );

    const xPubKey2 = masterWallet2.getPubKeyInfo().xPubKeyHDPM;
    const subWallet2: any = await masterWallet2.createSubWallet("ELA");
    const addresses2 = subWallet2.getAddresses(0, 1, false);
    expect(addresses2[0]).toEqual("EHvbf5bwLwdKF8CNzgiqgL7CYhttm7Uezo");

    const mnemonic3 = `multiple always junk crash fun exist stumble shift over benefit fun toe`;
    const cosigners = [xPubKey, xPubKey1, xPubKey2];
    const m = 2;
    const masterWallet3 =
      await masterWalletManager.createMultiSignMasterWalletWithMnemonic(
        "master-wallet-id-7",
        mnemonic3,
        passphrase,
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
    const signedTx = await subWallet1.signTransaction(tx, payPassword);
    console.log("multisig signedTx...", signedTx);
    const signedTx1 = await subWallet2.signTransaction(signedTx, payPassword);
    console.log("multisig signedTx1...", signedTx1);

    const signedInfo = subWallet.getTransactionSignedInfo(signedTx1);
    console.log("multisig signedInfo", signedInfo);
    const rawTx = subWallet.convertToRawTransaction(signedTx1);
    console.log("multisig rawTx", rawTx);
    // then call rpc 'sendrawtransaction' to send the rawTx to the ela testnet
  });
});

/* localStore data of the multisig wallet with id 'master-wallet-id-7'
{
  "xPrivKey": "U2FsdGVkX1/EEQ046WVovM/SEsxqFr1x9GHIDTvmFqjRtXvPKj9Dkwijg+TEgbWMFluxIMb8Jeze0bQ75B5DdRL2/CRLZV80mnxbLLp0YpqT28YgZzcPHhwY4lJp2hECPYxlZxckPXYEMZiNNhLSNE3NT2yVJ5A6Ht2YrfaRn5TzaQ882Rq39wXWjaNDRYQW",
  "xPubKey": "xpub6Bm9Ma4UzCWt3YmCrdqADJWZVUcQHqKvELz2yUvgLbivMxhNctnLRn5Pu1sYwCRFEEERipTCPphqTDAaT9Uizvdhvw25oM64mnRGuQiYLu8",
  "xPubKeyHDPM": "xpub69FELQsaiWdLw9x2rFjsykXA7zKAko3s56a8eaGov7qoJ2MztJwzLYYcgaxBDLaPqFHUZZqGcfxzUVV4ohFP9ai3EspLESWEUVwUwhqZxpv",
  "requestPrivKey": "U2FsdGVkX1/B84ui2t6oV8mHPevObfszGzPL4E9vqijWi23Mx7DiC6Fky43YcRwUhhaUj3zazM9dOmQQqM8ebZuqEEtunAmx+LBCllXpQ2MoOQaUDV0fp7XEZi2qw++UrhN1e/pozPwNO+AIKjHwS2480AnuS1SM1AJ48YyCzoKY391APMQXNwCCyvcT198Z",
  "requestPubKey": "025aa50c1f5f1e68204c1928fc621c46e63eff5f8c717eb5bca23f8557b9f96e8d",
  "publicKeyRing": [
    {
      "xPubKey": "xpub68yaz1bGWJkFwmWwotAyWXrWdMuQLnjzhs2wEAFtWuVcqpRBnXfLttDaEkP4YtwyPFBf2eAjHk7kjpAUnn7gzkcwfeznsN6F9LqRSFdfEKx",
      "requestPubKey": ""
    },
    {
      "xPubKey": "xpub69AWKAuw1yonLo3Kueatxg1pK1Tbpkqj4b58TBNJbpsfEfEXXA6CBwxEekKSjGDgiHDqC5XKvhYTAYH9qmyYfzsujTUUBC2q2Zx71KmMs3B",
      "requestPubKey": ""
    },
    {
      "xPubKey": "xpub67uvyrCFhKSTqmmv9TsrPc5S85DvdPS8Vg2xCfXr8ALB8YCyRo2hUwLxt6H2pT6GrinwVFFmUuAJijSsUKi9ze5FKmz1PtFapTSUXk6GBR5",
      "requestPubKey": ""
    },
    {
      "xPubKey": "xpub69FELQsaiWdLw9x2rFjsykXA7zKAko3s56a8eaGov7qoJ2MztJwzLYYcgaxBDLaPqFHUZZqGcfxzUVV4ohFP9ai3EspLESWEUVwUwhqZxpv",
      "requestPubKey": "025aa50c1f5f1e68204c1928fc621c46e63eff5f8c717eb5bca23f8557b9f96e8d"
    }
  ],
  "m": 2,
  "n": 4,
  "mnemonicHasPassphrase": false,
  "derivationStrategy": "BIP45",
  "account": 0,
  "mnemonic": "U2FsdGVkX19DYtHbXkjsR8d2nHG29OqD4SdmBsS6IFHz1DbuHXfXpdJHcDdrj8aECmYPx9rmmUWocPiCBUOdxh3U1Cgfthr5Bh1dHCvTFO1jHwebVwiAZwiGCaH5tUEnHSOFXxoK084gBo/ksoRgtAgObjgsD033EqtgXYhP3UbQTXag9cgbk8rAherV+WlsaiDAcxJ7/Kr6OWFCk7vwyATUDhHPM05/4x6XSdwrjk396gGdTh6wpAjgsEV+gkMcA+S3BDRo5+0ecaGwu1omBd1w0iojBlF6gDYnNx8fVbJR8NlpT82FniFycFJnztJXg5qwW2a5zpZNvGChpv4O/ZzKcXj1aGPJ0Xc4MP3+UF2o/KAF/XBPwxTEmAGXDrlDyledzzz/zPLnq6qvEbsusciA/Y+kO3nyaDFBHX0a9Fdi5qRHpXohLXlCw3RgONqt",
  "passphrase": "",
  "ownerPubKey": "",
  "singleAddress": true,
  "readonly": false,
  "coinInfo": null,
  "seed": "U2FsdGVkX18qHS/yfJRmZhmTCcC0OxC6K2j7bPHFHj+rhsVjTo/KloamBirqJ9yQ3awwVYHRWPU8Rey3fkcGZTLbeTYT8K4swj7et3K3ZGMf1D87gyV5W+BENlHmqz7QIjIYmDYDjT0e2CDYZgfNDVm3VaflnPRDKh6wjaphwfMP2L2w7k3Iyj2YJYIxfsuLQkl3vtHMyobP5L+qcAn99vepEv4ib0MWW3d7cDEABOIjPlTmV/4N+tgxOSYxJ5dfNSJHtwyNBplDPQUacFedKJLY9CHREs8C+FxRVwq87RexA92vjhSmpmZ7su3J1zVVH2BRjkX0o7fFzN8d1cV+85eC0H/lHoztJSTADjxS0p6kzugUtkFsMsw4Y5pQvEwP",
  "ethscPrimaryPubKey": "048116d3f5384a573c0eb890a79994428133fc1fff1771f0ac04ce3a56c674cc6b580c3c89eb2f84909fc4f0498106d9b7f13540d4aaaf1b611146bf8c9d431eb3",
  "ripplePrimaryPubKey": "022c487bdfcc7d5831beff7ff3d112eafe9f638bafcefa0cc42bcbc61b96ac4a0e",
  "xPubKeyBitcoin": "xpub6CnYN3zzjHbhCv8p3RPQo26xUGz2da3Dct8A5Epre4b16gbDWb2UL8x7tu64zJabTR56yaqTHKXRdwhwRih3BciwWLg38kuLTywEsFmmu92",
  "SinglePrivateKey": "U2FsdGVkX19QRxHGki8c++R3+Yo8cN7+9IZ2b54tNlgG6SDtIu9aItMwbpXS9yvBwHQop9EXYv6WPr6in5qSRjP3UFIgWMizdl8DF8Noc6nhTdw3oL9BpFjG4PIatQmTVNRL1T2jpEq7IBeBfjp+8PNcEOFwT4Yvv1jg+vvL4+IrFjZHJ9ankOLeVwtmU0vt"
}
*/
