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
    const netConfig = { NetType: netType, ELA: {} };
    const t = () => {
      new MasterWalletManager(browserStorage, netType, netConfig);
    };
    const error = { Code: 20001, Message: "invalid NetType" };
    expect(t).toThrow(JSON.stringify(error));
  });

  test("create and sign a tx", () => {
    const netType = "TestNet";
    const masterWalletID = "master-wallet-id-3";
    const browserStorage = new BrowserLocalStorage(masterWalletID);
    const netConfig = { NetType: netType, ELA: {} };

    masterWalletManager = new MasterWalletManager(
      browserStorage,
      netType,
      netConfig
    );
    expect(masterWalletManager).toBeInstanceOf(MasterWalletManager);

    const mnemonic = `cloth always junk crash fun exist stumble shift over benefit fun toe`;
    const passphrase = "";
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

    const subWallet: any = masterWallet.createSubWallet("ELA");

    // const localStore = browserStorage.loadStore(masterWalletID);

    const address = "EUL3gVZCdJaj6oRfGfzYu8v41ecZvE1Unz";
    const addresses = subWallet.getAddresses(0, 1, false);
    // the value of addresses is ['EUL3gVZCdJaj6oRfGfzYu8v41ecZvE1Unz']
    expect(addresses[0]).toBe(address);

    const digest = `88486f91981d11adf53c327e7ab2556b00c8f89b18f56eab8ff72f940c6d8889`;

    const sigHex = `50cdc759396d1c229852f373d985abb06283c72153032e4b9716dfe426c94cfb45ca4807f6aa6930ef404d631afaaef5c0be48acfddb624a3990e19958aef646`;

    const signature = subWallet.signDigest(addresses[0], digest, passwd);
    expect(signature).toBe(sigHex);

    const pubKeyData = [
      "031f56955cc005122f11cec5264ea5968240a90f01434fb0a1b7429be4b9157d46"
    ];

    const pubKeys = subWallet.getPublicKeys(0, 1, false);
    expect(pubKeys[0]).toBe(pubKeyData[0]);

    const pubKey = pubKeys[0];
    // const rs = subWallet.verifyDigest(pubKey, digest, signature);
    const rs = subWallet.verifyDigest(pubKey, digest, sigHex);
    expect(rs).toBe(true);

    const inputsJson = [
      {
        Address: addresses[0],
        Amount: "499990000",
        TxHash:
          "e10e3ab2bd5f4fb5d6cade98bb2c4f4f56d64bac50e7e8d8a9d37feb0e804df0",
        Index: 1
      }
    ];
    const outputsJson = [
      {
        Address: "EfKiUnAeATTf7UbnMGf5EjAqYNKiG7ZH4L",
        Amount: "200000000"
      }
    ];
    const fee = "10000";
    const memo = "test creating a transaction";

    const tx = subWallet.createTransaction(inputsJson, outputsJson, fee, memo);
    const signedTx = subWallet.signTransaction(tx, passwd);

    const signedInfo = subWallet.getTransactionSignedInfo(signedTx);
    const rawTx = subWallet.convertToRawTransaction(signedTx);
  });

  test("get master wallet IDs", () => {
    const masterWallets = masterWalletManager.getAllMasterWallets();
    expect(masterWallets.length).toBe(1);
  });
});

/* localStore data of the master wallet with master-wallet-id-3
{
  "xPrivKey": "U2FsdGVkX187fKODb1BguK6y894KpOxg501rUrr1O70P559TzUbMTGvVRXcGpCd5bLEkPerKAntIlIDZrqep1+RzC4BXBcoRRs2mNOnbgeCTXRZ60PYWEzwcUoSOtZHH60NkuJYZWXt4TF4JdiR4iT0qi5qtxL6DblJshuZimWkhn4eqDviJ8pumELUBmyC7IJoEWl3bqE7NXsIe6u1dPANo6bSVlEcMWW96FgEGu3k=",
  "xPubKey": "xpub6D85mnCjCnAh7JtBicwxdeW2qmUayEppbRBt84UwYFzmYKWuwfHW9nTrKqMmXvPjspDQU1zcbFv8wmSDyQh4kG96FA1eKc6i6Mwae2mGyGU",
  "xPubKeyHDPM": "xpub6954Nq5fpH52vaxQuNr15zTXdNMWqfrzgv1QfJR6rG9V4AnBjSagzs3f1Dq4r9ZnUWFFd4rigspLYEkNYi7nQyjzAMw2LTDX7RaANUXt5Fz",
  "requestPrivKey": "U2FsdGVkX1/vpfqlbP7bk57a2Dh228VablSwKC2B4jml9rtQNy89lQAqRouCreMzdQ2a1x+e+nBp5b2SUdmLpS5/F3uFIeA2ynlENESR7+lQNMTlzrhyAEt6fDX+xUW3O0B++PfZt67YG6hT1ET2BgflPBTMjE7K3xYt5MGUHZp/XF4ysia5KHhCfrZlAS381O6zdOTEQzLdRWDap4931xSpuL/TAu4wKx705gmLDj4=",
  "requestPubKey": "0254c4bbfda0bc6660214f8dd81c605fd368b7f8f070f96fe351bcc528b09d77a7",
  "publicKeyRing": [
    {
      "xPubKey": "xpub6954Nq5fpH52vaxQuNr15zTXdNMWqfrzgv1QfJR6rG9V4AnBjSagzs3f1Dq4r9ZnUWFFd4rigspLYEkNYi7nQyjzAMw2LTDX7RaANUXt5Fz",
      "requestPubKey": "0254c4bbfda0bc6660214f8dd81c605fd368b7f8f070f96fe351bcc528b09d77a7"
    }
  ],
  "m": 1,
  "n": 1,
  "mnemonicHasPassphrase": false,
  "derivationStrategy": "BIP44",
  "account": 0,
  "mnemonic": "U2FsdGVkX1/BntFP/cidYBZNydIrP2vegzwji0tJYErKDLkalgoZIiyoUhiiUZIynKl9jZfEIw8z5VMTHZD/05LHVKn7G1SzsRMUkiM4G1Fotlv6KVNGALndu2TqCuwwjPA7wbE4dLEZ6YigurbvpkQdyeKhHWt99N/KpbpdSF5zk6R+YUStOJYpxKHXICBP0e7Ilg+vgcc4CldmYzDKSkFFvjWAiaC4w4HBm8V6mAq+1R4dUhjjiQ/0xgSAAF4rxDn8tbj4+M11oWC+jx57a0386yHcqxt2O55ja6+Cje6YKilC9GWIzh/kP4sBY+Xnm3hvTe3F/4DUkkasL6C0lLQm5Rf6UGbR2Rmn0agTwr5Q1y/XefkF9Mm9a75Vi8kYfQZ8CuCnRckql2expXey719CRNK9d9xWXNtN+YBWLpU=",
  "ownerPubKey": "020c3d28bb2ee7365348722c686b4b60a10ddca032c444e3170022cd35bb079138",
  "singleAddress": true,
  "readonly": false,
  "coinInfo": [{ "ChainID": "ELA" }],
  "seed": "U2FsdGVkX19kNzYZQeYlnpZ2ZpAqhlTpBc8rQYOj0ffUMUVjKTv5jp5/3chJaJSKkDe+t0ljYjFymF71PnpQXeAnX0BAnOjU5vsOVcVODfiXEMXwCcmr5P/e8JT1MycqoQSIYEQD6kaiWTYmdwjKsN5QgyYC7YPHiJThXL4iitqAodeDNqFKPZl+tbvG+q96PxSza8Skld7jy1Xqm7nbMwmbysQb44FG0hf1UQ1ePE4BevHcLMvUSuJY0bs6RPaPqkt6P63LRrrA/MQJo+7HexqSSQizcTQiMXCVtYM02zvNfn0QCHm1FFBAGilqd+z2mNQPRYXQP//jFJ8zT2t/h5A2FMIX2sKBxlijJFi+yPSpQygIQ/H/UqksBRb7Z2Dy",
  "ethscPrimaryPubKey": "04caf60d80da2b6be7d1d7e9c4f77e73848e11c60c8d82d04589bd889acdd982101889abf48d793aeb2bc7206f3a81968bf1f340de1921270f9fbaa1b01179d250",
  "SinglePrivateKey": "U2FsdGVkX18N9Va4TV7JQEJJc7NECIpZWM1I1olEIHwz6ZwaXMsRfxmdBj6Xj3TXEoDOTQV6Ob+5EnCCyOVBQS9820qsLjTsXaI72IPmFtxiN7ZttHhpITj28dWflxsKNZBUlZUNhzD3NCBL9gFtsdcAWSLZGiR5+SCXiLuELYxq+ALnRI78SlacWYmVVefsUmKJr25vYplVa1JZ2BlESmumslrENNw/mAhhXxT7qNw=",
  "ripplePrimaryPubKey": "0328024e7d60a49bf573487ce9858f94434c7879dcd62be8bc1b8902e9c826bf6b",
  "xPubKeyBitcoin": "xpub6D2sniEHZaZqZSiFpMxai9e6EWxJtWMHYATkq8uYrF8jZGdA7dXQP15BWRwHZUZh8N5h9uCPjP6CCikr6F69JLHUq9wppXzbR8hmEK7SKp5",
  "passphrase": ""
}
*/
