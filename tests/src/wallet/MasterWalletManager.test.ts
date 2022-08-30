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
  MasterWallet
} from "@elastosfoundation/wallet-js-sdk";
import { NodejsFileStorage } from "../../../src/persistence/implementations/NodejsFileStorage";

describe("MasterWalletManager Tests", () => {
  test("generate a multisig master wallet with mnemonic", async () => {
    let masterWalletManager: MasterWalletManager;
    const netType = "TestNet";

    const walletStorage = new NodejsFileStorage();
    const netConfig = { NetType: netType, ELA: {} };

    masterWalletManager = await MasterWalletManager.create(
      walletStorage,
      netType,
      netConfig
    );

    const passphrase = "";
    const payPassword = "11111111";
    const singleAddress = true;
    const mnemonic3 = `multiple always junk crash fun exist stumble shift over benefit fun toe`;
    const cosigners = [
      "xpub68yaz1bGWJkFwmWwotAyWXrWdMuQLnjzhs2wEAFtWuVcqpRBnXfLttDaEkP4YtwyPFBf2eAjHk7kjpAUnn7gzkcwfeznsN6F9LqRSFdfEKx",
      "xpub69AWKAuw1yonLo3Kueatxg1pK1Tbpkqj4b58TBNJbpsfEfEXXA6CBwxEekKSjGDgiHDqC5XKvhYTAYH9qmyYfzsujTUUBC2q2Zx71KmMs3B",
      "xpub67uvyrCFhKSTqmmv9TsrPc5S85DvdPS8Vg2xCfXr8ALB8YCyRo2hUwLxt6H2pT6GrinwVFFmUuAJijSsUKi9ze5FKmz1PtFapTSUXk6GBR5"
    ];
    const m = 2;
    const masterWallet =
      await masterWalletManager.createMultiSignMasterWalletWithMnemonic(
        "master-wallet-id-7",
        mnemonic3,
        passphrase,
        payPassword,
        cosigners,
        m,
        singleAddress
      );
    expect(masterWallet).toBeInstanceOf(MasterWallet);
    const localStoreData = {
      xPrivKey:
        "U2FsdGVkX1+XKTLyRPlxOmxof7JHvsCi34xAXdjqXrECy6oFBSDbIrnRO8wjQ0YEtuCMginH7xOJoyHuT/Zd0w3yK++TC2YfNqcwVxzAbBMY4WP1HgcpcOheCuKU8Gvqg3dO9swlXPRSV9vIQB8p1zRB3Zk35syDM63yZj+zhr2cKgCV6RL0hzwTEAb+Pv5F",
      xPubKey:
        "xpub6Bm9Ma4UzCWt3YmCrdqADJWZVUcQHqKvELz2yUvgLbivMxhNctnLRn5Pu1sYwCRFEEERipTCPphqTDAaT9Uizvdhvw25oM64mnRGuQiYLu8",
      xPubKeyHDPM:
        "xpub69FELQsaiWdLw9x2rFjsykXA7zKAko3s56a8eaGov7qoJ2MztJwzLYYcgaxBDLaPqFHUZZqGcfxzUVV4ohFP9ai3EspLESWEUVwUwhqZxpv",
      requestPrivKey:
        "U2FsdGVkX1+xXZUNlDkTvUxuIc0TApN2WX1vj8DxHOys5ELNgur0KtFAhLpePSFQxGxDGKxsvImM/LNf1IUmVYW0yLCqIs3gLPw+m3evhHdP1CtcRijQO+Rae58rDJGoTBznGCD3ckUR3/pdQb4AnmVGGZZN/A3IQXesWoH0SYANAXD3etv3LUnJEFblvILg",
      requestPubKey:
        "025aa50c1f5f1e68204c1928fc621c46e63eff5f8c717eb5bca23f8557b9f96e8d",
      publicKeyRing: [
        {
          xPubKey:
            "xpub68yaz1bGWJkFwmWwotAyWXrWdMuQLnjzhs2wEAFtWuVcqpRBnXfLttDaEkP4YtwyPFBf2eAjHk7kjpAUnn7gzkcwfeznsN6F9LqRSFdfEKx",
          requestPubKey: ""
        },
        {
          xPubKey:
            "xpub69AWKAuw1yonLo3Kueatxg1pK1Tbpkqj4b58TBNJbpsfEfEXXA6CBwxEekKSjGDgiHDqC5XKvhYTAYH9qmyYfzsujTUUBC2q2Zx71KmMs3B",
          requestPubKey: ""
        },
        {
          xPubKey:
            "xpub67uvyrCFhKSTqmmv9TsrPc5S85DvdPS8Vg2xCfXr8ALB8YCyRo2hUwLxt6H2pT6GrinwVFFmUuAJijSsUKi9ze5FKmz1PtFapTSUXk6GBR5",
          requestPubKey: ""
        },
        {
          xPubKey:
            "xpub69FELQsaiWdLw9x2rFjsykXA7zKAko3s56a8eaGov7qoJ2MztJwzLYYcgaxBDLaPqFHUZZqGcfxzUVV4ohFP9ai3EspLESWEUVwUwhqZxpv",
          requestPubKey:
            "025aa50c1f5f1e68204c1928fc621c46e63eff5f8c717eb5bca23f8557b9f96e8d"
        }
      ],
      m: 2,
      n: 4,
      mnemonicHasPassphrase: false,
      derivationStrategy: "BIP45",
      account: 0,
      mnemonic:
        "U2FsdGVkX18ryl2x3/bGuP1YKZcZp4D9LgcBF2EnHbAz81NQ3XP6wbwknwXQx5LvWQoScpa70kK3zMUaaI8t7nveK2BkOJp/vyf1XXdjmtrAPTfQascTPmbU2ElG8nl1/DfCm5e0Cd7eMp14FkszX1X+G5o4I1AiggY4J5yqiAHKCqQHFX5rOkvOcbAOQIhIY4l0I1MbOSIRqcXLxv1og9HK82ZmNSfkiBDI0YY35pz+wUhKrQyDdPDcmSVEyIVY7nsY6z8RQSx+yRjXT8NwQYkqy2Al7EgSBiOv9pd0EUCulWVybOqQDsI+hK6AfSu0PofSq2KGgwZhRyAG/pIlE2s95HxhEPzEK3lTciDbXLzrXmmHNIULzsHq4xc5H4HbrwK9lTYZy9P7Fjx70ebCuaYZuIG3dCevd0jA4r/7qhNjhEzmy10cCOb7UfgcHG+x",
      passphrase: "",
      ownerPubKey: "",
      singleAddress: true,
      readonly: false,
      coinInfo: null,
      seed: "U2FsdGVkX1++rYq62KdwbhPjlpSYu3loGrfVtQQDdM+c2OH69hk6dRTG0OpMgtgXLMOL47XIOPCP1Mf4zZmRhBCk/d+h2wpkRpD2Mg5bzCbhcHI1YiHCh/0H2MEmR9yXkxj8zuOLjeuxlp1cRHncaZ83sc56l8Qx/WXsKayD4rPfl+q2sy2/UnH4zBjnliwCZqcOSr7zv2BeUc4cLkPm7UB+t1fNovtdBSKXtMoeT6alsQWaugkE3M+jfk8E/cPf/mizvqBmjGwdXU2Uh2wsKyEGuL/dyr/DpNGHxsb+/JzLPYjbDYeFdbdfQVXxVRMjjKEXHtA/VZwGX5OrBKHKHuJAiesFBOU022pp06f+7wsbvduuZIu0Tq1S+gysm4Tb",
      ethscPrimaryPubKey:
        "048116d3f5384a573c0eb890a79994428133fc1fff1771f0ac04ce3a56c674cc6b580c3c89eb2f84909fc4f0498106d9b7f13540d4aaaf1b611146bf8c9d431eb3",
      ripplePrimaryPubKey:
        "022c487bdfcc7d5831beff7ff3d112eafe9f638bafcefa0cc42bcbc61b96ac4a0e",
      xPubKeyBitcoin:
        "xpub6CnYN3zzjHbhCv8p3RPQo26xUGz2da3Dct8A5Epre4b16gbDWb2UL8x7tu64zJabTR56yaqTHKXRdwhwRih3BciwWLg38kuLTywEsFmmu92",
      SinglePrivateKey:
        "U2FsdGVkX1/15eV0X76Czgwc88mP+nmTb8/WKE+Juove7DkjTSPs5oZrjAFQ6rEQ5M+hbNSYogB9XOMH4ibvIvcYedIAt/SB10Hh0hZLuR2A+rDpv8Y8DJhapvEC+4MG4exVP+sRToRcr/q9UxFyK60jB2Gu37opGhO/xR/IhyQEbU8BGFkzQc4G6OkzZ9mi"
    };
    const savedData = await walletStorage.loadStore("master-wallet-id-7");
    expect(savedData.xPubKey).toEqual(localStoreData.xPubKey);
    expect(savedData.xPubKeyHDPM).toEqual(localStoreData.xPubKeyHDPM);
    expect(savedData.requestPubKey).toEqual(localStoreData.requestPubKey);

    expect(savedData.publicKeyRing.length).toEqual(4);
    expect(savedData.publicKeyRing[0].xPubKey).toEqual(
      localStoreData.publicKeyRing[0].xPubKey
    );
    expect(savedData.publicKeyRing[1].xPubKey).toEqual(
      localStoreData.publicKeyRing[1].xPubKey
    );
    expect(savedData.publicKeyRing[2].xPubKey).toEqual(
      localStoreData.publicKeyRing[2].xPubKey
    );
    expect(savedData.publicKeyRing[3].xPubKey).toEqual(
      localStoreData.publicKeyRing[3].xPubKey
    );
    expect(savedData.publicKeyRing[3].requestPubKey).toEqual(
      localStoreData.publicKeyRing[3].requestPubKey
    );

    expect(savedData.m).toEqual(localStoreData.m);
    expect(savedData.n).toEqual(localStoreData.n);
    expect(savedData.mnemonicHasPassphrase).toEqual(
      localStoreData.mnemonicHasPassphrase
    );
    expect(savedData.derivationStrategy).toEqual(
      localStoreData.derivationStrategy
    );
    expect(savedData.account).toEqual(localStoreData.account);
    expect(savedData.passphrase).toEqual(localStoreData.passphrase);
    expect(savedData.ownerPubKey).toEqual(localStoreData.ownerPubKey);
    expect(savedData.singleAddress).toEqual(localStoreData.singleAddress);
    expect(savedData.readonly).toEqual(localStoreData.readonly);
    expect(savedData.coinInfo).toEqual(localStoreData.coinInfo);
    expect(savedData.ethscPrimaryPubKey).toEqual(
      localStoreData.ethscPrimaryPubKey
    );
    expect(savedData.ripplePrimaryPubKey).toEqual(
      localStoreData.ripplePrimaryPubKey
    );
    expect(savedData.xPubKeyBitcoin).toEqual(localStoreData.xPubKeyBitcoin);

    await masterWalletManager.destroyWallet("master-wallet-id-7");
  });
});
