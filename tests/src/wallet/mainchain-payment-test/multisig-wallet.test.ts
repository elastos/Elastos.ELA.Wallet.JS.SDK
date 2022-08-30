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
  MainchainSubWallet,
  SignedInfo,
  EncodedTx,
  SigningPublicKeyInfo,
  MasterWallet
} from "@elastosfoundation/wallet-js-sdk";

import { NodejsFileStorage } from "../../../../src/persistence/implementations/NodejsFileStorage";

describe("MultiSig Wallet Payment Tests", () => {
  let masterWalletManager: MasterWalletManager;
  beforeEach(async () => {
    const netType = "TestNet";

    const walletStorage = new NodejsFileStorage();
    const netConfig = { NetType: netType, ELA: {} };

    masterWalletManager = await MasterWalletManager.create(
      walletStorage,
      netType,
      netConfig
    );
    expect(masterWalletManager).toBeInstanceOf(MasterWalletManager);
  });

  test("use a single-address wallet to test", async () => {
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
    expect(masterWallet).toBeInstanceOf(MasterWallet);

    const xPubKey = masterWallet.getPubKeyInfo().xPubKeyHDPM;
    const subWallet = (await masterWallet.createSubWallet(
      "ELA"
    )) as MainchainSubWallet;

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
    expect(masterWallet1).toBeInstanceOf(MasterWallet);

    const xPubKey1 = masterWallet1.getPubKeyInfo().xPubKeyHDPM;
    const subWallet1 = (await masterWallet1.createSubWallet(
      "ELA"
    )) as MainchainSubWallet;

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
    const subWallet2 = (await masterWallet2.createSubWallet(
      "ELA"
    )) as MainchainSubWallet;

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

    const subWallet3 = (await masterWallet3.createSubWallet(
      "ELA"
    )) as MainchainSubWallet;
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

    const tx: EncodedTx = subWallet3.createTransaction(
      inputsJson,
      outputsJson,
      fee,
      memo
    );
    const signedTx: EncodedTx = await subWallet3.signTransaction(
      tx,
      payPassword
    );
    const signedTx1: EncodedTx = await subWallet1.signTransaction(
      signedTx,
      payPassword
    );
    const info: SignedInfo[] = subWallet1.getTransactionSignedInfo(signedTx1);
    expect(info.length).toEqual(1);

    expect(info[0].SignType).toEqual("MultiSign");
    expect(info[0].M).toEqual(2);
    expect(info[0].N).toEqual(4);
    expect(info[0].Signers.length).toEqual(2);
    expect(info[0].Signers[0]).toEqual(
      "02ba6d6332cc4b2d499c24b7516a891a9021924fed5028380df6714438476b718a"
    );
    expect(info[0].Signers[1]).toEqual(
      "023ceb84fc0655dfdefe56b2292411429c45fc8a8ac98ed8fca23d59ef744f60ab"
    );

    const rawTx = subWallet1.convertToRawTransaction(signedTx1);
    console.log("single address multisig rawTx", rawTx);
    // then call rpc 'sendrawtransaction' to send the rawTx to the ela testnet
  });

  test("use a multi-address wallet to test", async () => {
    const passphrase = "";
    const payPassword = "11111111";
    const singleAddress = false;

    const masterWalletID = "master-wallet-id-14";
    const mnemonic = `moon always junk crash fun exist stumble shift over benefit fun toe`;

    const masterWallet = await masterWalletManager.createMasterWallet(
      masterWalletID,
      mnemonic,
      passphrase,
      payPassword,
      singleAddress
    );

    const xPubKey = masterWallet.getPubKeyInfo().xPubKeyHDPM;
    expect(xPubKey).toEqual(
      "xpub68yaz1bGWJkFwmWwotAyWXrWdMuQLnjzhs2wEAFtWuVcqpRBnXfLttDaEkP4YtwyPFBf2eAjHk7kjpAUnn7gzkcwfeznsN6F9LqRSFdfEKx"
    );

    const subWallet = (await masterWallet.createSubWallet(
      "ELA"
    )) as MainchainSubWallet;
    subWallet.getAddresses(0, 3, false);

    const mnemonic1 = `response soft uphold fun ride cable biology raccoon exchange loyal yellow elegant`;
    const masterWallet1 = await masterWalletManager.createMasterWallet(
      "master-wallet-id-15",
      mnemonic1,
      passphrase,
      payPassword,
      singleAddress
    );

    const subWallet1 = (await masterWallet1.createSubWallet(
      "ELA"
    )) as MainchainSubWallet;
    subWallet1.getAddresses(0, 3, false);

    const xPubKey1 = masterWallet1.getPubKeyInfo().xPubKeyHDPM;
    expect(xPubKey1).toEqual(
      "xpub69AWKAuw1yonLo3Kueatxg1pK1Tbpkqj4b58TBNJbpsfEfEXXA6CBwxEekKSjGDgiHDqC5XKvhYTAYH9qmyYfzsujTUUBC2q2Zx71KmMs3B"
    );

    const mnemonic2 = `cheap exotic web cabbage discover camera vanish damage version allow merge scheme`;
    const masterWallet2 = await masterWalletManager.createMasterWallet(
      "master-wallet-id-16",
      mnemonic2,
      passphrase,
      payPassword,
      singleAddress
    );

    const subWallet2 = (await masterWallet2.createSubWallet(
      "ELA"
    )) as MainchainSubWallet;
    subWallet2.getAddresses(0, 3, false);

    const xPubKey2 = masterWallet2.getPubKeyInfo().xPubKeyHDPM;
    expect(xPubKey2).toEqual(
      "xpub67uvyrCFhKSTqmmv9TsrPc5S85DvdPS8Vg2xCfXr8ALB8YCyRo2hUwLxt6H2pT6GrinwVFFmUuAJijSsUKi9ze5FKmz1PtFapTSUXk6GBR5"
    );

    const mnemonic3 = `multiple always junk crash fun exist stumble shift over benefit fun toe`;
    const cosigners = [xPubKey, xPubKey1, xPubKey2];
    const m = 3;
    const masterWallet3 =
      await masterWalletManager.createMultiSignMasterWalletWithMnemonic(
        "master-wallet-id-17",
        mnemonic3,
        passphrase,
        payPassword,
        cosigners,
        m,
        false
      );

    const subWallet3 = (await masterWallet3.createSubWallet(
      "ELA"
    )) as MainchainSubWallet;
    const addresses3 = subWallet3.getAddresses(0, 3, false);

    const xPubKey3 = masterWallet3.getPubKeyInfo().xPubKeyHDPM;
    expect(xPubKey3).toEqual(
      "xpub69FELQsaiWdLw9x2rFjsykXA7zKAko3s56a8eaGov7qoJ2MztJwzLYYcgaxBDLaPqFHUZZqGcfxzUVV4ohFP9ai3EspLESWEUVwUwhqZxpv"
    );

    expect(addresses3.length).toEqual(3);
    expect(addresses3[0]).toEqual("8TW3SaMpAd1RwcGLnsgmG8EPuHrYsMUSop");
    expect(addresses3[1]).toEqual("8P45GV9vgZzdtZCvXhSyxMEMgfjyGZznVr");
    expect(addresses3[2]).toEqual("8G138byd9xu82scunFEFqFMgpqdz4RrS6d");

    const inputsJson = [
      {
        Address: addresses3[0],
        Amount: "3000000",
        TxHash:
          "5b9d23e65a9521bf321f0d956a4a1da3301082cd0188a55b3ed3d5b778667258",
        Index: 0
      },
      {
        Address: addresses3[1],
        Amount: "4950000",
        TxHash:
          "b33297128dc47573ab8ec0fd8a28846a4dd216cd2a418242819c9b2f1f90c3d6",
        Index: 0
      },
      {
        Address: addresses3[2],
        Amount: "1990000",
        TxHash:
          "5b9d23e65a9521bf321f0d956a4a1da3301082cd0188a55b3ed3d5b778667258",
        Index: 1
      }
    ];
    const outputsJson = [
      {
        Address: "EfKiUnAeATTf7UbnMGf5EjAqYNKiG7ZH4L",
        Amount: "9930000"
      }
    ];
    const fee = "10000";
    const memo = "test creating a multisign transaction";

    const tx: EncodedTx = subWallet3.createTransaction(
      inputsJson,
      outputsJson,
      fee,
      memo
    );
    const signedTx: EncodedTx = await subWallet3.signTransaction(
      tx,
      payPassword
    );
    const signedTx1: EncodedTx = await subWallet1.signTransaction(
      signedTx,
      payPassword
    );

    const signedXPubKeys: SigningPublicKeyInfo[] =
      subWallet2.matchSigningPublicKeys(
        signedTx1,
        [...cosigners, xPubKey3],
        false
      );
    expect(signedXPubKeys.length).toEqual(4);
    expect(signedXPubKeys[0].xPubKey).toEqual(xPubKey3);
    expect(signedXPubKeys[0].signed).toEqual(true);
    expect(signedXPubKeys[1].xPubKey).toEqual(xPubKey2);
    expect(signedXPubKeys[1].signed).toEqual(false);
    expect(signedXPubKeys[2].xPubKey).toEqual(xPubKey1);
    expect(signedXPubKeys[2].signed).toEqual(true);
    expect(signedXPubKeys[3].xPubKey).toEqual(xPubKey);
    expect(signedXPubKeys[3].signed).toEqual(false);

    const signedTx2: EncodedTx = await subWallet2.signTransaction(
      signedTx1,
      payPassword
    );
    const info: SignedInfo[] = subWallet2.getTransactionSignedInfo(signedTx2);
    expect(info.length).toEqual(3);

    expect(info[0].SignType).toEqual("MultiSign");
    expect(info[0].M).toEqual(3);
    expect(info[0].N).toEqual(4);
    expect(info[0].Signers.length).toEqual(3);
    expect(info[0].Signers[0]).toEqual(
      "02ba6d6332cc4b2d499c24b7516a891a9021924fed5028380df6714438476b718a"
    );
    expect(info[0].Signers[1]).toEqual(
      "023ceb84fc0655dfdefe56b2292411429c45fc8a8ac98ed8fca23d59ef744f60ab"
    );
    expect(info[0].Signers[2]).toEqual(
      "0337a4fac5255cae5d3e4c3c85608c2f340117c1eceb527d485e865ffdd1e4ac27"
    );

    expect(info[1].SignType).toEqual("MultiSign");
    expect(info[1].M).toEqual(3);
    expect(info[1].N).toEqual(4);
    expect(info[1].Signers.length).toEqual(3);
    expect(info[1].Signers[0]).toEqual(
      "0230cb604996b32780e29e8d21300335175c3c20d1d4a9b3f8cab8ac4b5b8bf38c"
    );
    expect(info[1].Signers[1]).toEqual(
      "03b310497c8d6e6a4a3fc23a96815067e7fc784d37cde9b497eb635b2a720acad5"
    );
    expect(info[1].Signers[2]).toEqual(
      "03cfdc3f70c04b460a21c766c43bb35eac47eeeeb56ea55ff67dda84ba78095507"
    );

    expect(info[2].SignType).toEqual("MultiSign");
    expect(info[2].M).toEqual(3);
    expect(info[2].N).toEqual(4);
    expect(info[2].Signers.length).toEqual(3);
    expect(info[2].Signers[0]).toEqual(
      "03a37a0035df199582e0b0e3309a2db0188ee9d9d5c6c4d2f6e69732c2428d8361"
    );
    expect(info[2].Signers[1]).toEqual(
      "02fb8192bb89422fbf068e22a85348babde99e527673ab6259b713180e72bb0dbd"
    );
    expect(info[2].Signers[2]).toEqual(
      "0294a47a757b02c26cee0263cb37c771dc750ef8fc7148a6d379922fee40cb16fa"
    );
  });
});
