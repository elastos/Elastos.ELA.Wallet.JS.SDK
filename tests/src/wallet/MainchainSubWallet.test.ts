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
  BrowserLocalStorage,
  EncodedTx,
  SignedInfo,
  MainchainSubWallet,
  VoteContentInfo
} from "@elastosfoundation/wallet-js-sdk";

describe("Mainchain SubWallet Transaction Tests", () => {
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
    expect(masterWalletManager).toBeInstanceOf(MasterWalletManager);
  });

  test("create vote transaction", async () => {
    const mnemonic = `moon always junk crash fun exist stumble shift over benefit fun toe`;
    const passphrase = "";
    const passwd = "11111111";
    const singleAddress = true;
    const masterWalletID = "master-wallet-id-18";
    const masterWallet = await masterWalletManager.createMasterWallet(
      masterWalletID,
      mnemonic,
      passphrase,
      passwd,
      singleAddress
    );

    const subWallet: MainchainSubWallet = await masterWallet.createSubWallet(
      "ELA"
    );
    const addresses = subWallet.getAddresses(0, 1, false);
    console.log("addresses...", addresses);

    const inputsJson = [
      {
        Address: "EfKiUnAeATTf7UbnMGf5EjAqYNKiG7ZH4L",
        Amount: "100000000",
        TxHash:
          "68f493a61a34a775b10af3df00713eba78d88d1b0d49b5834b0c332e7f976342",
        Index: 0
      }
    ];
    const voteContents: VoteContentInfo[] = [
      {
        Type: "CRCImpeachment",
        Candidates: { innnNZJLqmJ8uKfVHKFxhdqVtvipNHzmZs: "100000000" }
      },
      {
        Type: "CRCProposal",
        Candidates: {
          "109780cf45c7a6178ad674ac647545b47b10c2c3e3b0020266d0707e5ca8af7c":
            "100000000"
        }
      },
      {
        Type: "Delegate",
        Candidates: {
          "031f7a5a6bf3b2450cd9da4048d00a8ef1cb4912b5057535f65f3cc0e0c36f13b4":
            "100000000"
        }
      },
      {
        Type: "CRC",
        Candidates: {
          iXviwqspCcLFw3waXKyQFbeP82Cfg3S9Je: "1000", // CR10
          ifzo3Fx82sUb6BAqw6K9ok8trvfKPfFwTL: "1000" // CR11
        }
      }
    ];
    const fee = "10000";
    const memo = "test the vote transaction";

    const tx: EncodedTx = subWallet.createVoteTransaction(
      inputsJson,
      voteContents,
      fee,
      memo
    );
    console.log("tx...", tx);

    const rawTx = subWallet.convertToRawTransaction(tx);
    console.log("rawTx...", rawTx);

    const signedTx: EncodedTx = await subWallet.signTransaction(tx, passwd);
    console.log("signedTx...", signedTx);

    const signedRawTx = subWallet.convertToRawTransaction(signedTx);
    console.log("signedRawTx...", signedRawTx);

    const info: SignedInfo[] = subWallet.getTransactionSignedInfo(signedTx);
    console.log("info", info);

    expect(info.length).toEqual(1);
    expect(info[0].SignType).toEqual("Standard");
    expect(info[0].Signers.length).toEqual(1);
    expect(info[0].Signers[0]).toEqual(
      "035ddbb21dd78b19b887f7f10e82848e4ea57663082e990878946972ce12f3967a"
    );
  });
});
