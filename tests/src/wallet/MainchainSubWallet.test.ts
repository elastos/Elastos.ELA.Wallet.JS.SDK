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
  VoteContentInfo,
  CRInfoPayload,
  CRInfoJson
} from "@elastosfoundation/wallet-js-sdk";
import BigNumber from "bignumber.js";

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
    subWallet.getAddresses(0, 1, false);
    const inputs = [
      {
        Address: "EfKiUnAeATTf7UbnMGf5EjAqYNKiG7ZH4L",
        Amount: "1000000000000",
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
      inputs,
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

  test("create register producer transaction", async () => {
    const mnemonic = `moon always junk crash fun exist stumble shift over benefit fun toe`;
    const passphrase = "";
    const passwd = "11111111";
    const singleAddress = true;
    const masterWalletID = "master-wallet-id-19";
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
    subWallet.getAddresses(0, 1, false);

    const ownerPublicKey = subWallet.getOwnerPublicKey();
    const nodePublicKey =
      "020c3d28bb2ee7365348722c686b4b60a10ddca032c444e3170022cd35bb079138";
    const nickName = "elastos";
    const url = "elastos.info";
    const ipAddress = "162.241.11.xxx";
    const location = new BigNumber(0);
    const payPasswd = passwd;

    const payload = await subWallet.generateProducerPayload(
      ownerPublicKey,
      nodePublicKey,
      nickName,
      url,
      ipAddress,
      location,
      payPasswd
    );

    const inputs = [
      {
        Address: "EfKiUnAeATTf7UbnMGf5EjAqYNKiG7ZH4L",
        Amount: "999999988000",
        TxHash:
          "f7ef97040667cda4bdc08a8a8c49029e86422b43e15796ad84782f59271392e3",
        Index: 1
      }
    ];
    const amount = "500100000000";
    const fee = "10000";
    const memo = "test the register producer transaction";

    const tx: EncodedTx = subWallet.createRegisterProducerTransaction(
      inputs,
      payload,
      amount,
      fee,
      memo
    );

    const signedTx: EncodedTx = await subWallet.signTransaction(tx, passwd);
    const info: SignedInfo[] = subWallet.getTransactionSignedInfo(signedTx);

    expect(info.length).toEqual(1);
    expect(info[0].SignType).toEqual("Standard");
    expect(info[0].Signers.length).toEqual(1);
    expect(info[0].Signers[0]).toEqual(
      "035ddbb21dd78b19b887f7f10e82848e4ea57663082e990878946972ce12f3967a"
    );
  });

  test("create register CR transaction", async () => {
    let masterWalletManager: MasterWalletManager;
    const netType = "TestNet";

    const browserStorage = new BrowserLocalStorage();
    const netConfig = { NetType: netType, ELA: {} };

    masterWalletManager = await MasterWalletManager.create(
      browserStorage,
      netType,
      netConfig
    );
    const mnemonic = `moon always junk crash fun exist stumble shift over benefit fun toe`;
    const passphrase = "";
    const passwd = "11111111";
    const singleAddress = true;
    const masterWalletID = "master-wallet-id-20";
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
    const addr = subWallet.getAddresses(0, 1, false);
    let crPublicKey = "";
    const pubKeys = subWallet.getPublicKeys(0, 1, false);
    if (pubKeys instanceof Array) {
      crPublicKey = pubKeys[0];
    }
    // Get the DID matched with your public key through this tool:
    // https://zuohuahua.github.io/Elastos.Tools.Creator.Capsule/
    const did = "ia61JoWHzfghMrHFqrEVCtdWKjapoJt8av";
    const nickName = "cr10_新未当选1";
    const url = " ";
    const location = new BigNumber(0);

    let crPayload: CRInfoPayload = subWallet.generateCRInfoPayload(
      crPublicKey,
      did,
      nickName,
      url,
      location
    );

    let digest = crPayload.Digest;
    let signature = "";
    if (digest) {
      // Actually we should use DID SDK to sign a CR info payload.
      signature = await subWallet.signDigest(addr[0], digest, passwd);
    }

    let crInfo: CRInfoJson = {
      Code: crPayload.Code,
      CID: crPayload.CID,
      DID: crPayload.DID,
      NickName: crPayload.NickName,
      Url: crPayload.Url,
      Location: crPayload.Location,
      Signature: signature
    };

    const inputs = [
      {
        Address: addr[0],
        Amount: "999999988000",
        TxHash:
          "f7ef97040667cda4bdc08a8a8c49029e86422b43e15796ad84782f59271392e3",
        Index: 1
      }
    ];
    const amount = "501000000000";
    const fee = "10000";
    const memo = "test the register CR candidate transaction";

    const tx: EncodedTx = subWallet.createRegisterCRTransaction(
      inputs,
      crInfo,
      amount,
      fee,
      memo
    );

    const signedTx: EncodedTx = await subWallet.signTransaction(tx, passwd);
    const info: SignedInfo[] = subWallet.getTransactionSignedInfo(signedTx);
    expect(info.length).toEqual(1);
    expect(info[0].SignType).toEqual("Standard");
    expect(info[0].Signers.length).toEqual(1);
    expect(info[0].Signers[0]).toEqual(
      "035ddbb21dd78b19b887f7f10e82848e4ea57663082e990878946972ce12f3967a"
    );
  });
});
