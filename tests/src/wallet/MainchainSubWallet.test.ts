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
  CRInfoJson,
  CRCouncilMemberClaimNodeInfo,
  NormalProposalOwnerInfo
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

  test("test createVoteTransaction", async () => {
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

  test("test createRegisterProducerTransaction", async () => {
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

  test("test createRegisterCRTransaction", async () => {
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

  test("test createRetrieveCRDepositTransaction", async () => {
    const mnemonic = `moon always junk crash fun exist stumble shift over benefit fun toe`;
    const passphrase = "";
    const passwd = "11111111";
    const singleAddress = true;
    const masterWalletID = "master-wallet-id-21";
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

    let depositAddress = subWallet.getCRDepositAddress();
    expect(depositAddress).toBe("DreWWZa4k6XuUcKcJRzSGUdGHMopoXnGUY");

    const inputs = [
      {
        Address: depositAddress,
        Amount: "501000000000",
        TxHash:
          "91d71b7cf2b43b4c6b715fc0738697c469192c51c2ee7aa9cd479f7b24dc5a82",
        Index: 0
      }
    ];
    const fee = "10000";
    const memo = "test the retrieve cr deposit transaction";
    const amount = "501000000000"; // funds you deposited
    const tx: EncodedTx = subWallet.createRetrieveCRDepositTransaction(
      inputs,
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

  test("test CRCouncilMemberClaimNodeTransaction", async () => {
    // the wallet of CR12 on private blockchain
    const mnemonic = `joke coil tag chapter auto fold leave rather primary mobile battle tool`;
    const passphrase = "";
    const passwd = "11111111";
    const singleAddress = true;
    const masterWalletID = "master-wallet-id-22";
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

    const nodePublicKey =
      "03b5d90257ad24caf22fa8a11ce270ea57f3c2597e52322b453d4919ebec4e6300";

    const councilMemberClaimNodeInfo: CRCouncilMemberClaimNodeInfo = {
      NodePublicKey: nodePublicKey,
      CRCouncilMemberDID: "iSrCAT6BPaJbDTG9aL6GtLdhZUixZwAxJy"
    };

    const digest = subWallet.CRCouncilMemberClaimNodeDigest(
      councilMemberClaimNodeInfo
    );
    let signature = await subWallet.signDigest(addresses[0], digest, passwd);
    councilMemberClaimNodeInfo.CRCouncilMemberSignature = signature;

    const inputs = [
      {
        Address: addresses[0],
        Amount: "49999999900",
        TxHash:
          "f0412f67766a8dfb662e2264808a594906db6e99f1078464862c2646811bed9b",
        Index: 1
      }
    ];
    const fee = "10000";
    const memo = "test the CR council member claim node transaction";

    const tx: EncodedTx = subWallet.createCRCouncilMemberClaimNodeTransaction(
      inputs,
      councilMemberClaimNodeInfo,
      fee,
      memo
    );
    const signedTx: EncodedTx = await subWallet.signTransaction(tx, passwd);
    const info: SignedInfo[] = subWallet.getTransactionSignedInfo(signedTx);

    expect(info.length).toEqual(1);
    expect(info[0].SignType).toEqual("Standard");
    expect(info[0].Signers.length).toEqual(1);
    expect(info[0].Signers[0]).toEqual(
      "02175944ed43bb7ec70a80e1856fb0324562502af36ba63e7f35fcbc2c712955f8"
    );
  });

  test("test createProposalTransaction", async () => {
    // convert the suggestion #1109 on CR website to a proposal
    // the wallet of a proposal owner on private blockchain
    const mnemonic = `decline proud hero asthma drop involve drama borrow decrease buddy chalk raw`;
    const passphrase = "";
    const passwd = "11111111";
    const singleAddress = true;

    const masterWallet = await masterWalletManager.createMasterWallet(
      "master-wallet-id-23",
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

    let publicKey = "";
    const pubKeys = subWallet.getPublicKeys(0, 1, false);
    if (pubKeys instanceof Array) {
      publicKey = pubKeys[0];
    }
    console.log("publicKey...", publicKey);

    // draft hash of the suggestion #1109
    // use api-3 of the CR website to get a suggesiton's details
    let draftHash = `ee5f375a91f04be31718df04f6d4cdc1d366c71179de602ef4a23e6f1ae16742`;

    // draft data of the suggestion #1109
    // use api-8 of the CR website to get a suggestion's draft data
    let draftData = `504b03041400000808002638d154b92bd6745c010000e40300000d00000070726f706f73616c2e6a736f6e8d534b4ec33010ddf71451d62dcaaf6e61cb11608750e5145359f2277206a4aaaa84106b9650362c3840bb618b380ca2945be049fa2389ac6e6c4fdebce7f19bcca4e5793e7010cc3fb10796c3406923a9180424ec0d42bf8d0934cdc1d02160cef65c205203bfa5c0b5426c171d95707a733562905becc2869e3729560be440477865d0de7cc9e8583205a78603339ca25ce817e0b4ddcc0d5ddcc8cd8d5cdcd8cd8d5ddc64cdb5eb65e91017d655ad58dd04e0d2425466f818d24d024248bfb7551f692a0a57370a9db21dff0d6c2cb5a24c48b7ef568eeacae121cac771dc0b9cca715d393a40994441d84d9cca495d39ae98cf652618b6a8f829cf1995f52e48265366507a68823d878d2e8702f74e056279a655ce532e388c31691fe5ea5a97d360988741c9ae94b6790feeeb69c9045567b6d4a262c4569f2fcbd9e27bfeba7cfa582dde97b3c7afbbfbfdc96ac8fe7d7bf8993fefb25bd33f504b010214031400000808002638d154b92bd6745c010000e40300000d0000000000000000000000a4810000000070726f706f73616c2e6a736f6e504b050600000000010001003b000000870100000000`;

    // signature of the suggestion #1109
    let signature =
      "1876996df6f9f470b05b81f93087d57d1256efb43cad877f3b7f05499090f5e0a63d2c508608526047ee59954a3783358d1efbae55f0d6df0ad10d2d4a1c9cec";

    let payload: NormalProposalOwnerInfo = {
      Type: 0,
      CategoryData: "",
      OwnerPublicKey: publicKey,
      DraftHash: draftHash,
      DraftData: draftData,
      Budgets: [
        { Type: 0, Stage: 0, Amount: "100000000000" },
        { Type: 1, Stage: 1, Amount: "100200000000" },
        { Type: 1, Stage: 2, Amount: "100300000000" },
        { Type: 2, Stage: 3, Amount: "100400000000" }
      ],
      Recipient: addresses[0]
    };

    // council member wallet
    const crMnemonic = `joke coil tag chapter auto fold leave rather primary mobile battle tool`;

    const crMasterWallet = await masterWalletManager.createMasterWallet(
      "master-wallet-id-24",
      crMnemonic,
      passphrase,
      passwd,
      singleAddress
    );

    const crSubWallet: MainchainSubWallet =
      await crMasterWallet.createSubWallet("ELA");

    const councilMemberAddresses = crSubWallet.getAddresses(0, 1, false);
    console.log("councilMemberAddresses", councilMemberAddresses);

    payload.Signature = signature;
    payload.CRCouncilMemberDID = "iSrCAT6BPaJbDTG9aL6GtLdhZUixZwAxJy";
    console.log("payload...", payload);

    const crDigest = crSubWallet.proposalCRCouncilMemberDigest(payload);

    let councilMemberSignature = await crSubWallet.signDigest(
      councilMemberAddresses[0],
      crDigest,
      passwd
    );
    payload.CRCouncilMemberSignature = councilMemberSignature;

    const inputs = [
      {
        Address: councilMemberAddresses[0],
        Amount: "49999989900",
        TxHash:
          "a90b92c2abff9ab4a0968d9a6de405a819f7915e64093ed94db86d2e12608d84",
        Index: 0
      }
    ];
    const fee = "10000";
    const memo = "create a normal proposal transaction";

    const tx: EncodedTx = crSubWallet.createProposalTransaction(
      inputs,
      payload,
      fee,
      memo
    );
    const signedTx: EncodedTx = await crSubWallet.signTransaction(tx, passwd);
    const info: SignedInfo[] = crSubWallet.getTransactionSignedInfo(signedTx);

    expect(info.length).toEqual(1);
    expect(info[0].SignType).toEqual("Standard");
    expect(info[0].Signers.length).toEqual(1);
    expect(info[0].Signers[0]).toEqual(
      "02175944ed43bb7ec70a80e1856fb0324562502af36ba63e7f35fcbc2c712955f8"
    );
  });
});
