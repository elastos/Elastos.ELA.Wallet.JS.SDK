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
  NormalProposalOwnerInfo,
  ChangeProposalOwnerInfo,
  TerminateProposalOwnerInfo,
  ReceiveCustomIDOwnerInfo,
  SecretaryElectionInfo
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
        { Type: 0, Stage: 0, Amount: "100000000000" }, // Amount unit is sela
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

  test("test createProposalChangeOwnerTransaction", async () => {
    // get the suggestion #1111 on CR website into a proposal
    const mnemonic = `decline proud hero asthma drop involve drama borrow decrease buddy chalk raw`;
    const passphrase = "";
    const passwd = "11111111";
    const singleAddress = true;
    const masterWalletID = "master-wallet-id-25";
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

    let publicKey = "";
    const pubKeys = subWallet.getPublicKeys(0, 1, false);
    if (pubKeys instanceof Array) {
      publicKey = pubKeys[0];
    }

    let draftHash =
      "99283a47e2f70923633ad274aa791e07534deb7906a7cd6268b75c9fb8174ec7";
    let draftData =
      "504b0304140000080800813ad554885d1ead48000000500000000d00000070726f706f73616c2e6a736f6eabe65250502ac92cc94955b252507ada3fe3d9ec2dcffa273c5bd8f174ce86a7731b740dcc8c0c957440aa12938a4b8a12934b400aa142b9f9259965892599f97920412325ae5a00504b01021403140000080800813ad554885d1ead48000000500000000d0000000000000000000000a4810000000070726f706f73616c2e6a736f6e504b050600000000010001003b000000730000000000";

    let payload: ChangeProposalOwnerInfo = {
      CategoryData: "",
      OwnerPublicKey: publicKey,
      DraftHash: draftHash,
      DraftData: draftData,
      TargetProposalHash:
        "89f676ceb1b1abb1a2dcf53e386048df2742ef57b209af3d51daf586820b9c6d",
      NewOwnerPublicKey:
        "0287de855c87579ee3821ff4a3a3dc9072ca727cb53316d54f6d2f1709e821c5af",
      NewRecipient: "EWZVWjqoZaaiHpR18nLzDA5sZ63FUrhGXh"
    };

    let signature =
      "4fdddff276d0cb6e394990afe60d67b73cf83605b77f3bbb80c636345ae017a3bfabfeab43dac6f34e15e744f90fe02224f7092807f735ac3617a405a1b2ad6d";

    let newOwnerSignature =
      "e63a2e09384d95bc92333ba48d0469e8004a9e7d31084fe806833a9749f819e398e3c80f550444f32359f34e6c1d43cc13f7f01e520d177483fed4c34b36503e";

    // council member wallet
    const mnemonic1 = `joke coil tag chapter auto fold leave rather primary mobile battle tool`;

    const masterWalletID1 = "master-wallet-id-26";
    const masterWallet1 = await masterWalletManager.createMasterWallet(
      masterWalletID1,
      mnemonic1,
      passphrase,
      passwd,
      singleAddress
    );

    const crSubWallet: MainchainSubWallet = await masterWallet1.createSubWallet(
      "ELA"
    );

    const councilMemberAddresses = crSubWallet.getAddresses(0, 1, false);

    payload.Signature = signature;
    payload.NewOwnerSignature = newOwnerSignature;
    payload.CRCouncilMemberDID = "iSrCAT6BPaJbDTG9aL6GtLdhZUixZwAxJy";

    const crDigest =
      crSubWallet.proposalChangeOwnerCRCouncilMemberDigest(payload);

    let councilMemberSignature = await crSubWallet.signDigest(
      councilMemberAddresses[0],
      crDigest,
      passwd
    );

    payload.CRCouncilMemberSignature = councilMemberSignature;
    console.log("payload...", payload);

    const inputs = [
      {
        Address: councilMemberAddresses[0],
        Amount: "49999979900",
        TxHash:
          "5845f53c7fa710c944b6c1d0aff8ebacea36467e59afa69edcc2cf5617a1e2b1",
        Index: 0
      }
    ];
    const fee = "10000";
    const memo = "test the change owner proposal transaction";

    const tx: EncodedTx = crSubWallet.createProposalChangeOwnerTransaction(
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

  test("test createTerminateProposalTransaction", async () => {
    // get the suggestion #1112 on CR website into a proposal
    const mnemonic = `decline proud hero asthma drop involve drama borrow decrease buddy chalk raw`;
    const passphrase = "";
    const passwd = "11111111";
    const singleAddress = true;
    const masterWalletID = "master-wallet-id-27";
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

    let publicKey = "";
    const pubKeys = subWallet.getPublicKeys(0, 1, false);
    if (pubKeys instanceof Array) {
      publicKey = pubKeys[0];
    }

    let draftHash =
      "76c3b3b60973d15e13ac86a14fb13eccf58eacb0d71b64c29ed19ae3891822a7";

    let draftData = `504b03041400000808003674d554239582415e0000006c0000000d00000070726f706f73616c2e6a736f6eabe65250502ac92cc94955b252507ad63fe16967eff3dd1dcfd62e02b29f2decd03530333254d201a94a4c2a2e294a4c2e01297cb17fe6b319eb9f4d9cf16259e3e386268882dcfc92ccb2c492ccfc3c8492a75d2b9ecdd90552c2550b00504b010214031400000808003674d554239582415e0000006c0000000d0000000000000000000000a4810000000070726f706f73616c2e6a736f6e504b050600000000010001003b000000890000000000`;

    let payload: TerminateProposalOwnerInfo = {
      CategoryData: "",
      OwnerPublicKey: publicKey,
      DraftHash: draftHash,
      DraftData: draftData,
      TargetProposalHash:
        "14b44b68f99e414c35396b8d267e2434d7ae0c3d6a761c062fe782d08bea389d"
    };

    let signature =
      "404f66eec8b6476a7590399e6d147c0c60c0b3948ebd19f7af0b7f3a43eb7d901c05838e6297046ece38f907e7373c296d7e0630cce4b8927399dd25062242e8";

    // council member wallet
    const mnemonic1 = `joke coil tag chapter auto fold leave rather primary mobile battle tool`;

    const masterWalletID1 = "master-wallet-id-28";
    const masterWallet1 = await masterWalletManager.createMasterWallet(
      masterWalletID1,
      mnemonic1,
      passphrase,
      passwd,
      singleAddress
    );

    const crSubWallet: MainchainSubWallet = await masterWallet1.createSubWallet(
      "ELA"
    );

    const councilMemberAddresses = crSubWallet.getAddresses(0, 1, false);
    payload.Signature = signature;
    payload.CRCouncilMemberDID = "iSrCAT6BPaJbDTG9aL6GtLdhZUixZwAxJy";

    const crDigest =
      crSubWallet.terminateProposalCRCouncilMemberDigest(payload);

    let councilMemberSignature = await crSubWallet.signDigest(
      councilMemberAddresses[0],
      crDigest,
      passwd
    );
    payload.CRCouncilMemberSignature = councilMemberSignature;
    console.log("payload...", payload);

    const inputs = [
      {
        Address: councilMemberAddresses[0],
        Amount: "49999969900",
        TxHash:
          "73fe990d794099273d005cf16c61e975543f012356c97077cdae65a4766ab7c9",
        Index: 0
      }
    ];
    const fee = "10000";
    const memo = "test the change owner proposal transaction";

    const tx: EncodedTx = crSubWallet.createTerminateProposalTransaction(
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

  test("test createReceiveCustomIDTransaction", async () => {
    // get the suggestion #1114 on CR website into a proposal
    const mnemonic = `decline proud hero asthma drop involve drama borrow decrease buddy chalk raw`;
    const passphrase = "";
    const passwd = "11111111";
    const singleAddress = true;
    const masterWalletID = "master-wallet-id-29";
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

    let publicKey = "";
    const pubKeys = subWallet.getPublicKeys(0, 1, false);
    if (pubKeys instanceof Array) {
      publicKey = pubKeys[0];
    }
    console.log("publicKey...", publicKey);

    let draftHash =
      "2646352bac1e2af59954ffa1da94d6b69c9aa51a5251b2a821f9259d3fcead11";

    let draftData =
      "504b0304140000080800a074d5543020015c52000000590000000d00000070726f706f73616c2e6a736f6eabe65250502ac92cc94955b252507a3a61fdf3292b5e2e6a793e75e6f3592d2fda573d5d37ebc9ce4e174f175d03332343251d90f2c4a4e292a2c4e412900ea8506e7e4966596249667e1e48d04889ab1600504b01021403140000080800a074d5543020015c52000000590000000d0000000000000000000000a4810000000070726f706f73616c2e6a736f6e504b050600000000010001003b0000007d0000000000";

    let payload: ReceiveCustomIDOwnerInfo = {
      CategoryData: "",
      OwnerPublicKey: publicKey,
      DraftHash: draftHash,
      DraftData: draftData,
      ReceivedCustomIDList: ["12345678"],
      ReceiverDID: "iakWWbvg76NrJkQ8mERGHDYyposdT7ivjN"
    };

    let signature =
      "a2d51cb1597fe2649bae52c4f2b7b7303f3b567a91a4b3338d1a9ecd70ebfacce5bcecf4d6c89c575a5209c77585eac009fc3368d71c967a7587819efcbd2de9";

    // council member wallet
    const mnemonic1 = `joke coil tag chapter auto fold leave rather primary mobile battle tool`;

    const masterWalletID1 = "master-wallet-id-30";
    const masterWallet1 = await masterWalletManager.createMasterWallet(
      masterWalletID1,
      mnemonic1,
      passphrase,
      passwd,
      singleAddress
    );

    const crSubWallet: MainchainSubWallet = await masterWallet1.createSubWallet(
      "ELA"
    );

    const councilMemberAddresses = crSubWallet.getAddresses(0, 1, false);

    payload.Signature = signature;
    payload.CRCouncilMemberDID = "iSrCAT6BPaJbDTG9aL6GtLdhZUixZwAxJy";
    const crDigest = crSubWallet.receiveCustomIDCRCouncilMemberDigest(payload);
    let councilMemberSignature = await crSubWallet.signDigest(
      councilMemberAddresses[0],
      crDigest,
      passwd
    );
    payload.CRCouncilMemberSignature = councilMemberSignature;
    console.log("payload...", payload);

    const inputs = [
      {
        Address: councilMemberAddresses[0],
        Amount: "49999969900",
        TxHash:
          "73fe990d794099273d005cf16c61e975543f012356c97077cdae65a4766ab7c9",
        Index: 0
      }
    ];
    const fee = "10000";
    const memo = "test the change owner proposal transaction";

    const tx: EncodedTx = crSubWallet.createReceiveCustomIDTransaction(
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

  test("test createSecretaryGeneralElectionTransaction", async () => {
    // get the suggestion #1113 on CR website into a proposal
    const mnemonic = `decline proud hero asthma drop involve drama borrow decrease buddy chalk raw`;
    const passphrase = "";
    const passwd = "11111111";
    const singleAddress = true;
    const masterWallet = await masterWalletManager.createMasterWallet(
      "master-wallet-id-31",
      mnemonic,
      passphrase,
      passwd,
      singleAddress
    );
    const subWallet: MainchainSubWallet = await masterWallet.createSubWallet(
      "ELA"
    );

    let publicKey = "";
    const pubKeys = subWallet.getPublicKeys(0, 1, false);
    if (pubKeys instanceof Array) {
      publicKey = pubKeys[0];
    }

    let draftHash =
      "14805094730f50f9a45421fc75c08033bf9c50594384fa9f5b8054e45d564d11";

    let draftData =
      "504b03041400000808007174d5544ff466134d000000540000000d00000070726f706f73616c2e6a736f6eabe65250502ac92cc94955b252507ada3fe3d9ec2dcf97cf78b273d9cba9fb9fecd8e51c6460a86b606664a8a403529998545c5294985c02520c15cacd2fc92c4b2cc9cccf03091a2971d50200504b010214031400000808007174d5544ff466134d000000540000000d0000000000000000000000a4810000000070726f706f73616c2e6a736f6e504b050600000000010001003b000000780000000000";

    let payload: SecretaryElectionInfo = {
      CategoryData: "",
      OwnerPublicKey: publicKey,
      DraftHash: draftHash,
      DraftData: draftData,
      SecretaryGeneralPublicKey:
        "0287de855c87579ee3821ff4a3a3dc9072ca727cb53316d54f6d2f1709e821c5af",
      Signature:
        "efdd633ae9ec2973bb1066f37403feef0039a2935677ad7ad86f073491f9a4b6b141166e6800935f3b0d1543e2eeb6ed342424fca86f26b65f8a803a072a9df6",
      SecretaryGeneralDID: "iakWWbvg76NrJkQ8mERGHDYyposdT7ivjN",
      SecretaryGeneralSignature:
        "0089608ba5b1e4beded3a8ac96f0c49cfab6b6330f9e86427be9d6fe596d49d1b2fdd6ac8f6753dd29439f333baff46b70c59eeed3522d8766d5fcd410f808ac",
      CRCouncilMemberDID: "iSrCAT6BPaJbDTG9aL6GtLdhZUixZwAxJy"
    };

    // council member wallet
    const mnemonic1 = `joke coil tag chapter auto fold leave rather primary mobile battle tool`;

    const masterWallet1 = await masterWalletManager.createMasterWallet(
      "master-wallet-id-32",
      mnemonic1,
      passphrase,
      passwd,
      singleAddress
    );

    const crSubWallet: MainchainSubWallet = await masterWallet1.createSubWallet(
      "ELA"
    );

    const councilMemberAddresses = crSubWallet.getAddresses(0, 1, false);

    const crDigest =
      crSubWallet.proposalSecretaryGeneralElectionCRCouncilMemberDigest(
        payload
      );

    let councilMemberSignature = await crSubWallet.signDigest(
      councilMemberAddresses[0],
      crDigest,
      passwd
    );
    payload.CRCouncilMemberSignature = councilMemberSignature;

    const inputs = [
      {
        Address: councilMemberAddresses[0],
        Amount: "49999969900",
        TxHash:
          "73fe990d794099273d005cf16c61e975543f012356c97077cdae65a4766ab7c9",
        Index: 0
      }
    ];
    const fee = "10000";
    const memo = "test the change owner proposal transaction";

    const tx: EncodedTx = crSubWallet.createSecretaryGeneralElectionTransaction(
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
