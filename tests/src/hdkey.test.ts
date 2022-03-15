/*
 * Copyright (c) 2021 Elastos Foundation
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

import { HDKey, KeySpec } from "@elastosfoundation/wallet-js-sdk";

describe('HDKey Tests', () => {
    test('Test Elastos', () => {
        let mnemonic = "cloth always junk crash fun exist stumble shift over benefit fun toe";

        let rootSK = "xprv9s21ZrQH143K3XXCfHWx6UAVbgAaxCXUMGeVAgDXpnnzeL9XKFEJjV2DLxut6mhoneSBdaNoBtfrnSEvba1QXXoEgGYiMYePbHHuTPXNmpG";
        let rootPK = "xpub661MyMwAqRbcG1bfmK3xTc7E9i15MfFKiVa5y4d9P8KyX8UfrnYZHHLhCEVfxXUK8Zu3RNWcYbNY7dk9LHzLwov5qebjGJa6MSVJg1tXkmg";
        let ki00SK = "xprvA3hqKDnMQGYbwA9sg71QKkgbnmQ2FVe6p8NwQFgrLD3EN6a8E1mYLnUia79cgoaMBnp5s3Mdfk4T5D6XnMZqPzhMmqgcbDt61ZPpuuGVCjE";
        let ki00PK = "xpub6GhBijKFEe6u9eELn8YQgtdLLoEWexMxBMJYCe6TtYaDEtuGmZ5ntaoCRNeafspiiDE25FWLoqJChhU9VmD5thjR6MQqd4Zx2ipSZ5ZbXdF";

        let address = "EUL3gVZCdJaj6oRfGfzYu8v41ecZvE1Unz";
        let DIDString = "iY4Ghz9tCuWvB5rNwvn4ngWvthZMNzEA7U";

        let root = HDKey.fromMnemonic(mnemonic, "", KeySpec.Elastos);
        console.log(root.serializeBase58());
        console.log(root.serializePublicKeyBase58());
        expect(root.serializeBase58()).toBe(rootSK);
        expect(root.serializePublicKeyBase58()).toBe(rootPK);

        let key = root.deriveWithPath(HDKey.ELASTOS_ACCOUNT_DERIVATION_PATH_PREFIX + '0');
        console.log(key.serializeBase58());
        console.log(key.serializePublicKeyBase58());
        expect(key.serializeBase58()).toBe(ki00SK);
        expect(key.serializePublicKeyBase58()).toBe(ki00PK);

        expect(key.getAddress()).toBe(address);
        expect(key.getDidAddress()).toBe(DIDString);
    });

    test('Test Bitcoin', () => {
        let mnemonic = "cloth always junk crash fun exist stumble shift over benefit fun toe";

        let rootSK = "xprv9s21ZrQH143K3XXCfHWx6UAVbgAaxCXUMGeVAgDXpnnzeL9XKFEJjV2DLxut6mhoneSBdaNoBtfrnSEvba1QXXoEgGYiMYePbHHuTPXNmpG";
        let rootPK = "xpub661MyMwAqRbcG1bfmK3xTc7E9i15MfFKiVa5y4d9P8KyX8UfrnYZHHLhCDcZr88kr6FnhhysasSKcn2SaFFV1evmCXGm1Quv3RFyk41TGp8";
        let ki00SK = "xprvA3wNUs2LhUmf54iXLLueRoB7dGeYFk7V3ckWJkUPyU4QX4pfQjpDmmdBZ1BCJCa3A9X2R82ycE8b17kT3AW8mmq6Gw8AjQpmAdRJmVDkBwE";
        let ki00PK = "xpub6GvitNZEXrKxHYnzSNSenw7rBJV2fCqLQqg778t1XobPPs9oxH8UKZwfQG9LpEeQ8r7b7GArMeCQVJQ89kcpWwLmVmdYk8gyNFWoYJ891tq";

        let address = "17A3DeeUTgL7HLacFVKx3kBqfkjkhVau5x";

        let root = HDKey.fromMnemonic(mnemonic, "", KeySpec.Bitcoin);
        console.log(root.serializeBase58());
        console.log(root.serializePublicKeyBase58());
        expect(root.serializeBase58()).toBe(rootSK);
        expect(root.serializePublicKeyBase58()).toBe(rootPK);

        let key = root.deriveWithPath(HDKey.BITCOIN_ACCOUNT_DERIVATION_PATH_PREFIX + '0');
        console.log(key.serializeBase58());
        console.log(key.serializePublicKeyBase58());
        expect(key.serializeBase58()).toBe(ki00SK);
        expect(key.serializePublicKeyBase58()).toBe(ki00PK);

        console.log(key.getAddress());
        expect(key.getAddress()).toBe(address);
    });

    test('Test Ethereum', () => {
        let mnemonic = "cloth always junk crash fun exist stumble shift over benefit fun toe";

        let rootSK = "xprv9s21ZrQH143K3XXCfHWx6UAVbgAaxCXUMGeVAgDXpnnzeL9XKFEJjV2DLxut6mhoneSBdaNoBtfrnSEvba1QXXoEgGYiMYePbHHuTPXNmpG";
        let rootPK = "xpub661MyMwAqRbcG1bfmK3xTc7E9i15MfFKiVa5y4d9P8KyX8UfrnYZHHLhCDcZr88kr6FnhhysasSKcn2SaFFV1evmCXGm1Quv3RFyk41TGp8";
        let ki00SK = "xprvA3PYQNrdAdfKaYdYT1qSiEjQA8YgYiGzUny3b3vRmxv9HSS22QnKkz3UyPrhhoj3ZbzVy3u79Rdr3FBtoZcqfwCBaAmyfimRYaZ8kKiLyqK";
        let ki00PK = "xpub6GNtotPX11Dco2i1Z3NT5Ng8iAPAxAzqr1tePSL3LJT8AEmAZx6aJnMxpg5C1tbpiW9c8enmxct794jpv55HVayzGyhFTfit9T9SPn3rwXa";

        let address = "0x4d2851618957E63A1CF40D816773447816C455f4";

        let root = HDKey.fromMnemonic(mnemonic, "", KeySpec.Ethereum);
        console.log(root.serializeBase58());
        console.log(root.serializePublicKeyBase58());
        expect(root.serializeBase58()).toBe(rootSK);
        expect(root.serializePublicKeyBase58()).toBe(rootPK);

        let key = root.deriveWithPath(HDKey.ETHEREUM_ACCOUNT_DERIVATION_PATH_PREFIX + '0');
        console.log(key.serializeBase58());
        console.log(key.serializePublicKeyBase58());
        expect(key.serializeBase58()).toBe(ki00SK);
        expect(key.serializePublicKeyBase58()).toBe(ki00PK);

        console.log(key.getAddress());
        expect(key.getAddress()).toBe(address);
    });

    test('Test Derive Public Only', () => {
        let mnemonic = "pact reject sick voyage foster fence warm luggage cabbage any subject carbon";
        let root = HDKey.fromMnemonic(mnemonic, "helloworld");
        let preDerivedKey = root.deriveWithPath(HDKey.ELASTOS_ACCOUNT_PUBLICKEY_PREDERIVATION_PATH);
        let preDerivedPubBase58 = preDerivedKey.serializePublicKeyBase58();
        let preDerivedPub = HDKey.deserializeBase58(preDerivedPubBase58);

        for (let index = 0; index < 5; index++) {
            let key = root.deriveWithPath(HDKey.ELASTOS_ACCOUNT_DERIVATION_PATH_PREFIX + index);
            let keyPubOnly = preDerivedPub.deriveWithPath("m/0/" + index);

            expect(key.getPublicKeyBase58()).toBe(keyPubOnly.getPublicKeyBase58())
            expect(key.getDidAddress()).toBe(keyPubOnly.getDidAddress())
        }
    });
})