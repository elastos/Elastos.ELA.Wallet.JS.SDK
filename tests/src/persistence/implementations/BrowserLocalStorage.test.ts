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

import "jest-localstorage-mock";
import { BrowserLocalStorage } from "@elastosfoundation/wallet-js-sdk";

const setItem = localStorage.setItem as jest.MockedFunction<
  typeof localStorage.setItem
>;

beforeEach(() => {
  // to fully reset the state between tests, clear the storage
  localStorage.clear();
  // optionally reset individual mocks instead:
  // setItem.mockClear();
});

describe("BrowserLocalStorage Tests", () => {
  test("should save to localStorage", () => {
    const key = "master-wallet-id-0";
    const value = { key };
    const browserStorage = new BrowserLocalStorage(key);
    browserStorage.saveStore(value);
    expect(setItem).toHaveBeenLastCalledWith(key, JSON.stringify(value));
    expect(Object.keys(localStorage.__STORE__).length).toBe(1);
  });

  test("load localStorage", () => {
    const key = "master-wallet-id-1";
    const value = { key };
    const browserStorage = new BrowserLocalStorage(key);
    browserStorage.saveStore(value);
    expect(localStorage.__STORE__[key]).toBe(JSON.stringify(value));
  });

  test("get master wallet IDs", () => {
    const key = "master-wallet-id-2";
    const browserStorage = new BrowserLocalStorage(key);
    const ids = browserStorage.getMasterWalletIDs();
    expect(ids.length).toBe(2);
    expect(ids[0]).toBe("master-wallet-id-0");
    expect(ids[1]).toBe("master-wallet-id-1");
  });
});
