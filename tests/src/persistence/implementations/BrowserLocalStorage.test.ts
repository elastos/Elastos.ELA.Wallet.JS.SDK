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

describe("HDKey Tests", () => {
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
