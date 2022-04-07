import "jest-localstorage-mock";
// import {} from "@elastosfoundation/wallet-js-sdk";

const setItem = localStorage.setItem as jest.MockedFunction<
  typeof localStorage.setItem
>;

beforeEach(() => {
  // to fully reset the state between tests, clear the storage
  localStorage.clear();

  // optionally reset individual mocks instead:
  setItem.mockClear();
  setItem("foo", "bar");
});

test("should save to localStorage", () => {
  const KEY = "foo";
  const VALUE = "bar";

  // const browserStorage = new BrowserLocalStorage();

  expect(setItem).toHaveBeenLastCalledWith(KEY, VALUE);
  expect(localStorage.__STORE__[KEY]).toBe(VALUE);
  expect(Object.keys(localStorage.__STORE__).length).toBe(1);
});
