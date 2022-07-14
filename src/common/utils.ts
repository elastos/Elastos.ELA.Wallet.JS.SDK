// reverse a hash's byte order
export function reverseHashString(hash: string) {
  let hashStr = hash.match(/[a-fA-F0-9]{2}/g);
  let reversedStr = "";
  if (hashStr) {
    reversedStr = hashStr.reverse().join("");
  }
  return reversedStr;
}
