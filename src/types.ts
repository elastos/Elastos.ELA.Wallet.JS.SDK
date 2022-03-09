import BigNumber from "bignumber.js";

// TODO: this file is mostly a temporary file, clean it up, split.

export const UINT16_MAX = 0xffff;
export const UINT32_MAX = 0xffffffff;
export const INT32_MAX = 2147483647;

export type uint8_t = number;
export type uint16_t = number;
export type uint32_t = number;
export type uint64_t = BigNumber;
export type uint256 = BigNumber;
export type size_t = number;
export type bytes_t = Buffer;
export type time_t = number;
export type uchar_vector = bytes_t;

/**
 * Core type that represents a JSON object.
 */
export interface JSONObject {
  [x: string]: JSONValue;
}

export type JSONValue = string | number | boolean | JSONObject | JSONArray;

export interface JSONArray extends Array<string | number | boolean | JSONObject | JSONArray> { }
export type json = JSONObject;

export const sizeof_uint8_t = () => 1;