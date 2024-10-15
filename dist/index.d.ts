import type { KeyObject, webcrypto } from "node:crypto";
export declare function convert(
  keyObject: KeyObject,
  alg: string,
): webcrypto.CryptoKey;
