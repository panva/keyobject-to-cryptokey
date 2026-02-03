import type { KeyObject, webcrypto } from "node:crypto";

const util = globalThis.process?.getBuiltinModule?.("node:util/types");

function isKeyObject(input: unknown): asserts input is ConvertableKeyObject {
  if (util?.isKeyObject?.(input) !== true) {
    throw new TypeError("keyObject must be an instance of KeyObject");
  }
}

interface ConvertableKeyObject extends KeyObject {
  toCryptoKey(
    alg:
      | webcrypto.AlgorithmIdentifier
      | webcrypto.RsaHashedImportParams
      | webcrypto.EcKeyImportParams
      | webcrypto.HmacImportParams
      | webcrypto.AesKeyAlgorithm,
    extractable: boolean,
    usages: string[],
  ): webcrypto.CryptoKey;
}

const nist = new Map<unknown, string>([
  ["prime256v1", "P-256"],
  ["secp384r1", "P-384"],
  ["secp521r1", "P-521"],
]);

export function convert(
  keyObject: KeyObject,
  alg: string,
): webcrypto.CryptoKey {
  isKeyObject(keyObject);

  const type = keyObject.type;
  const asymmetricKeyType = keyObject.asymmetricKeyType as string;

  if (asymmetricKeyType === "x25519" || asymmetricKeyType === "x448") {
    switch (alg) {
      case "ECDH-ES":
      case "ECDH-ES+A128KW":
      case "ECDH-ES+A192KW":
      case "ECDH-ES+A256KW":
        break;

      default:
        throw new TypeError("unsupported algorithm");
    }

    return keyObject.toCryptoKey(
      asymmetricKeyType,
      true,
      type === "private" ? ["deriveBits", "deriveKey"] : [],
    );
  }

  if (asymmetricKeyType === "ed25519" || asymmetricKeyType === "ed448") {
    switch (alg) {
      case "EdDSA":
        break;
      case "Ed25519":
      case "Ed448":
        if (alg.toLowerCase() === asymmetricKeyType) break;

      default:
        throw new TypeError("unsupported algorithm");
    }

    return keyObject.toCryptoKey(asymmetricKeyType, true, [
      type === "private" ? "sign" : "verify",
    ]);
  }

  if (asymmetricKeyType === "rsa") {
    let hash: string;
    switch (alg) {
      case "RSA-OAEP":
        hash = "SHA-1";
        break;
      case "RS256":
      case "PS256":
      case "RSA-OAEP-256":
        hash = "SHA-256";
        break;
      case "RS384":
      case "PS384":
      case "RSA-OAEP-384":
        hash = "SHA-384";
        break;
      case "RS512":
      case "PS512":
      case "RSA-OAEP-512":
        hash = "SHA-512";
        break;

      default:
        throw new TypeError("unsupported algorithm");
    }

    if (alg.startsWith("RSA-OAEP")) {
      return keyObject.toCryptoKey(
        {
          name: "RSA-OAEP",
          hash,
        },
        true,
        type === "private" ? ["decrypt", "unwrapKey"] : ["encrypt", "wrapKey"],
      );
    }

    return keyObject.toCryptoKey(
      {
        name: alg.startsWith("PS") ? "RSA-PSS" : "RSASSA-PKCS1-v1_5",
        hash,
      },
      true,
      [type === "private" ? "sign" : "verify"],
    );
  }

  if (asymmetricKeyType === "ec") {
    const namedCurve = nist.get(keyObject.asymmetricKeyDetails?.namedCurve);
    if (!namedCurve) {
      throw new TypeError("unsupported EC curve");
    }

    if (alg === "ES256" && namedCurve === "P-256") {
      return keyObject.toCryptoKey(
        {
          name: "ECDSA",
          namedCurve,
        },
        true,
        [type === "private" ? "sign" : "verify"],
      );
    }

    if (alg === "ES384" && namedCurve === "P-384") {
      return keyObject.toCryptoKey(
        {
          name: "ECDSA",
          namedCurve,
        },
        true,
        [type === "private" ? "sign" : "verify"],
      );
    }

    if (alg === "ES512" && namedCurve === "P-521") {
      return keyObject.toCryptoKey(
        {
          name: "ECDSA",
          namedCurve,
        },
        true,
        [type === "private" ? "sign" : "verify"],
      );
    }

    if (alg.startsWith("ECDH-ES")) {
      return keyObject.toCryptoKey(
        {
          name: "ECDH",
          namedCurve,
        },
        true,
        type === "private" ? ["deriveBits", "deriveKey"] : [],
      );
    }
  }

  if (
    asymmetricKeyType === "ml-dsa-44" ||
    asymmetricKeyType === "ml-dsa-65" ||
    asymmetricKeyType === "ml-dsa-87"
  ) {
    if (alg === asymmetricKeyType.toUpperCase()) {
      return keyObject.toCryptoKey({ name: alg }, true, [
        type === "private" ? "sign" : "verify",
      ]);
    }

    throw new TypeError("unsupported algorithm");
  }

  if (type === "secret") {
    switch (alg) {
      case "HS256":
      case "HS384":
      case "HS512":
      case "PBES2-HS256+A128KW":
      case "PBES2-HS384+A192KW":
      case "PBES2-HS512+A256KW":
      case "A128KW":
      case "A128GCMKW":
      case "A128GCM":
      case "A192KW":
      case "A192GCMKW":
      case "A192GCM":
      case "A256KW":
      case "A256GCMKW":
      case "A256GCM":
        break;
      default:
        throw new TypeError("unsupported algorithm");
    }

    if (alg.startsWith("HS")) {
      return keyObject.toCryptoKey(
        {
          name: "HMAC",
          hash: `SHA-${alg.slice(-3)}`,
        },
        true,
        ["sign", "verify"],
      );
    }

    if (alg.startsWith("A")) {
      const length = parseInt(alg.slice(1, 4), 10);
      if (keyObject.symmetricKeySize === length >> 3) {
        return keyObject.toCryptoKey(
          {
            name: alg.includes("GCM") ? "AES-GCM" : "AES-KW",
          },
          true,
          alg.includes("GCM")
            ? ["encrypt", "decrypt"]
            : ["wrapKey", "unwrapKey"],
        );
      }
    }

    if (alg.startsWith("PBES2")) {
      return keyObject.toCryptoKey(
        {
          name: "PBKDF2",
        },
        false,
        ["deriveBits", "deriveKey"],
      );
    }
  }

  throw new TypeError("unsupported key type");
}
