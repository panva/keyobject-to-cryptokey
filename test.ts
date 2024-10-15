import test from "node:test";
import * as assert from "node:assert/strict";
import * as crypto from "node:crypto";
import * as util from "node:util";
import { convert } from "./index.ts";

const generateKeyPair = util.promisify(crypto.generateKeyPair);

const ed25519 = new Set(["EdDSA", "Ed25519"]);
const ed448 = new Set(["EdDSA", "Ed448"]);
const x25519 = new Set([
  "ECDH-ES",
  "ECDH-ES+A128KW",
  "ECDH-ES+A192KW",
  "ECDH-ES+A256KW",
]);
const x448 = new Set([
  "ECDH-ES",
  "ECDH-ES+A128KW",
  "ECDH-ES+A192KW",
  "ECDH-ES+A256KW",
]);
const rsa = new Set([
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
  "RSA-OAEP",
  "RSA-OAEP-256",
  "RSA-OAEP-384",
  "RSA-OAEP-512",
]);

const p256 = new Set([
  "ES256",
  "ECDH-ES",
  "ECDH-ES+A128KW",
  "ECDH-ES+A192KW",
  "ECDH-ES+A256KW",
]);

const p384 = new Set([
  "ES384",
  "ECDH-ES",
  "ECDH-ES+A128KW",
  "ECDH-ES+A192KW",
  "ECDH-ES+A256KW",
]);

const p521 = new Set([
  "ES512",
  "ECDH-ES",
  "ECDH-ES+A128KW",
  "ECDH-ES+A192KW",
  "ECDH-ES+A256KW",
]);

const secretAnyLength = new Set([
  "HS256",
  "HS384",
  "HS512",
  "PBES2-HS256+A128KW",
  "PBES2-HS384+A192KW",
  "PBES2-HS512+A256KW",
]);

const secret128 = new Set([
  "A128KW",
  "A128GCMKW",
  "A128GCM",
  ...secretAnyLength,
]);

const secret192 = new Set([
  "A192KW",
  "A192GCMKW",
  "A192GCM",
  ...secretAnyLength,
]);

const secret256 = new Set([
  "A256KW",
  "A256GCMKW",
  "A256GCM",
  ...secretAnyLength,
]);

const all = new Set([
  ...ed25519,
  ...ed448,
  ...x25519,
  ...x448,
  ...rsa,
  ...p256,
  ...p384,
  ...p521,
  ...secretAnyLength,
  ...secret128,
  ...secret192,
  ...secret256,
]);

test("ed25519", async () => {
  const k = await generateKeyPair("ed25519");

  for (const alg of all) {
    if (ed25519.has(alg)) {
      assert.doesNotThrow(() => convert(k.privateKey, alg));
      assert.doesNotThrow(() => convert(k.publicKey, alg));
    } else {
      assert.throws(() => convert(k.privateKey, alg));
      assert.throws(() => convert(k.publicKey, alg));
    }
  }
});

test("x25519", async () => {
  const k = await generateKeyPair("x25519");

  for (const alg of all) {
    if (x25519.has(alg)) {
      assert.doesNotThrow(() => convert(k.privateKey, alg));
      assert.doesNotThrow(() => convert(k.publicKey, alg));
    } else {
      assert.throws(() => convert(k.privateKey, alg));
      assert.throws(() => convert(k.publicKey, alg));
    }
  }
});

test("ed448", async () => {
  const k = await generateKeyPair("ed448");

  for (const alg of all) {
    if (ed448.has(alg)) {
      assert.doesNotThrow(() => convert(k.privateKey, alg));
      assert.doesNotThrow(() => convert(k.publicKey, alg));
    } else {
      assert.throws(() => convert(k.privateKey, alg));
      assert.throws(() => convert(k.publicKey, alg));
    }
  }
});

test("x448", async () => {
  const k = await generateKeyPair("x448");

  for (const alg of all) {
    if (x448.has(alg)) {
      assert.doesNotThrow(() => convert(k.privateKey, alg));
      assert.doesNotThrow(() => convert(k.publicKey, alg));
    } else {
      assert.throws(() => convert(k.privateKey, alg));
      assert.throws(() => convert(k.publicKey, alg));
    }
  }
});

test("rsa", async () => {
  const k = await generateKeyPair("rsa", { modulusLength: 2048 });

  for (const alg of all) {
    if (rsa.has(alg)) {
      assert.doesNotThrow(() => convert(k.privateKey, alg));
      assert.doesNotThrow(() => convert(k.publicKey, alg));
    } else {
      assert.throws(() => convert(k.privateKey, alg));
      assert.throws(() => convert(k.publicKey, alg));
    }
  }
});

test("p-256", async () => {
  const k = await generateKeyPair("ec", { namedCurve: "P-256" });

  for (const alg of all) {
    if (p256.has(alg)) {
      assert.doesNotThrow(() => convert(k.privateKey, alg));
      assert.doesNotThrow(() => convert(k.publicKey, alg));
    } else {
      assert.throws(() => convert(k.privateKey, alg));
      assert.throws(() => convert(k.publicKey, alg));
    }
  }
});

test("p-384", async () => {
  const k = await generateKeyPair("ec", { namedCurve: "P-384" });

  for (const alg of all) {
    if (p384.has(alg)) {
      assert.doesNotThrow(() => convert(k.privateKey, alg));
      assert.doesNotThrow(() => convert(k.publicKey, alg));
    } else {
      assert.throws(() => convert(k.privateKey, alg));
      assert.throws(() => convert(k.publicKey, alg));
    }
  }
});

test("p-521", async () => {
  const k = await generateKeyPair("ec", { namedCurve: "P-521" });

  for (const alg of all) {
    if (p521.has(alg)) {
      assert.doesNotThrow(() => convert(k.privateKey, alg));
      assert.doesNotThrow(() => convert(k.publicKey, alg));
    } else {
      assert.throws(() => convert(k.privateKey, alg));
      assert.throws(() => convert(k.publicKey, alg));
    }
  }
});

test("secretAnyLength", async () => {
  const k = crypto.createSecretKey(crypto.randomBytes(20));

  for (const alg of all) {
    if (secretAnyLength.has(alg)) {
      assert.doesNotThrow(() => convert(k, alg));
    } else {
      assert.throws(() => convert(k, alg));
    }
  }
});

test("secret128", async () => {
  const k = crypto.createSecretKey(crypto.randomBytes(128 >> 3));

  for (const alg of all) {
    if (secret128.has(alg)) {
      assert.doesNotThrow(() => convert(k, alg));
    } else {
      assert.throws(() => convert(k, alg));
    }
  }
});

test("secret192", async () => {
  const k = crypto.createSecretKey(crypto.randomBytes(192 >> 3));

  for (const alg of all) {
    if (secret192.has(alg)) {
      assert.doesNotThrow(() => convert(k, alg));
    } else {
      assert.throws(() => convert(k, alg));
    }
  }
});

test("secret256", async () => {
  const k = crypto.createSecretKey(crypto.randomBytes(256 >> 3));

  for (const alg of all) {
    if (secret256.has(alg)) {
      assert.doesNotThrow(() => convert(k, alg));
    } else {
      assert.throws(() => convert(k, alg));
    }
  }
});
