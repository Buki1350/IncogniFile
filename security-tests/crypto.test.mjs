import test from "node:test";
import assert from "node:assert/strict";
import {
  newKey,
  encrypt,
  decrypt,
  lockKey,
  unlockKey,
  base64,
  unbase64,
} from "../frontend/crypto.js";

test("AES-GCM: round trip, random IV, wrong key and tampering", async () => {
  const key = newKey();
  const note = {
    v: 1,
    kind: "note",
    data: "<img src=x onerror=alert(1)>\u0000Zażółć",
  };
  const a = await encrypt(key, note),
    b = await encrypt(key, note);
  assert.notEqual(a.nonce, b.nonce);
  assert.deepEqual(await decrypt(key, a), note);
  await assert.rejects(decrypt(newKey(), a));
  const bytes = unbase64(a.ciphertext);
  bytes[0] ^= 1;
  await assert.rejects(decrypt(key, { ...a, ciphertext: base64(bytes) }));
  await assert.rejects(decrypt(key, { ...a, nonce: b.nonce }));
});
test("file remains byte-exact, including hostile name", async () => {
  const key = newKey(),
    bytes = crypto.getRandomValues(new Uint8Array(4096));
  const file = {
    v: 1,
    kind: "file",
    name: "../../<script>.html",
    data: base64(bytes),
  };
  assert.deepEqual(await decrypt(key, await encrypt(key, file)), file);
});
test("local vault: unlock, wrong password, tampering, distinct salts", async () => {
  const key = newKey(),
    password = "Separate-long-vault-password";
  const v = await lockKey(key, password),
    b = await lockKey(key, password);
  assert.notEqual(v.salt, b.salt);
  assert.notEqual(v.data, base64(key));
  assert.deepEqual(await unlockKey(v, password), key);
  await assert.rejects(unlockKey(v, "Different-long-password"));
  const bytes = unbase64(v.data);
  bytes[0] ^= 1;
  await assert.rejects(unlockKey({ ...v, data: base64(bytes) }, password));
});
