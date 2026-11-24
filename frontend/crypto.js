export const MAX_FILE = 512 * 1024;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const aad = encoder.encode("IncogniFile:v1");

export function to_base64(bytes) {
  let s = "";
  for (const byte of new Uint8Array(bytes)) s += String.fromCharCode(byte);
  return btoa(s);
}

export function from_base64(text) {
  return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
}

export function readTextKey(text) {
  const bytes = from_base64(text.trim());
  if (bytes.length !== 32)
    throw new Error("Klucz musi mieć 32 bajty (Base64).");
  return bytes;
}

export function newKey() {
  return crypto.getRandomValues(new Uint8Array(32));
}

async function prepareKeyForCrypto(raw, usage) {
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, [usage]);
}

export async function encryptData(raw, value) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 },
    await prepareKeyForCrypto(raw, "encrypt"),
    encoder.encode(JSON.stringify(value)),
  );
  return { ciphertext: to_base64(ciphertext), nonce: to_base64(nonce) };
}

export async function decryptData(raw, envelope) {
  if (envelope.ciphertext.length > 1_000_000)
    throw new Error("Za duży szyfrogram.");
  const bytes = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: from_base64(envelope.nonce),
      additionalData: aad,
      tagLength: 128,
    },
    await prepareKeyForCrypto(raw, "decrypt"),
    from_base64(envelope.ciphertext),
  );
  const value = JSON.parse(decoder.decode(bytes));
  if (
    value.v !== 1 ||
    !["note", "file"].includes(value.kind) ||
    typeof value.data !== "string"
  )
    throw new Error("Nieprawidłowy format wiadomości.");
  if (
    value.kind === "file" &&
    (typeof value.name !== "string" ||
      value.name.length > 255 ||
      from_base64(value.data).length > MAX_FILE)
  )
    throw new Error("Nieprawidłowy plik.");
  if (value.kind === "note" && value.data.length > 10000)
    throw new Error("Za długa notatka.");
  return value;
}

async function vaultKey(password, salt, usage) {
  if (password.length < 12 || password.length > 128)
    throw new Error("Hasło chroniące klucz: 12–128 znaków.");
  const material = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 600000, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    [usage],
  );
}

export async function lockKey(raw, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      additionalData: encoder.encode("IncogniFile:vault:1"),
    },
    await vaultKey(password, salt, "encrypt"),
    raw,
  );
  return { v: 1, salt: to_base64(salt), iv: to_base64(iv), data: to_base64(data) };
}

export async function unlockKey(v, password) {
  if (
    v.v !== 1 ||
    typeof v.data !== "string" ||
    v.data.length > 100 ||
    from_base64(v.salt).length !== 16 ||
    from_base64(v.iv).length !== 12
  )
    throw new Error("Nieprawidłowa zapisana kopia klucza.");
  const raw = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: from_base64(v.iv),
      additionalData: encoder.encode("IncogniFile:vault:1"),
    },
    await vaultKey(password, from_base64(v.salt), "decrypt"),
    from_base64(v.data),
  );
  return readTextKey(to_base64(raw));
}
