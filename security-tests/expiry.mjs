import { localVerificationToken } from "./local-mail.mjs";
import assert from "node:assert/strict";
import { newKey, encrypt } from "../frontend/crypto.js";
const base = new URL(process.argv[2] || "http://127.0.0.1:8080");
if (
  !["127.0.0.1", "localhost", "[::1]"].includes(base.hostname) ||
  base.protocol !== "http:" ||
  base.pathname !== "/"
)
  throw new Error("Local test instance required");
let token;
async function api(path, method, body) {
  console.log(
    ">",
    method,
    path,
    body
      ? JSON.stringify(body, (k, v) =>
          ["password", "token"].includes(k) ? "[redacted]" : v,
        )
      : "",
  );
  const r = await fetch(new URL(path, base), {
    method,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
    redirect: "error",
    signal: AbortSignal.timeout(15000),
  });
  const v = await r.json();
  console.log(
    "<",
    r.status,
    JSON.stringify(v, (k, v) => (k === "token" ? "[redacted]" : v)),
  );
  return { r, v };
}
const email = `expiry_${Date.now().toString(36)}@example.com`,
  password = "Demo-expiry-password-42";
const registration = await api("/api/register", "POST", { email, password });
assert.equal(registration.r.status, 200);
if (registration.v.verification_required)
  assert.equal(
    (
      await api("/api/verify-email", "POST", {
        token: await localVerificationToken(registration.v.user_id),
      })
    ).r.status,
    200,
  );
token = (await api("/api/login", "POST", { email, password })).v.token;
const { v } = await api("/api/secrets", "POST", {
  ...(await encrypt(newKey(), { v: 1, kind: "note", data: "expires" })),
  recipient: null,
  ttl_seconds: 60,
  one_time: false,
});
assert(v.id);
assert.equal((await api(`/api/secrets/${v.id}/read`, "POST")).r.status, 200);
console.log("Waiting 62 seconds for server-side expiry...");
await new Promise((r) => setTimeout(r, 62000));
assert.equal((await api(`/api/secrets/${v.id}/read`, "POST")).r.status, 404);
assert(
  !(await api("/api/secrets", "GET")).v.secrets.some((s) => s.id === v.id),
);
console.log("PASS | Expired secret cannot be read or listed");
