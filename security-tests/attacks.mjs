import { localVerificationToken } from "./local-mail.mjs";
// Run only against a disposable local IncogniFile instance. No third-party modules.
import assert from "node:assert/strict";
import { newKey, encrypt, decrypt } from "../frontend/crypto.js";
const base = new URL(process.argv[2] || "http://127.0.0.1:8080");
if (
  !["127.0.0.1", "localhost", "[::1]"].includes(base.hostname) ||
  base.protocol !== "http:" ||
  base.username ||
  base.password ||
  base.pathname !== "/" ||
  base.search ||
  base.hash
)
  throw new Error("Only a local disposable HTTP instance is permitted.");
const suffix = Date.now().toString(36),
  password = "Demo-only-Strong-password-47";
const alice = `alice_${suffix}@example.com`,
  bob = `bob_${suffix}@example.com`,
  eve = `eve_${suffix}@example.com`;
let failures = 0,
  checks = 0;
function printable(value) {
  const s = JSON.stringify(value, (k, v) =>
    ["token", "password"].includes(k)
      ? "[redacted]"
      : typeof v === "string" && v.length > 160
        ? v.slice(0, 100) + "…"
        : v,
  );
  return s?.slice(0, 600);
}
async function request(
  path,
  { method = "GET", token, body, headers = {} } = {},
) {
  console.log(
    `\n> ${method} ${path} ${token ? "Authorization: Bearer [redacted]" : ""} ${printable(body) || ""}`,
  );
  const r = await fetch(new URL(path, base), {
    method,
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      ...headers,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    redirect: "error",
    signal: AbortSignal.timeout(15000),
  });
  const text = await r.text();
  let value;
  try { value = JSON.parse(text); } catch { value = { message: text }; }
  console.log(`< ${r.status} ${printable(value)}`);
  return { status: r.status, value, headers: r.headers };
}
async function check(name, fn) {
  checks++;
  try {
    await fn();
    console.log(`PASS | ${name}`);
  } catch (e) {
    failures++;
    console.error(`FAIL | ${name}: ${e.message}`);
  }
}
async function account(email) {
  const r = await request("/api/register", {
    method: "POST",
    body: { email, password },
  });
  assert.equal(r.status, 200);
  if (r.value.verification_required) {
    const v = await request("/api/verify-email", {
      method: "POST",
      body: { token: await localVerificationToken(r.value.user_id) },
    });
    assert.equal(v.status, 200);
  }
  const l = await request("/api/login", {
    method: "POST",
    body: { email, password },
  });
  assert.equal(l.status, 200);
  return l.value.token;
}
try {
  const a = await account(alice),
    b = await account(bob),
    e = await account(eve),
    key = newKey();
  const marker =
    "<img src=x onerror=alert('xss')> ' OR 1=1; DROP TABLE users; --";
  const payload = await encrypt(key, { v: 1, kind: "note", data: marker });
  async function make(extra = {}) {
    const r = await request("/api/secrets", {
      method: "POST",
      token: a,
      body: {
        ...payload,
        recipient: bob,
        ttl_seconds: 3600,
        one_time: false,
        ...extra,
      },
    });
    assert.equal(r.status, 200);
    return r.value.id;
  }
  const id = await make();
  await check(
    "No session / forged session / cookie cannot authorize",
    async () => {
      for (const options of [
        {},
        { token: "x".repeat(43) },
        { headers: { Cookie: `session=${a}` } },
      ])
        assert.equal(
          (
            await request(`/api/secrets/${id}/read`, {
              method: "POST",
              ...options,
            })
          ).status,
          401,
        );
    },
  );
  await check("IDOR: stranger cannot list, read or delete", async () => {
    const l = await request("/api/secrets", { token: e });
    assert(!l.value.secrets.some((s) => s.id === id));
    assert.equal(
      (await request(`/api/secrets/${id}/read`, { method: "POST", token: e }))
        .status,
      404,
    );
    assert.equal(
      (await request(`/api/secrets/${id}`, { method: "DELETE", token: e }))
        .status,
      404,
    );
    assert.equal(
      (await request(`/api/secrets/${id}`, { method: "DELETE", token: b }))
        .status,
      404,
    );
  });
  await check(
    "SQL injection rejected; account and protected data remain intact",
    async () => {
      assert.equal(
        (
          await request("/api/login", {
            method: "POST",
            body: { email: "' OR 1=1 --", password },
          })
        ).status,
        400,
      );
      assert.equal(
        (
          await request("/api/secrets", {
            method: "POST",
            token: a,
            body: {
              ...payload,
              recipient: "' OR 1=1 --",
              ttl_seconds: 60,
              one_time: false,
            },
          })
        ).status,
        400,
      );
      assert.equal(
        (
          await request("/api/secrets/1%20OR%201=1/read", {
            method: "POST",
            token: e,
          })
        ).status,
        400,
      );
      const r = await request(`/api/secrets/${id}/read`, {
        method: "POST",
        token: b,
      });
      assert.equal(r.status, 200);
      assert.equal((await decrypt(key, r.value)).data, marker);
    },
  );
  await check(
    "Wrong key and changed ciphertext cannot decrypt (real frontend crypto)",
    async () => {
      const r = await request(`/api/secrets/${id}/read`, {
        method: "POST",
        token: b,
      });
      assert.equal(r.status, 200);
      await assert.rejects(decrypt(newKey(), r.value));
      const bytes = Buffer.from(r.value.ciphertext, "base64");
      bytes[0] ^= 1;
      await assert.rejects(
        decrypt(key, { ...r.value, ciphertext: bytes.toString("base64") }),
      );
    },
  );
  await check(
    "Encrypted file round trip; filename never becomes a server path",
    async () => {
      const bytes = crypto.getRandomValues(new Uint8Array(4096));
      const file = {
        v: 1,
        kind: "file",
        name: "../../payload.html",
        data: Buffer.from(bytes).toString("base64"),
      };
      const envelope = await encrypt(key, file);
      const created = await request("/api/secrets", {
        method: "POST",
        token: a,
        body: { ...envelope, recipient: bob, ttl_seconds: 60, one_time: false },
      });
      assert.equal(created.status, 200);
      const r = await request(`/api/secrets/${created.value.id}/read`, {
        method: "POST",
        token: b,
      });
      assert.equal(r.status, 200);
      assert.deepEqual(await decrypt(key, r.value), file);
    },
  );
  await check(
    "XSS payload survives as data; CSP blocks inline code (browser check separately)",
    async () => {
      const r = await request(`/api/secrets/${id}/read`, {
        method: "POST",
        token: b,
      });
      assert.equal((await decrypt(key, r.value)).data, marker);
      assert.match(
        r.headers.get("content-security-policy"),
        /script-src 'self'/,
      );
      assert(
        !r.headers.get("content-security-policy").includes("unsafe-inline"),
      );
      assert.equal(r.headers.get("x-content-type-options"), "nosniff");
      assert.equal(r.headers.get("cache-control"), "no-store");
    },
  );
  await check(
    "One-time: unauthorized access and listing do not consume; parallel reads have one winner",
    async () => {
      const once = await make({ one_time: true });
      assert.equal(
        (
          await request(`/api/secrets/${once}/read`, {
            method: "POST",
            token: e,
          })
        ).status,
        404,
      );
      const l = await request("/api/secrets", { token: b });
      assert(l.value.secrets.some((s) => s.id === once));
      assert(l.value.secrets.every((s) => !("ciphertext" in s)));
      const results = await Promise.all(
        Array.from({ length: 8 }, () =>
          request(`/api/secrets/${once}/read`, { method: "POST", token: b }),
        ),
      );
      assert.equal(results.filter((r) => r.status === 200).length, 1);
      assert.equal(results.filter((r) => r.status === 404).length, 7);
      assert.equal(
        (
          await request(`/api/secrets/${once}/read`, {
            method: "POST",
            token: a,
          })
        ).status,
        404,
      );
    },
  );
  await check(
    "Malformed/oversized uploads and invalid TTL rejected",
    async () => {
      for (const patch of [
        { nonce: "../../index.html" },
        { ciphertext: "plain text" },
        { ttl_seconds: 0 },
        { ttl_seconds: 604801 },
        { ciphertext: "A".repeat(1_000_001) },
      ]) {
        assert.equal(
          (
            await request("/api/secrets", {
              method: "POST",
              token: a,
              body: {
                ...payload,
                recipient: null,
                ttl_seconds: 60,
                one_time: false,
                ...patch,
              },
            })
          ).status,
          400,
        );
      }
      assert.equal(
        (
          await request("/api/secrets", {
            method: "POST",
            token: a,
            body: {
              ...payload,
              recipient: null,
              ttl_seconds: 60,
              one_time: false,
              ciphertext: "A".repeat(1_100_001),
            },
          })
        ).status,
        413,
      );
    },
  );
  await check(
    "Cross-origin request denied even with a valid token",
    async () => {
      assert.equal(
        (
          await request("/api/secrets", {
            token: a,
            headers: { Origin: "https://attacker.invalid" },
          })
        ).status,
        403,
      );
    },
  );
  await check("Logout revokes bearer token on server", async () => {
    assert.equal(
      (await request("/api/logout", { method: "POST", token: e })).status,
      200,
    );
    assert.equal((await request("/api/secrets", { token: e })).status, 401);
  });
  await check(
    "Brute force: account budget survives spoofed forwarding headers",
    async () => {
      const attempts = [];
      for (let i = 0; i < 6; i++)
        attempts.push(
          (
            await request("/api/login", {
              method: "POST",
              body: { email: alice, password: "Wrong-password-99" },
              headers: {
                "X-Forwarded-For": `192.0.2.${i}`,
                "X-Real-IP": `198.51.100.${i}`,
              },
            })
          ).status,
        );
      assert.deepEqual(attempts, [401, 401, 401, 401, 429, 429]); // initial login reserved one of five slots
      assert.equal(
        (
          await request("/api/login", {
            method: "POST",
            body: { email: alice, password },
          })
        ).status,
        429,
      );
    },
  );
  console.log(
    "\nExpiry: use TTL=60 seconds in the UI or run expiry.mjs; fail-closed: cargo test --test fail_closed.",
  );
} catch (e) {
  failures++;
  console.error(`SETUP FAILED: ${e.stack}`);
}
console.log(
  `\n${checks} scenarios, ${failures} failures. Disposable accounts remain; reset the TEST database when finished.`,
);
process.exitCode = failures ? 1 : 0;
