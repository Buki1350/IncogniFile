import { readFile } from "node:fs/promises";
import { join } from "node:path";

// Only the independent test runner reads the local outbox, never the browser/API.
export async function localVerificationToken(userId) {
  const mail = await readFile(
    join(process.env.TEST_MAIL_DIR || ".mail", `${userId}.eml`),
    "utf8",
  );
  const token = mail.match(/#verify=([A-Za-z0-9_-]{43})/)?.[1];
  if (!token)
    throw new Error(
      "Missing local verification link. Use MAIL_DELIVERY=local or disable verification for HTTP attack demos.",
    );
  return token;
}
