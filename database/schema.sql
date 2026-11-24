CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 email TEXT NOT NULL UNIQUE CHECK(length(email) BETWEEN 3 AND 254),
 password_hash TEXT NOT NULL,
 email_verified INTEGER NOT NULL DEFAULT 0 CHECK(email_verified IN (0,1))
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY NOT NULL,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS secrets (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 recipient_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
 ciphertext TEXT NOT NULL,
 nonce TEXT NOT NULL,
 expires_at INTEGER NOT NULL,
 one_time INTEGER NOT NULL DEFAULT 0 CHECK(one_time IN (0,1)),
 consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN (0,1)),
 created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS secrets_owner ON secrets(owner_id);
CREATE INDEX IF NOT EXISTS secrets_recipient ON secrets(recipient_id);
CREATE INDEX IF NOT EXISTS secrets_expiry ON secrets(expires_at);
CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
CREATE TABLE IF NOT EXISTS email_verifications (
 token_hash TEXT PRIMARY KEY NOT NULL,
 user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
 expires_at INTEGER NOT NULL
);
