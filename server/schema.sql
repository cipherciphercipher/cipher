-- Cipher server database (Cloudflare D1). Apply with:
--   npx wrangler d1 execute cipher --remote --file=server/schema.sql

-- Public-key directory. Public by design: anyone can look up a key by Discord user ID.
-- Changing a key needs proof from the key itself (see src/core/keyProof.ts). A change
-- without proof from the old key (the old key was lost) waits in pending_* for 7 days,
-- visible to everyone who looks the key up, and the owner can cancel it meanwhile.
CREATE TABLE IF NOT EXISTS keys (
    user_id             TEXT    NOT NULL,
    type                TEXT    NOT NULL CHECK (type IN ('age', 'pgp')),
    material            TEXT    NOT NULL,
    fingerprint         TEXT    NOT NULL,
    updated_at          INTEGER NOT NULL,
    -- When this account first published a key of this type.
    first_at            INTEGER NOT NULL,
    -- When the fingerprint last changed, and how: 'new' (first key), 'proven'
    -- (the old key approved it) or 'reset' (the old key didn't, after the delay).
    changed_at          INTEGER NOT NULL,
    how                 TEXT    NOT NULL CHECK (how IN ('new', 'proven', 'reset')),
    -- A waiting reset: the new key ('' to remove the key) and when it takes effect.
    pending_material    TEXT,
    pending_fingerprint TEXT,
    pending_at          INTEGER,
    PRIMARY KEY (user_id, type)
);

-- Disappearing messages (when no R2 bucket is bound): ciphertext, expiry, hash of the
-- delete code. Nothing about the sender. Expired rows are deleted by the hourly cron job
-- and never served. Note: D1's point-in-time backups keep deleted rows restorable by the
-- account owner for up to 7 days (free plan).
CREATE TABLE IF NOT EXISTS messages (
    id          TEXT    PRIMARY KEY,
    body        TEXT    NOT NULL,
    expires_at  INTEGER NOT NULL,
    delete_hash TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS messages_expiry ON messages (expires_at);

-- Bytes of stored messages, for the MAX_STORED_MB cap. One row.
CREATE TABLE IF NOT EXISTS stored_bytes (
    k     INTEGER PRIMARY KEY CHECK (k = 1),
    bytes INTEGER NOT NULL
);

-- Daily counters for rate limits. `who` is a keyed hash, not a user ID or IP.
-- Rows from earlier days are deleted by the daily cron job.
CREATE TABLE IF NOT EXISTS usage (
    day   TEXT    NOT NULL,
    who   TEXT    NOT NULL,
    count INTEGER NOT NULL,
    PRIMARY KEY (day, who)
);

-- Uploads per calendar month, for the bill cap (MONTHLY_UPLOAD_LIMIT).
CREATE TABLE IF NOT EXISTS budget (
    month   TEXT    PRIMARY KEY,
    uploads INTEGER NOT NULL
);
