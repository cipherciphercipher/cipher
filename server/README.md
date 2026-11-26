# Cipher server

An optional Cloudflare Worker that gives Cipher users:

- **a public-key directory**: people publish their age and/or PGP public key under their
  Discord account (proved by signing in with Discord), and others look it up in one click;
- **disappearing messages**: the encrypted text is kept for 1, 3 or 7 days and then deleted.
  Discord only carries a short encoded reference to it (no clickable link, no preview).

The server never sees plaintext or private keys. Cipher encrypts and decrypts on each
user's computer.

## What it stores

| Where | What | For how long |
|---|---|---|
| D1 `keys` | Discord user ID, public key, fingerprint, when it was first published and last changed (and how), a waiting change if any | until the user removes it |
| D1 `messages` (or R2, if you bind a bucket) | the encrypted message under a random ID, its expiry time, a hash of its delete code | 1, 3 or 7 days, deleted by the hourly job |
| D1 `usage` | daily counters per **keyed hash** of the user ID (and IP, if the limiter is on) | deleted the next day |
| D1 `budget` | number of uploads per month | about two months |

The server only answers over https (plain http gets a 403, not a redirect, so a misconfigured
client can't send a token in the clear). No sender, recipients, channel or IP is stored with a message. There are no sessions: sign-in
tokens are signed with `SECRET` and checked on each request. Logging is off.

A full breach shows which Discord accounts published which public keys (public anyway) and
a few days of encrypted messages with no names attached.

D1 keeps its own point-in-time backups ("Time Travel", 7 days on the free plan, 30 on paid), so
whoever controls the Cloudflare account can restore a removed key, or a deleted message, for
that long. If that matters to you, keep messages in R2 instead (no backups; needs a payment
method on the account): see step 3.

## What it accepts

- **Messages**: 32 KB at most, and only a real age or OpenPGP encrypted message: 1–10
  readers, no passphrase, nothing before or after the armor, nothing after the encrypted data.
  Plain text, signed-only messages, stored files and anything else are refused, so the server
  can't be used for file hosting.
- **Keys**: one age public key, or one OpenPGP public key made only of key, subkey, user ID and
  signature packets (32 KB at most).
- **Sign-in**: Discord accounts at least 2 days old (`MIN_ACCOUNT_AGE_DAYS`), not bots.
- **Key changes need proof from the key**: a PGP signature by the key's primary key (Ed25519,
  ECDSA P-256/384/521 or RSA 2048+), or for age a decrypted challenge. Tickets are stateless
  (HMAC with `SECRET`) and valid for 10 minutes. Replacing or removing a key without proof
  from the published one waits 7 days, shown to everyone who looks it up; proof from the
  published key cancels it. The daily cron job applies due changes.
- **Limits**: 300 uploads per account per day (`USER_DAILY_UPLOADS`), 40 key operations
  (challenges, publishes, removals) per day,
  120 requests per minute per IP (the `LIMITER` binding), and a monthly cap on uploads
  (`MONTHLY_UPLOAD_LIMIT`). Past the monthly cap, uploads are refused and Cipher offers to send
  a normal message instead.

## Cost

**Free plan (the default setup):** messages are kept in D1, so the account needs no payment
method and Cloudflare can't charge anything. Past the free limits requests simply fail, and
Cipher offers to send a normal message instead. The limits that matter: 100,000 Worker
requests a day, about 100,000 D1 row writes a day (each upload writes about 5, so roughly
20,000 uploads a day), and 500 MB per database (`MAX_STORED_MB = 400` keeps room for the key
directory).

**With R2 (paid usage possible):**
At 2,000 active users sending 30 messages a day each (about 1.8 million uploads a month): the
$5 Workers plan plus roughly $3–4 of R2 writes. Storage stays around 1 GB because everything
expires. Raise `MONTHLY_UPLOAD_LIMIT` (900000 by default, inside R2's free million writes) to
allow more; at 2000000 R2 writes stay near $4.50/month at most. Check
Cloudflare's current [Workers](https://developers.cloudflare.com/workers/platform/pricing/)
and [R2](https://developers.cloudflare.com/r2/pricing/) pricing before relying on these
numbers. Cloudflare has no spending cap of its own; also set a billing notification.

## Setting it up

You need a Cloudflare account (the free plan is enough) and a Discord account. Wrangler is Cloudflare's official command-line tool.

1. **Discord application.** At <https://discord.com/developers/applications>, create an
   application. Under *OAuth2*: copy the **Client ID** and **Client Secret**, and add the
   redirect `https://<your worker address>/v1/auth/callback`. No bot is needed.
2. **Database.** `npx wrangler d1 create cipher`. Put the printed `database_id` into
   `wrangler.toml`, then create the tables:
   `npx wrangler d1 execute cipher --remote --file=schema.sql`
3. **Message storage (optional).** Messages go into the D1 database by default, so you can
   skip this. To keep them in R2 instead, create the bucket (R2 needs a payment method),
   uncomment `[[r2_buckets]]` in `wrangler.toml`, and add the auto-delete rules (one per
   lifetime):
   `npx wrangler r2 bucket create cipher-messages`, then

   ```sh
   npx wrangler r2 bucket lifecycle add cipher-messages expire-1d m/1d/ --expire-days 1
   npx wrangler r2 bucket lifecycle add cipher-messages expire-3d m/3d/ --expire-days 3
   npx wrangler r2 bucket lifecycle add cipher-messages expire-7d m/7d/ --expire-days 7
   ```

   R2 deletes within about a day after that. With either storage, the server never serves a
   message past its expiry and deletes it when asked for it late.
4. **Settings.** In `wrangler.toml` set `PUBLIC_URL` (your Worker's address, no trailing
   slash; exactly the address people enter in Cipher, since PGP key proofs sign it) and
   `DISCORD_CLIENT_ID`. Then set the secrets:

   ```sh
   npx wrangler secret put SECRET                 # a long random string, 32+ characters
   npx wrangler secret put DISCORD_CLIENT_SECRET
   ```

   Generate `SECRET` with e.g. `node -e "console.log(crypto.randomBytes(32).toString('base64url'))"`.
   Changing it later signs everyone out.
5. **Deploy.** `npx wrangler deploy` (from this `server/` folder). Check
   `https://<your worker address>/v1/health` answers `{"ok":true}`.
6. **In Cipher**: Settings → Plugins → Cipher → Keys & contacts → *Cipher server*: enter the
   address, *Save*, *Sign in with Discord*, then *Publish* your keys.

## Tests

The server's tests run with the rest of Cipher's (`pnpm test`): they run the Worker's request
handler in Node against a real SQLite database and an in-memory R2, including forged tokens,
smuggled files, oversized bodies, expired messages and quota abuse.
