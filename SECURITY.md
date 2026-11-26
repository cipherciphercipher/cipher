# Security

Cipher has **not** been independently audited. This document describes what it tries to
protect, how, and where the limits are, so you can decide whether it fits your situation.

## Reporting a vulnerability

Please report security problems privately through GitHub's
**Security → Report a vulnerability** form on this repository (private security
advisories). Don't open a public issue for anything that could put users at risk.

Include what you found, how to reproduce it, and which version or commit you tested.
We aim to acknowledge reports within 7 days and to agree a disclosure date with you,
normally after a fix is released. There's no bug bounty.

Only the latest release is supported with security fixes.

## Threat model

### What Cipher protects

The **content** of a message you send while encryption is on, against:

- Discord (the company, its servers, its staff, anyone who obtains its data);
- people in the channel who aren't among the readers you picked;
- anyone who later gets Discord's copy of the channel (leaks, exports, subpoenas),
  as long as none of the readers' private keys leak.

Your **age private key at rest**, against someone who copies Discord's local data while
Cipher is locked: it's sealed with your Cipher passphrase (age's scrypt passphrase mode).
Your **PGP private key** is never stored by Cipher at all: it stays in GnuPG, protected by
GnuPG's own passphrase.

**Key substitution after first contact**: once you trust someone's key, a different key
posted under their account is flagged loudly and never used until you confirm it.

**A taken-over Discord account** (stolen password or token): the attacker sees your chats
as ciphertext only, since your private keys aren't in your Discord account. They can post a
fake key share, which your contacts see as a key change (above). On a Cipher server they
can't replace your published key either: changing it needs proof from the key itself (see
"The Cipher server" below).

**Someone at your computer while you're away**: Cipher locks itself after a set time
without keyboard or mouse input (15 minutes by default), when the screen locks, and after
sleep. Locking forgets the unsealed age key, clears decrypted text from memory, and makes
gpg-agent forget your PGP key's passphrase. Cipher also warns if your GnuPG key has no
passphrase, because then GnuPG can decrypt without asking, locked or not.

### What Cipher does not protect

- **Metadata.** Discord sees who posted each message, in which channel, when, its size, and
  which messages are Cipher messages. Message length leaks approximate plaintext length
  (there's no padding), and long messages are compressed before encryption, which can leak
  a little about their content to someone who can also inject text into them.
- **Ciphertext visibility.** Everyone with access to the channel sees the ciphertext. In PGP
  messages the recipients' key IDs are visible too, so anyone holding the matching public
  keys can tell who the readers are. age hides recipients.
- **A compromised device.** Malware, a malicious or buggy Vencord plugin, a malicious Discord
  update, or someone using your unlocked computer can read plaintext as you type it and read
  your keys while Cipher is unlocked. Cipher runs inside the Discord client and can't defend
  against the client itself.
- **Recipients.** Anyone you let read a message can copy, screenshot or forward it.
- **Revocation.** Removing a reader or a contact only affects future messages. Old
  ciphertext stays on Discord and stays readable by everyone it was encrypted to.
- **Forward secrecy.** Neither age nor OpenPGP offers it. If a private key leaks, all past
  messages encrypted to it can be decrypted from Discord's stored copy. Rotate keys if you
  suspect a leak, and delete messages you no longer need.
- **Sender authenticity for age.** age has no signatures. An age message proves only that
  it was encrypted to you, not who wrote it. The badge shows which Discord account posted
  it, which is only as trustworthy as that account. Use PGP with signing if authorship
  matters.
- **First contact (trust on first use).** The first key you trust for someone is only as
  good as your verification. Compare the comparison code out of band before marking a key
  as verified.
- **Discord's Terms of Service.** Client mods violate them. Using Cipher can get your
  account actioned.

### Things to know about the plaintext

- What you type is ordinary text inside Discord until you press Enter. **Discord saves
  unsent drafts locally**, and other plugins can read the text box and modify messages
  before or after Cipher does.
- **Slash commands are never encrypted.** Discord runs them without passing their text to
  Cipher. While encryption is on and the draft starts with `/`, the chat bar lock opens and
  turns red with "commands aren't encrypted".
- If a message is **longer than Discord's limit**, Discord may offer to upload it as a
  file before Cipher sees it. That file is **not encrypted**. The chat bar turns red with
  "too long" while an encrypted draft is over the limit.
- Attachments and stickers are never encrypted. With encryption on, Cipher blocks messages
  that have them instead of sending them.
- Decrypted text is kept in memory only, for display, and cleared when Cipher locks, the
  account changes or the plugin stops. It's never written into Discord's message store,
  so Discord's own caches only ever hold ciphertext. Showing it "in place of" the
  ciphertext is done by hiding the ciphertext element with CSS and drawing the decrypted
  text next to it; the message itself isn't changed. Reply previews, search results and
  notifications still show the ciphertext.
- The friend and group DM lists in the contact and group dialogs come from what the
  Discord client already has loaded. Cipher makes no requests for them and doesn't store
  them; only the contacts and groups you save are kept.
- Cipher never logs plaintext, keys or ciphertext. User-facing errors come from a fixed
  list of messages; library error text is discarded.

## Cryptography

| | age | OpenPGP |
|---|---|---|
| Implementation | `age-encryption` 0.3.1 (typage, by the age authors), bundled | your installed GnuPG (2.2.36+, 2.3.7+ or 2.4+; `gpg` and `gpgv`), not bundled |
| Keys | native X25519 (`age1…`), or post-quantum hybrid ML-KEM-768 + X25519 (`age1pq1…`) | created by Cipher: Ed25519 + Cv25519 (`future-default`). Existing GnuPG keys may be RSA/ECC |
| Message encryption | age v1 (X25519 or ML-KEM-768 + X25519, then ChaCha20-Poly1305) | whatever GnuPG picks from the readers' key preferences (typically AES-256), one PKESK per reader |
| Signatures | none | optional, on by default |
| Armor | age armor | OpenPGP armor |

- **Vault.** Your age private key is encrypted with age's passphrase mode (scrypt, work
  factor 2^18). The public key is stored in the clear so Cipher can show its fingerprint
  and share it while locked. On unlock, Cipher checks that the sealed private key matches
  the stored public key. Passphrases must be at least 8 characters; longer is much
  better, since the vault can be attacked offline if someone copies it. For PGP, Cipher
  stores only which GnuPG key you picked and its public key.
- **Storage.** Everything lives in Vencord's DataStore (IndexedDB inside Discord's
  profile), separately per Discord account. Contacts, groups and per-chat reader lists are
  **not** encrypted: someone with your disk can see whose keys you have and who you encrypt
  to in which chat.
- **Exports** are always passphrase protected: age keys as an age passphrase file
  (`age -d` can open it), PGP keys as exported by GnuPG, still protected by the key's
  GnuPG passphrase.
- **Post-quantum age keys.** A message is only post-quantum if *every* key in it is. One normal
  X25519 key would let a future quantum computer recover the message key, so Cipher never puts
  a normal age key into a ciphertext that has post-quantum readers: those readers get a
  separate copy, and a sender whose own key is normal is left out of that copy (with a
  warning). A post-quantum key in a normal message is harmless and allowed. PGP stays
  classic: GnuPG's post-quantum support needs GnuPG 2.5, uses its own key format that other
  OpenPGP software can't read, and covers encryption only.
- **Comparison code.** 96 bits of SHA-256 over the key type and fingerprint, shown as six
  5-digit groups. Both sides compute it from the key alone, so they see the same code.
- **Inner payload.** `0xC1 'C' 'P' 0x01`, a flags byte (bit 0 = deflate-raw), then the
  UTF-8 text. Decompression is capped at 256 KiB. Payloads without the magic are treated as
  plain UTF-8 so hand-made `age`/`gpg` messages work.
- **Message parts** are linked by a random reference. Reassembly only uses parts posted by
  the same Discord account, and conflicting parts are rejected. Splitting is integrity
  neutral: age and OpenPGP authenticate the whole ciphertext.

## PGP through GnuPG

PGP is done by your own GnuPG, run from Discord's main process (`src/native.ts`, which
uses `src/core/gpg.ts`). The Discord window can only ask for a fixed list of operations
through Vencord's plugin IPC, and only from Discord's own top-level page (not from
iframes such as embedded activities). Every argument is type- and size-checked there.

- GnuPG is run directly, with an argument list and no shell, and only from its standard
  install folder (`C:\Program Files (x86)\GnuPG\bin` for Gpg4win, `/usr/bin`, Homebrew,
  GPG Suite). `PATH` is never searched, so another program called `gpg` can't stand in
  for it.
- Plaintext only goes through stdin/stdout pipes, never into files. Temp files hold only
  public keys, in a private folder that's deleted right after use.
- Messages are encrypted to exactly the keys Cipher passes (`--recipient-file`), and
  `--no-encrypt-to` stops `gpg.conf` from adding readers. Contacts' keys are never imported
  into your keyring. GnuPG never contacts a keyserver.
- Signatures are checked with `gpgv` against a keyring made only of your contacts' keys
  and your own, with an empty GnuPG home of its own, so your keyring and trust settings
  don't change the result. The badge only says "signed by X" when the signing key belongs
  to the account that posted the message.
- GnuPG's output is capped (decrypted text at 256 KiB, everything else at a few MiB) and
  the process is killed beyond that, so a compressed "bomb" can't exhaust memory.
- Messages with any passphrase packet are refused before GnuPG decrypts them, so a message
  in chat can never make GnuPG pop up a passphrase prompt chosen by its sender. That covers
  passphrase-only messages and also mixed ones: GnuPG falls back to a message's passphrase
  when its public-key part doesn't work. Cipher reads the packet list itself to check.
- Anyone with your public key can post PGP messages to you, and decrypting one may open
  GnuPG's passphrase prompt. If you close that prompt, Cipher stops decrypting PGP messages
  on its own until you click **Decrypt** on one.
- Exporting a PGP secret key needs a click in a window opened by Discord's main process.
  Scripts in the Discord page (another plugin, say) can call Cipher's GnuPG bridge but
  can't answer that window, so they can't take a copy of your secret key silently.
- **GnuPG remembers passphrases on its own.** After you type your PGP key's passphrase,
  gpg-agent caches it for a while (by default 10 minutes, renewed on use; configurable in
  Kleopatra or `gpg-agent.conf`). Locking Cipher doesn't clear that cache. To clear it
  now, run `gpgconf --reload gpg-agent`.
- In Discord in a browser there's no main process, so PGP isn't available there.

## Bundled code and its review

Cipher bundles exactly one runtime dependency, `age-encryption` 0.3.1, which pulls in
`@noble/ciphers`, `@noble/curves`, `@noble/hashes`, `@noble/post-quantum` and
`@scure/base`. Every file of those packages was read line by line for malware and
tampering. Cipher's own code was read the same way. [AUDIT.md](AUDIT.md) records the
method and the results. This is the authors' own review, not an independent audit.
`@noble/post-quantum` provides ML-KEM-768 for post-quantum age keys; its own README says it
hasn't been independently audited.

The test suite also checks the bundled cryptography against official test vectors,
against Node's OpenSSL on random inputs, and against an independent age implementation
written in the tests.

## Messages from other people

Anything in a channel you're viewing is read automatically, so Cipher keeps that path narrow:

- PGP messages are first read by Cipher's own JavaScript (`src/core/pgpPackets.ts`) to see
  which keys they're for. Only messages addressed to one of your keys are handed to GnuPG, so a
  stranger's message never reaches GnuPG's C code. Messages that hide their recipients need a
  click ("Try to decrypt").
- A PGP key posted by someone who isn't a contact is only handed to GnuPG when you click
  "Check key". age keys are checked in JavaScript. Contacts' keys are checked at once, so a key
  change is noticed.
- age messages with more than 32 recipient stanzas, and PGP messages with more than 32
  session-key packets, are refused before any key is tried.
- PGP messages with any passphrase packet are refused before GnuPG decrypts them (see below).
- Disappearing messages are only downloaded automatically from *your* Cipher server. A link to
  any other server needs a click, because loading it tells that server your IP address, and
  is refused outright if it points at an IP address, localhost or a local-network name, so a
  message can't make Cipher send requests to your router or other devices.
- Discord's main process only talks to https servers; plain http (localhost, for developing a
  server) needs the `CIPHER_DEV_HTTP=1` environment variable, so nothing in the page can use it
  to reach services on your computer.
- Importing a PGP secret key into GnuPG needs a click in a native window (like exporting one),
  and the file must be a plain secret key (no photo IDs) before GnuPG reads it.
- Decrypted text is rendered by Discord's own message formatter, without images or embeds.
- Every PGP key and message is checked by Cipher's JavaScript before GnuPG sees it, and only
  the exact shapes Cipher makes get through (`src/core/pgpPackets.ts`): a key is one primary
  key with subkeys, user IDs and signatures, with no photo IDs (GnuPG can hand those to an
  external viewer program); a message is session-key packets plus one encrypted packet, with
  nothing after it; after decryption, the inside must be literal data with at most one
  signature, and **never compressed**, so GnuPG's decompressors never see sender data.
  Cipher never compresses PGP data itself; it compresses plaintext in JavaScript.
- GnuPG runs with `--no-options`, so nothing in your `gpg.conf` (photo viewers, keyservers,
  auto-key-retrieve, exec paths) can change what Cipher's calls do. Your keyring and
  gpg-agent are still used.

## The Cipher server (optional)

A Cipher server ([server/README.md](server/README.md)) holds a public-key directory and
disappearing messages (1, 3 or 7 days). It never gets plaintext or private keys.

What a server operator (or anyone who breaks into the server) can do:

- **See metadata of uploads and reads**: which Discord account uploads (from its sign-in token),
  from which IP, when, and how big each message is; which IP downloads which message, and
  when. The reference server stores none of this and keeps no logs, but you're trusting the
  operator to run it unmodified. Cloudflare sees the traffic too.
- **Withhold or delete messages early**, or refuse service.
- **Hand out a wrong public key** from the directory. A key from the server is only as
  trustworthy as the server: Cipher treats it like a pasted key (you click Trust, it starts
  unverified, you compare codes), and the usual loud warning appears if it differs from a key
  you already trust.

Publishing, replacing and removing a key in the directory needs **proof that you hold its
private key**, on top of the Discord sign-in (`src/core/keyProof.ts`):

- PGP: GnuPG signs a fixed statement (server, Discord account, key fingerprint, a one-time
  ticket) with the key's primary key. The server checks the signature itself
  (`server/src/pgpVerify.ts`, WebCrypto: Ed25519, ECDSA P-256/384/521, RSA 2048+). Cipher's
  bridge to GnuPG refuses to sign any other text, so it can't be used to sign things with
  your key.
- age (no signatures): the server encrypts a random code to the key, and Cipher sends it back.
  Cipher only answers if the decrypted text is exactly a challenge for that ticket, so a
  server can't use this to get other messages decrypted.
- Replacing a key needs proof from the new key *and* the old one. Without the old one (you
  lost it), the change waits 7 days. Meanwhile the old key stays, everyone who looks you up
  sees the waiting change, Cipher warns you when it starts, and the old key can cancel it.
  For 30 days after such a reset, lookups warn that the key changed without the old key's
  approval.

So someone with your Discord account alone can't swap your published key for theirs. If you
never published a key, they can publish one under your account (first use is trusted); that's
why lookups still need the comparison code.

What it can't do:

- Run code on your computer. Cipher never runs anything it receives: server answers are
  fetched by Discord's main process from a fixed list of addresses (64 KB cap, no
  redirects), parsed as JSON and checked field by field, and server error text is never
  shown, only fixed messages. Ciphertext from the server goes through the same checks as
  anything posted in chat (above). Cipher's auto-update is off, so no server can push code.
- Read messages: it only has ciphertext.
- Change a message: the Discord message carries the SHA-256 of each ciphertext, and Cipher
  refuses anything that doesn't match. So it can't swap a message for another one encrypted to
  the same people either, which matters for unsigned age messages.
- Make Cipher contact other hosts: Cipher's main-process bridge only allows the server's fixed
  requests (`src/core/serverApi.ts`), with no redirects, a size cap and a timeout.

Deletion is as good as the server: the reference server deletes on expiry (hourly), but
anyone who downloaded the ciphertext before then (a reader, the operator) can keep it. With the
default D1 storage, D1's own backups also let the account owner restore deleted messages for
up to 7 days (R2 storage has no such backups), and neither age
nor PGP has forward secrecy. Disappearing messages limit how long the ciphertext is
*available*; they don't make a leaked private key harmless for messages someone already saved.

If the server is unreachable or full, Cipher asks before sending a normal (permanent) message
instead; it never falls back by itself.

## Hardening in the code

- The send hook catches every error and cancels the send, because Vencord would otherwise
  send the original (plaintext) message when a listener throws.
- A plan never drops a reader: missing, expired, revoked or incompatible keys fail the send
  with an explanation. The 10-reader cap counts people, not ciphertexts.
- The installer only builds if every runtime package npm delivers has the integrity hash of
  the reviewed version (`scripts/audited-deps.json`), and only from the expected Vencord
  commit.
- Dependencies are pinned to exact versions and the lockfile is committed. The repository
  refuses packages published in the last 7 days and runs no install scripts.
- Attachments are only downloaded from Discord's own CDN, without cookies.
