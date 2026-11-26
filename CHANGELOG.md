# Changelog

All notable changes to Cipher are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- Decrypted messages now appear in place of the encrypted text, in a green box with a lock,
  with a "Show encrypted text" link per message and a setting to turn it off. Earlier parts
  of a split message collapse to a one-line note.
- Messages that fit in one Discord message no longer carry a `ref` in their header. Older
  messages with one still decrypt; Cipher versions before this one can't read the new
  short header.

### Security

- Cipher locks itself after 15 minutes without keyboard or mouse input (setting), when the
  screen locks and after sleep. Locking (also "Lock now") makes gpg-agent forget the PGP
  key's passphrase.
- Cipher warns when the selected GnuPG key has no passphrase.
- PGP keys and messages are checked in JavaScript before GnuPG parses them: photo IDs,
  extra packets, data after the encrypted packet and compressed data inside are refused.
  Plain-gpg messages need `--compress-algo none`.
- GnuPG now runs with `--no-options`, so `gpg.conf` can't change Cipher's calls.
- Importing a secret key needs a native confirmation and a plain key file; other people's
  disappearing-message links to IP addresses or local-network names are refused; plain-http
  servers need `CIPHER_DEV_HTTP=1`.
- With your own Cipher server set, Cipher never contacts any other server: disappearing
  messages stored elsewhere are shown as a note, not loaded. Messages on your server from
  people who aren't contacts need a click, so strangers can't burn its quota.
- The server refuses plain http.
- PGP messages from people who aren't contacts need a click before GnuPG sees them (closing
  the last zero-click path to GnuPG). age messages still decrypt by themselves.
- Key lookups no longer return exact timestamps; only the day of a key change.
- The installer adds Cipher's dependency with `--ignore-scripts`.
- A small lock next to your contacts' names (in messages, member and DM lists, and profiles):
  green when codes were compared, grey when not yet, red after a key change. Only you see it;
  it comes from your own contact list. Turn it off with "Show contact badges".
- Cipher now comes set to the project's own server. Clear the address to keep everything in
  Discord; "Use the default server" brings it back.
- Server responses carry stricter headers (sandboxed CSP, no framing, same-origin only).
- Cipher server: Discord sign-in tokens are revoked as soon as the user ID is read, sign-in
  attempts are capped per IP, malformed age keys get a clean refusal, RSA keys with a weak
  exponent can't make key proofs, and the GnuPG proof-signing bridge is throttled.
- PGP messages are now read by Cipher's own code first, and only messages addressed to one of
  your keys reach GnuPG, so strangers' messages never get parsed by GnuPG. Hidden-recipient
  messages need a click.
- PGP keys posted by non-contacts are only checked with GnuPG after a click.
- age and PGP messages with more than 32 recipients are refused before any key is tried.
- GnuPG older than 2.2.36 / 2.3.7 (status-line spoofing bugs CVE-2018-12020 and
  CVE-2022-34903) is refused.
- PGP messages that carry a passphrase packet next to a public-key one are now refused.
  Before, GnuPG could fall back to that passphrase and open a prompt chosen by the sender.
- Closing GnuPG's passphrase prompt pauses automatic PGP decryption until you click
  Decrypt, so messages from strangers can't reopen it again and again. Closed prompts can
  now be retried.
- Exporting a PGP secret key needs a confirmation in a native window that scripts in the
  Discord page can't click.
- The chat bar warns when encryption is on and the draft is a slash command, which Discord
  sends unencrypted.
- The contact picker always shows @usernames, since display names can be copied.

### Added

- Post-quantum age keys (ML-KEM-768 + X25519). Normal and post-quantum age keys are never mixed
  in one ciphertext; key shares carry the long post-quantum key in a compact form that fits in
  one Discord message.
- Disappearing messages are posted as a `CIPHER DISAPPEARING MESSAGE` block whose body is a
  base64 reference, so Discord shows no clickable link and fetches no preview.
- Optional Cipher server (Cloudflare Worker in `server/`): public-key directory with Discord
  sign-in plus proof of key possession (a PGP signature or an age challenge) for every key
  change, a 7-day visible waiting period for changes without the old key, and a warning when
  someone requests one; and disappearing messages (1, 3 or 7 days) linked from Discord with a hash so the
  server can't change them. Cipher only auto-loads links from your own server.
- Installer for Windows, macOS and Linux (`install.cmd`, `install.sh`): builds Vencord with
  Cipher from source, checks the Vencord commit and that every dependency matches the
  reviewed version, then optionally installs into Discord. `--deploy` updates an installed
  Vencord in place.
- Release workflow that publishes a zip with the installer.
- "Copy decrypted text" under decrypted messages.
- The reader picker offers "Set up my key" when you have none, and "Add <name>'s key" for
  people in the chat you have no key for.
- Pick a contact from your Discord friends and group DMs instead of typing a user ID.
- Make a recipient group from a Discord group DM, and add everyone in the current DM or
  group DM to the readers in one click.

## [0.1.0] - 2026-11-25

First release. Not independently audited; see `AUDIT.md` for the authors' line-by-line
review of the bundled code.

### Added

- age (X25519) keys stored by Cipher, and PGP through your installed GnuPG (Gpg4win on
  Windows): use a key from your keyring or create a Curve25519 one. Both at once if you
  like. Import and passphrase-protected export for both.
- The age key is sealed with your Cipher passphrase (age scrypt) and unlocked once per
  session. PGP secret keys never leave GnuPG.
- GnuPG is run without a shell from its standard install folder only, encrypts to exactly
  the chosen keys, checks signatures with `gpgv` against your contacts only, caps its
  output, and refuses passphrase-only messages.
- Contact book keyed by Discord user ID with automatic key-type detection and warnings for
  expired, revoked and encryption-incapable PGP keys.
- "Share my key" messages with a "Trust this key" button for other Cipher users.
- Fingerprints, a 30-digit comparison code and verified/unverified marks.
- Loud key-change warnings; a changed key is never used without explicit confirmation.
- Recipient picker in the chat bar: only contacts with keys, nobody but you preselected,
  saved groups, a hard limit of 10 readers including you.
- Modes: off, next message only, keep on in this chat.
- Mixed age/PGP selections: drop one type (showing who is removed) or send two linked
  ciphertexts.
- Chat bar shows the readers and warns about members who see but can't read, and about
  drafts longer than Discord's limit.
- Inline decryption of age and PGP messages with signature and verification badges, and
  clear "not a recipient" / "no key" states.
- Optional PGP signing (on by default) and signature checking.
- Compression, splitting across messages, and attachment fallback for long messages.
- Sends are blocked, never downgraded to plaintext, when encryption is on and something is
  wrong; edits are refused while encryption is on.

[Unreleased]: https://github.com/cipherciphercipher/cipher/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/cipherciphercipher/cipher/releases/tag/v0.1.0
