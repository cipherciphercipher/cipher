# Cipher

End-to-end encrypted messages for Discord, as a [Vencord](https://vencord.dev) userplugin.
You choose who can read each message: one person in a DM, or up to 10 people
(including you) in a group DM or server channel. Every contact uses either
[age](https://age-encryption.org) or [OpenPGP](https://www.openpgp.org).

> **Status: early and unaudited.** Cipher has not had an independent security
> audit. It doesn't implement its own cryptography: age is done by
> [typage](https://github.com/FiloSottile/typage) (the age authors' TypeScript
> implementation) and PGP by **your own installed GnuPG** (Gpg4win on Windows). The
> way Cipher combines them has only been reviewed by its authors. Read
> [what Cipher does not protect](#what-cipher-does-not-protect) before relying on it.
> [AUDIT.md](AUDIT.md) records the line-by-line review of the bundled code.

## Features

- **Your keys**: an age key (stored by Cipher), a PGP key from your GnuPG keyring (the
  keys you see in Kleopatra), or both. Cipher can create either; new PGP keys are
  Curve25519, not RSA. Your age key is encrypted with your Cipher passphrase and unlocked
  when you start using it. Your PGP secret key never leaves GnuPG: GnuPG asks for its
  passphrase itself, and Cipher warns if the key has none.
- **Auto-lock**: Cipher locks after 15 minutes without keyboard or mouse use (adjustable),
  when the screen locks, and after sleep, and makes GnuPG forget your PGP passphrase too.
- **Contacts**: a contact book keyed by Discord user ID. Pick who a key is for from your
  Discord friends and group DMs (or paste a user ID), paste the key, and its type is
  detected. Expired, revoked or encryption-incapable PGP keys are flagged.
- **Key sharing**: "Share my key here" posts a clearly marked public key message. Other
  Cipher users get a "Trust this key for <name>" button under it.
- **Verification**: every key has a fingerprint and a 30-digit comparison code. Read the
  code to each other over a call or in person, then mark the key as verified.
- **Key changes are loud**: if a contact posts a different key, Cipher shows a red warning,
  keeps encrypting to the old key, and only switches after you explicitly confirm.
- **Picking readers**: the lock button in the chat bar opens a picker that lists only people
  you have a key for, with their key type and verification status. Nobody but you is selected
  by default. Saved groups (e.g. "Close friends") add several people in one click; a group
  can be made from one of your Discord group DMs, and "Everyone in this chat" adds the
  members of the current DM or group DM.
- **Modes**: off (the default everywhere), *next message only*, or *keep on in this chat*
  with the readers remembered for that chat. Encryption never turns itself on.
- **Visible readers**: while encryption is on, the chat bar shows who can read the next
  message and warns about people in the chat who will see the ciphertext but can't read it.
- **Mixed key types**: one ciphertext is either age or PGP. If your readers mix both,
  Cipher asks you to either drop one type (and shows exactly who would be removed) or send
  two linked ciphertexts. Nobody is ever dropped silently.
- **Hard limit of 10 readers**, including you.
- **Fails closed**: if encryption is on and anything is wrong (no readers, a missing or
  expired key, attachments in the message, an error), the message is not sent and Cipher
  says why. It never falls back to plaintext. Edits are refused while encryption is on,
  because Cipher can't encrypt them.
- **Copy and retry**: "Copy decrypted text" copies the plaintext (Discord's own Copy Text
  copies the ciphertext). If you close GnuPG's passphrase prompt, Cipher stops opening it on
  its own and shows a Decrypt button instead.
- **Reading**: age and PGP messages are decrypted and shown **in place of the encrypted
  text**, in a green box with a lock, with badges for the signature (PGP) and for whether
  you verified the sender's key. A "Show encrypted text" link under each one shows what
  Discord actually stores; a setting turns the replacement off. Hand-made `age -a` /
  `gpg -a` messages pasted into chat are decrypted too.
- **Signatures (PGP only)**: outgoing PGP messages are signed when enabled (default on),
  and incoming signatures are checked. **age has no signatures**: an age message proves
  nothing about who wrote it, and Cipher labels it "unsigned (age)".
- **Post-quantum age keys** (ML-KEM-768 + X25519), for messages that should stay safe even
  against future quantum computers. Cipher never mixes them with normal keys in one message,
  which would undo the protection.
- **Optional Cipher server** ([server/README.md](server/README.md)): a public-key directory
  (find someone's key by their Discord account) and **disappearing messages** kept for 1, 3 or
  7 days, with only a short encoded reference in Discord (no clickable link). You host it yourself on Cloudflare; it only ever
  gets public keys and ciphertext. Changing a published key needs proof from the key itself,
  so a stolen Discord login can't swap it. Cipher comes set to the project's own server
  (free, run by the maintainer); clear the address in settings to keep everything in Discord,
  or host your own.
- **Long messages**: compressed if that helps, then split across several messages, and
  sent as an attachment beyond a configurable limit (default 4 messages).

## Install

### Windows: one click

1. Download **`Cipher-Setup.exe`** from the [latest release](https://github.com/cipherciphercipher/cipher/releases/latest).
2. Double-click it, pick your Discord, click **Install**. (Windows may say "Windows protected
   your PC" because the file isn't signed with a paid certificate: click **More info → Run
   anyway**.)
3. Start Discord and turn on **Cipher** in Settings → Vencord → Plugins.

No admin rights, nothing else to install. **Uninstall** in the same window puts everything
back. What it changes, and nothing else: the Vencord + Cipher files in
`%APPDATA%\Vencord\dist` (an existing Vencord there is backed up and restored on uninstall),
and, only for an unmodified Discord, the same small loader in Discord's `resources` folder
that Vencord's own installer uses. A Discord already set up by Vencord keeps its loader; one
modified by other software isn't touched at all. Source: [`installer/CipherSetup.cs`](installer/CipherSetup.cs).

**Checking the download** (optional): every `Cipher-Setup.exe` is built by GitHub Actions from
the tagged source, with a checksum and a signed build record:

```powershell
Get-FileHash Cipher-Setup.exe   # compare with Cipher-Setup.exe.sha256 on the release
gh attestation verify Cipher-Setup.exe -R cipherciphercipher/cipher
```

To build it yourself on Windows (uses the C# compiler that comes with Windows, nothing to
download beyond Vencord): `node scripts/build-exe.mjs`, output in `dist-exe/`.

### From source (any system)

Cipher is a [userplugin](https://docs.vencord.dev/installing/custom-plugins/): it's built
into Vencord from source. The installer does all of that for you.

**You need:** the Discord **desktop** app, [Node.js](https://nodejs.org) 18 or newer, and
[git](https://git-scm.com). For PGP, also GnuPG 2.2+ in its standard place:
[Gpg4win](https://gpg4win.org) on Windows (includes Kleopatra), Homebrew or GPG Suite on
macOS, your distribution's `gnupg` on Linux. Cipher never looks for GnuPG on `PATH`. age
works without GnuPG.

1. Download the latest release zip (or `git clone` this repository) and unpack it.
2. Run the installer:
   - **Windows:** double-click `install.cmd`.
   - **macOS / Linux:** run `./install.sh` in a terminal.
3. When it asks, answer **y** to install into Discord, then restart Discord.
4. Enable **Cipher** in Settings → Vencord → Plugins.

The installer:

- downloads Vencord at the release Cipher was tested with into `~/Vencord-Cipher`, and stops
  if that release's commit isn't the expected one;
- adds Cipher's one dependency and **stops unless every package it pulls in is exactly the
  version that was reviewed** (the integrity hashes in `scripts/audited-deps.json`; see
  [AUDIT.md](AUDIT.md));
- builds Vencord with Cipher in it, then, only if you agree, runs Vencord's own installer.

To **update**, download the new version and run the installer again. Options
(`install.cmd --help`):

| Option | |
|---|---|
| `--inject` / `--no-inject` | install into Discord without asking / only build |
| `--vencord <path>` | use your own Vencord source checkout |
| `--deploy <dist folder>` | for a Vencord that's already installed: build a standalone copy with Vencord's updater turned off and copy it into that `dist` folder (backed up first). On Windows that's usually `%APPDATA%\Vencord\dist`. With the updater off, Vencord only updates when you rerun the installer. |

In Discord in a browser, Cipher can do age but not PGP, because a web page can't run GnuPG.

<details><summary>Installing by hand</summary>

1. Set up Vencord from source following the [official guide](https://docs.vencord.dev/installing/).
2. Copy this repository's `src/` folder to `Vencord/src/userplugins/cipher/`.
3. In the Vencord folder: `pnpm add -w age-encryption@0.3.1`, then `pnpm build` and
   `pnpm inject`. Restart Discord.

</details>

## Quick start

1. **Make a key.** Settings → Plugins → Cipher → *Generate age key* (you choose a Cipher
   passphrase; it can't be recovered), and/or under PGP pick one of your GnuPG keys or
   *Create a new key in GnuPG* (GnuPG asks for that key's passphrase).
2. **Swap keys.** In a DM, click the lock in the chat bar → *Share my … key here*. Ask the
   other person to do the same, then click *Trust this key for …* under their message.
3. **Verify.** Open their contact (lock → *details*, or right-click them → *Cipher key…*)
   and compare the 30-digit code with them over a call. Tick *I compared this code*.
4. **Encrypt.** Lock → tick who can read → *Encrypt next message* or *Keep on in this chat*.
   The lock turns green and shows the readers. Right-click it to turn encryption off.

Group DMs and server channels work the same way: everyone in the channel sees the
ciphertext, only the readers you pick can decrypt it.

## How it looks on the wire

~~~
-# 🔒 Cipher v1 · pgp · 1/2 · ref k3x9q2ab
```
-----BEGIN PGP MESSAGE-----
...
```
~~~

`ref` links the parts of a split message and `set` links the age and PGP copies of one
message. A message that fits in one Discord message has neither: its header is just
`-# 🔒 Cipher v1 · pgp · 1/1`.

The armor inside is standard: join the parts and `age -d` or `gpg -d` can decrypt it
too. Inside the ciphertext is a 5-byte header (magic + flags) and the text, deflate-compressed
only when the message would otherwise need several Discord messages. Without the header the
payload is plain UTF-8, which is why hand-made `age`/`gpg` messages also work.

Rough sizes (checked by the test suite): a short signed message to 10 PGP readers fits
within the default limit of 4 Discord messages. 4,000 random characters to 10 PGP readers
need more than 4, so with the default limit it goes out as an attachment
(`cipher-<ref>.asc` / `.age`).

## What Cipher does not protect

Please read [SECURITY.md](SECURITY.md) for the full threat model. In short:

- **Metadata is visible to Discord**: who sent a message, to which channel, when, and how
  long it is. Discord also stores the ciphertext forever.
- **Everyone who can read the channel sees the ciphertext**, and with it the time and
  sender. Only the readers you chose can decrypt it.
- **A compromised device defeats the encryption.** Malware, a malicious plugin or someone
  with access to your unlocked Discord can read your plaintext and your unlocked keys.
  Locking Cipher doesn't make GnuPG forget a PGP passphrase it has cached; see
  [SECURITY.md](SECURITY.md#pgp-through-gnupg).
- **Recipients can leak what you send**: screenshots, copy-paste, forwarding.
- **Removing someone doesn't revoke access to old messages.** Anything they could read
  before, they can still read.
- **No forward secrecy**: neither age nor PGP has it. If a private key leaks later, every
  message ever encrypted to it can be decrypted from Discord's copy.
- **age messages aren't signed**: anyone who knows your public key can write you a
  message. Only PGP signatures prove who wrote something.
- **Discord client mods violate Discord's Terms of Service.** Using Vencord, and so
  Cipher, can get your account actioned. That's your call to make.

## Development

```sh
pnpm install
pnpm test            # vitest: key generation, round trips, recipients, splitting, ...
pnpm lint
pnpm typecheck       # the framework-free core and the tests
pnpm vencord:check   # typecheck and build the whole plugin inside Vencord
```

Releases: bump `version` in `package.json`, move the *Unreleased* changelog entries under the
new version, and push a tag `vX.Y.Z`. The release workflow runs the checks and the installer,
then publishes a zip with the installer, `src/` and the docs, plus its SHA-256.

`src/core/` has no Discord or Vencord imports and holds all the cryptography, message
formats and rules; it's what the tests cover. `src/core/gpg.ts` runs GnuPG (Node only).
`src/native.ts` exposes it to the Discord window through Vencord's plugin IPC, and
`src/gnupgBridge.ts` is the window side of that bridge. `src/ui/`, `src/send.ts`,
`src/receive.ts` and `src/state.ts` connect the core to Vencord's APIs (settings, chat bar
button, message send/edit events, message accessories, context menus, DataStore). Cipher
uses no webpack patches of its own.

The tests need GnuPG installed. They only ever use throwaway GnuPG homes in a temp folder
with passphrase-less test keys, never your own keyring.

See [CONTRIBUTING.md](CONTRIBUTING.md) and the [changelog](CHANGELOG.md).

## License

[GPL-3.0-or-later](LICENSE), the same as Vencord.
