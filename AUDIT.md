# Dependency audit log

Line-by-line read of every file Cipher ships or installs, for malware and tampering.
This is the maintainers' own review, **not an independent security audit**.

Method per file type:

- `.js` (the code that runs), `package.json`, `README`, `LICENSE`: read in full.
- `.ts` sources shipped next to the `.js`: mechanically verified to compile (types stripped)
  to exactly the `.js` that was read.
- `.d.ts` declarations: code lines read; doc-comment lines verified verbatim against the source.
- Older duplicate versions of a package: diffed against the newer version; every changed line read.
- `.map` source maps: structurally checked (JSON, point only at the package's own sources).

What was looked for: network access, dynamic code (`eval`, `Function`, dynamic `import`),
process / file-system / storage access, obfuscated or encoded payloads, hidden globals,
install scripts, and crypto tampering (random number source, constants, comparisons).

Backed up by `test/vectors.test.ts`: official test vectors, cross-checks against Node's
OpenSSL, and an independent age implementation.

## age-encryption 0.3.1 — 21 files — clean

All `dist/*.js`, `dist/*.d.ts`, README, LICENSE (BSD-3-Clause), package.json read.
No network; `navigator.credentials` only in the optional WebAuthn module, never called by Cipher.
Uses WebCrypto X25519 when available, noble otherwise. Constant-time header MAC compare.
scrypt work factor capped at 2^20 on decrypt. Matches the age spec (independent implementation
round-trips in both directions).

## @scure/base 2.4.0 — 6 files — clean

index.js and index.ts read in full; index.d.ts code lines read, its 357 doc-comment lines
verified verbatim in index.ts; README, LICENSE (MIT), package.json read. Pure encoders;
bech32 constants match BIP-173/350.

## @noble/hashes 2.4.0 — 60 files — clean

All 19 `.js` modules, package.json, LICENSE (MIT) and README read in full. `randomBytes` is
`globalThis.crypto.getRandomValues` (also proven by test: `Math.random` is never used).
Standard constants (SHA-2 IVs/round constants, Keccak, BLAKE IVs). Only globals: `crypto`,
`TextEncoder`, `scheduler.yield`/`setTimeout` for async loops.
`scripts/audit-check.mjs`: 18/19 `src/*.ts` compile to exactly the `.js` read; `src/index.ts`
(doc comment + `throw`) read in full; all `.d.ts` code lines read (pure types), their
doc-comment lines verbatim in the sources.

## @noble/hashes 2.0.1 — 98 files — clean

Pulled in by @noble/post-quantum. Every `.js` line that differs from 2.4.0 read (989 lines:
older implementations of the same algorithms, no new capabilities); `randomBytes` checked
directly (`crypto.getRandomValues`). `.ts` sources: 18/19 identical to the `.js`, index.ts same
as 2.4.0's. `.d.ts` lines not already in 2.4.0 read (241, all types). All 38 `.map` files are
plain source maps of the package's own sources (no embedded content). README differences read
(documentation only); LICENSE identical to 2.4.0.

## @noble/ciphers 2.4.0 — 33 files — clean

All 10 `.js` modules (aes, chacha, salsa, ff1, webcrypto, utils, _arx, _poly1305, _polyval,
index), README, LICENSE (MIT) and package.json (no install scripts) read in full. Pure
computation: no network, storage, dynamic code or hidden globals; only `crypto.getRandomValues`,
`crypto.subtle` (webcrypto wrapper, unused by age) and `TextEncoder`/`TextDecoder`. ChaCha20
constants and quarter-round order match RFC 8439; Poly1305 clamp masks match poly1305-donna;
the AES S-box is computed from GF(2^8) arithmetic, not embedded; every AEAD verifies its tag with
the constant-time `equalBytes` before decrypting. `scripts/audit-check.mjs`: 9/10 `src/*.ts`
compile to exactly the `.js` read; `src/index.ts` (doc comment + `throw`) read in full; all 399
`.d.ts` code lines read (pure types), all their doc-comment lines verbatim in the sources.

## @noble/curves 2.4.0 — 72 files — clean

All 25 `.js` modules (utils, index, ed25519, ed448, nist, secp256k1, misc, webcrypto, bn254,
bls12-381, abstract/{curve, modular, montgomery, edwards, weierstrass, hash-to-curve, oprf, frost,
fft, der, bls, poseidon, tower}), README, LICENSE (MIT) and package.json (no install scripts; only
dependency @noble/hashes 2.4.0) read in full. No network, storage, dynamic code or hidden globals;
randomness only via @noble/hashes `randomBytes` (`crypto.getRandomValues`); `crypto.subtle` only in
webcrypto.js (not used by age). X25519 follows RFC 7748 (u=9, a24=121665, RFC ladder, libsodium
low-order blocklist); the Curve25519 constants (p, d, n, G, √−1, both order-8 u values) were
re-derived independently and match. Other curve constants match SEC 2 / RFC 5639 / RFC 9380 /
draft-irtf-cfrg-pairing-friendly-curves. `scripts/audit-check.mjs`: 22/23 `src/*.ts` compile to
exactly the `.js` read; `src/index.ts` (doc comment + `throw`) read in full; all 1404 `.d.ts`
code lines read (pure types), all their doc-comment lines verbatim in the sources.

## @noble/curves 2.0.1 — 108 files — clean

Pulled in by @noble/post-quantum. package.json read (no install scripts; only dependency
@noble/hashes 2.0.1). Every `.js` line that differs from 2.4.0 read (2113 lines: older wNAF,
DER inline in weierstrass, a WeakMap `memoized` cache, older Montgomery cswap; no new
capabilities). `.ts` sources: 20/21 identical to the `.js`, index.ts doc comment + `throw`. The 852
`.d.ts` code lines not already in 2.4.0 read (all types). All 42 `.map` files are plain source maps
of the package's own sources (no embedded content). README differences read (documentation only);
LICENSE identical to 2.4.0.

## @noble/post-quantum 0.5.4 — 38 files — clean

Loaded by age-encryption for its hybrid ML-KEM-768 + X25519 recipients (Cipher only creates
plain X25519 recipients, but the module is still imported). All 7 `.js` modules (utils, index,
_crystals, ml-kem, ml-dsa, slh-dsa, hybrid), README, LICENSE (MIT) and package.json (no install
scripts; dependencies @noble/curves ~2.0.0, @noble/hashes ~2.0.0) read in full. No network,
storage, dynamic code or hidden globals; randomness only via @noble/hashes `randomBytes`. ML-KEM
constants match FIPS 203 (q = 3329, ζ = 17, 3303 = 128⁻¹ mod q); ML-DSA constants match FIPS 204
(q = 8380417, ζ = 1753, 8347681 = 256⁻¹ mod q). `scripts/audit-check.mjs`: 6/7 `src/*.ts` compile
to exactly the `.js` read; `src/index.ts` (doc comment + `throw`) read in full; all 227 `.d.ts`
code lines read (pure types); all 14 `.map` files plain. Its README states it has not been
independently audited.

## Runtime dependency tree — complete

`pnpm-lock.yaml` resolves age-encryption 0.3.1 to exactly: @noble/ciphers 2.4.0,
@noble/curves 2.4.0 + 2.0.1, @noble/hashes 2.4.0 + 2.0.1, @noble/post-quantum 0.5.4,
@scure/base 2.4.0. All of them are covered above.

Dev tooling (TypeScript, ESLint, Vitest/Vite) and Vencord's own build dependencies never ship in
Cipher and are **not** covered by this line-by-line review. They are pinned by integrity hash in
the lockfiles, and Cipher's workspace runs no install scripts (`onlyBuiltDependencies: []`) and
refuses releases younger than 7 days (`minimumReleaseAge`). Vencord's own checkout uses Vencord's
settings, not these.

PGP is done by the user's installed GnuPG (Gpg4win on Windows), which Cipher doesn't ship. Its
installer's signature was checked; its code was not read.

## Cipher's own code — clean

Every file read in full: `src/` (core, plugin, UI, CSS), `test/`, `scripts/`, `package.json`,
`pnpm-workspace.yaml`, `tsconfig.json`, `vitest.config.ts`, `eslint.config.js`, `.gitignore`
and the CI workflow (third-party actions pinned by commit SHA, read-only token).

- Network: only Discord's own API (sending messages and uploading attachments, through
  Discord's modules) and downloading Cipher attachments from Discord's CDN without cookies.
  Since the second review, also the user's own Cipher server if they set one (empty by
  default), and another server's link only after a click. No telemetry or other hosts. `scripts/vencord-check.mjs` clones Vencord from GitHub and runs
  pnpm; it never runs `pnpm inject`.
- Processes: only `gpg`/`gpgv` from fixed install paths, argument arrays, no shell (plugin and
  tests); the tests' own `gpg` calls always pass a throwaway `--homedir`.
- Storage: Vencord's DataStore, per Discord account. Plaintext is never stored; decrypted text
  lives in memory only. No `console` calls (lint error).

Second review (2026-11-26), every line again, after the post-quantum, server and link
features were added, plus the new `server/` Worker (`src/index.ts`, `src/validate.ts`,
`schema.sql`, `wrangler.toml`). New network paths: the optional Cipher server only, through
`native.ts`'s fixed request list. `@noble/post-quantum` (already reviewed above) is now used for
post-quantum age keys. Fixed in that pass (tests added): strangers' PGP messages and keys no
longer reach GnuPG automatically; recipient-count caps; a GnuPG version floor; mixed
public-key/passphrase PGP messages refused; secret-key export needs a native confirmation.
Post-quantum PGP (GnuPG 2.5) was not adopted: its code (GnuPG, libgcrypt and friends, hundreds
of thousands of lines of C, shipped as compiled binaries) can't be read line by line here, and
it needs GnuPG 2.5 on every reader.

Third pass (2026-11-26), every new and changed line: `src/core/keyProof.ts`,
`src/autoLock.ts`, `server/src/pgpVerify.ts`, the key routes in `server/src/index.ts`, the new
GnuPG operations in `src/core/gpg.ts` (`signProof`, `keyProtection`, `forgetPassphrase`) and
their `native.ts` entry points. New process: `gpg-connect-agent` from GnuPG's own folder
(fixed path, argument array, no shell), sent only `KEYINFO` and `CLEAR_PASSPHRASE` for the
selected key's keygrips; it never reads key material. New Electron API: `powerMonitor`
(idle time and screen lock only). No new dependencies.

Fourth pass (2026-11-26), with the goal "nobody running or breaking into a Cipher server can
run code on a user's computer": every path from server data and chat data into the plugin
was traced. JavaScript shape checks now guard every GnuPG input, GnuPG ignores `gpg.conf`,
compressed PGP data is refused, server-provided directory fields are validated, and
`scripts/vencord-check.mjs` no longer passes unchecked arguments to the Windows shell. A
pattern sweep of `src/`, `server/` and `scripts/` found no HTML injection, dynamic code, or
process starts other than GnuPG (argument arrays, no shell) and the installer's checked
`npx` calls.

Bugs found and fixed during the first review (tests added):

- A key-generation user ID starting with `-` would have been read by gpg as an option. Now
  refused in `native.ts` and `gpg.ts`; the UI strips leading dashes.
- A contact key Cipher couldn't check (for example with GnuPG missing) was reported as "no
  encryption subkey". It's now reported as "check failed", with a hint about GnuPG.
- A storage error when applying the recipient picker was unhandled; it's now shown.
