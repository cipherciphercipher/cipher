# Contributing to Cipher

Thanks for helping. Cipher handles people's private messages, so changes are held to a
careful standard. Please open an issue to discuss new features before writing them.

Security problems go through the private process in [SECURITY.md](SECURITY.md), not public
issues or pull requests.

## Setup

```sh
pnpm install
pnpm check           # lint + typecheck + tests
pnpm vencord:check   # typecheck and build inside a scratch Vencord checkout (.vencord/)
```

Node 22+, pnpm 10 (the version in `package.json`), and GnuPG 2.2+ installed in its
standard location (the tests run real `gpg`/`gpgv`). `vencord:check` fetches the pnpm
version Vencord pins by itself.

Tests must never touch a real keyring: create GnuPG engines only through `newGpgHome()`
in `test/helpers.ts`, which makes a throwaway home and deletes it afterwards.

To try your changes in Discord, copy `src/` to `Vencord/src/userplugins/cipher/` in your
own Vencord source checkout and rebuild it.

## Layout

- `src/core/`: everything testable. Cryptography wrappers, key inspection, the vault, the
  contact book, recipient planning, message formats, and `gpg.ts` (runs GnuPG; Node only).
  **No Vencord or Discord imports here.**
- `src/native.ts`: runs in Discord's main process and exposes the GnuPG operations over
  Vencord's plugin IPC. Treat every argument as untrusted. `src/gnupgBridge.ts` is the
  window side.
- `src/send.ts`, `src/receive.ts`, `src/state.ts`: glue between the core and Vencord.
- `src/ui/`: React components (chat bar button, recipient picker, message accessory,
  key manager, dialogs).
- `test/`: vitest tests for the core.

## Rules for changes

- **Never log or display plaintext, private keys or ciphertext.** `console` is a lint
  error. Throw `CipherError` with a code from `src/core/errors.ts`; don't show library error
  messages to users.
- **Fail closed.** If encryption is on and something unexpected happens, the message must
  not be sent. Never drop a recipient to make a send succeed.
- **Use Vencord's plugin APIs**: settings, chat bar buttons, message events, accessories,
  context menus, DataStore. Webpack patches need a very good reason and a discussion first.
- **Tests.** Logic changes in `src/core/` need tests. Bug fixes should come with a test
  that failed before the fix.
- **Wire format.** Changes to how messages, keys or the vault look must stay readable by
  older versions or bump the format version, and need a changelog entry.
- **Dependencies.** Avoid new ones. If one is truly needed: pin an exact version, say why in
  the PR, and check that its published tarball matches its source repository. A runtime
  dependency must also be read line by line and recorded in `AUDIT.md`
  (`scripts/audit-check.mjs` helps with the mechanical parts). The workspace refuses
  packages younger than 7 days and doesn't run install scripts; don't turn that off.
  After a reviewed change to the runtime dependencies, update `scripts/audited-deps.json`
  (the tests check it matches `pnpm-lock.yaml`); the installer refuses anything else.
- **GnuPG.** Run it only through `GpgEngine`: argument arrays, no shell, no `PATH` lookup,
  plaintext only on pipes. Never pass user text as a positional argument that could start
  with `-`.
- Keep the docs honest. Don't claim Cipher is audited or protects anything it doesn't.

## Pull requests

- One topic per PR, with a description of what changed and how you tested it
  (including in Discord, for UI changes).
- CI must pass: lint, typecheck, tests, and the Vencord build.
- Add a line to `CHANGELOG.md` under *Unreleased*.

By contributing you agree your contribution is licensed under GPL-3.0-or-later.
