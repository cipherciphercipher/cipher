import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { afterAll } from "vitest";

import { generateAgeIdentity } from "../src/core/ageCipher";
import type { DecryptKeys } from "../src/core/compose";
import { findGpg, GpgEngine, type GpgPaths } from "../src/core/gpg";
import { inspectKey, type KeyInfo } from "../src/core/keys";
import { setPgpEngine } from "../src/core/pgpCipher";
import type { Candidate } from "../src/core/recipients";

/*
 * GnuPG for tests. Every test GnuPG home is a fresh temp folder with
 * throwaway, passphrase-less keys. The user's own GnuPG home is never used:
 * every engine here is created with an explicit `homedir`.
 */

const found = findGpg();
if (!found) throw new Error("These tests need GnuPG 2.2+ installed (Gpg4win on Windows, gnupg on Linux/macOS).");
export const gpgPaths: GpgPaths = found;
const gpgconf = join(dirname(found.gpg), "gpgconf" + (process.platform === "win32" ? ".exe" : ""));

const homes: string[] = [];

export function newGpgHome(): { home: string; engine: GpgEngine; } {
    const home = mkdtempSync(join(tmpdir(), "cipher-test-gnupg-"));
    homes.push(home);
    return { home, engine: new GpgEngine({ ...gpgPaths, homedir: home, noPinentry: true }) };
}

/** Runs gpg directly in a test home, for setups the engine deliberately can't do. */
export function rawGpg(home: string, args: string[], input?: Uint8Array | string) {
    const r = spawnSync(gpgPaths.gpg, ["--homedir", home, "--batch", "--no-tty", "--pinentry-mode", "loopback", "--passphrase", "", ...args], { input, windowsHide: true, maxBuffer: 1 << 28 });
    if (r.error) throw r.error;
    return { code: r.status, stdout: r.stdout, stderr: r.stderr.toString() };
}

export function readRevocation(home: string, fingerprint: string): string {
    // GnuPG prefixes the BEGIN line with ':' so the file can't be imported by accident.
    return readFileSync(join(home, "openpgp-revocs.d", `${fingerprint}.rev`), "utf8").replace(":-----BEGIN", "-----BEGIN");
}

afterAll(() => {
    for (const home of homes.splice(0)) {
        spawnSync(gpgconf, ["--homedir", home, "--kill", "all"], { windowsHide: true });
        rmSync(home, { recursive: true, force: true });
    }
});

// Key inspection doesn't depend on any keyring; give it an empty home.
export const inspector = newGpgHome().engine;
setPgpEngine(inspector);

export interface TestUser {
    userId: string;
    name: string;
    type: "age" | "pgp";
    publicKey: string;
    keys: DecryptKeys;
    /** PGP users: their engine (their own GnuPG home), that home, and fingerprint. */
    engine?: GpgEngine;
    home?: string;
    fingerprint?: string;
    info: KeyInfo;
}

let counter = 1000;

export async function ageUser(name: string): Promise<TestUser> {
    const { identity, recipient } = await generateAgeIdentity();
    return {
        userId: String(counter++), name, type: "age", publicKey: recipient,
        keys: { ageIdentity: identity }, info: await inspectKey("age", recipient)
    };
}

/** A PGP user with their own GnuPG home and a fresh Curve25519 key. */
export async function pgpUser(name: string): Promise<TestUser> {
    const { home, engine } = newGpgHome();
    const fingerprint = await engine.generateKey(`${name} (Cipher test)`);
    const publicKey = await engine.exportPublicKey(fingerprint);
    return {
        userId: String(counter++), name, type: "pgp", publicKey,
        keys: { pgp: engine }, engine, home, fingerprint,
        info: await inspectKey("pgp", publicKey, Date.now(), engine)
    };
}

export function candidate(u: TestUser, extra: Partial<Candidate> = {}): Candidate {
    return {
        userId: u.userId, name: u.name, type: u.type, material: u.publicKey,
        problems: [], verified: true, pendingKeyChange: false, ...extra
    };
}

export function lookupOf(users: TestUser[], extra: Partial<Candidate> = {}) {
    const map = new Map(users.map(u => [u.userId, candidate(u, extra)]));
    return (id: string) => map.get(id);
}

/** Incompressible-ish text: random CJK characters, 3 bytes each in UTF-8. */
export function randomText(chars: number): string {
    const codes = crypto.getRandomValues(new Uint16Array(chars));
    return String.fromCharCode(...Array.from(codes, c => 0x4E00 + (c % 20000)));
}
