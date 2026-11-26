/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * PgpEngine backed by the user's GnuPG (gpg + gpgv). Node only: used by
 * src/native.ts in Discord's main process, and by the tests.
 *
 * Safety rules, all enforced here:
 *  - gpg is run directly with an argument array, never through a shell, and
 *    only from a fixed install location (never looked up on PATH).
 *  - Plaintext only travels through stdin/stdout pipes, never temp files.
 *    Temp files hold public keys only, in a private directory deleted after use.
 *  - Readers are exactly the keys Cipher passes: --no-encrypt-to stops
 *    gpg.conf from silently adding extra recipients.
 *  - gpg never goes online: no keyserver lookups.
 *  - Signatures are checked with gpgv against a keyring holding only the
 *    keys Cipher passes in, so the user's keyring and trust settings don't
 *    change the answer and contacts are never imported.
 *  - Output size is capped; a decompression bomb kills the process.
 *  - Messages not encrypted to a public key (passphrase-only messages) are
 *    refused before gpg runs, so nobody can trigger a passphrase prompt.
 *  - Keys and messages are checked in JavaScript first (pgpPackets.ts): only
 *    the exact packet shapes Cipher makes reach gpg's C parser. No photo IDs,
 *    no compressed data, nothing after the encrypted packet.
 *  - gpg.conf is ignored (--no-options): options there (photo viewers,
 *    keyservers, exec paths) can't change what Cipher's gpg calls do.
 */

/** Public-key packets only, checked in JavaScript; anything else never reaches gpg. */
export function publicKeyShapeOk(armored: string): boolean {
    try {
        checkPublicKeyShape(dearmor(armored));
        return true;
    } catch {
        return false;
    }
}

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { isProofStatementFor } from "./keyProof";
import { type GpgKey, type KeyProtection, type PgpAvailability, type PgpDecryptResult, type PgpEngine, PgpEngineError, type SignatureStatus } from "./pgpEngine";
import { checkInnerShape, checkMessageShape, checkPublicKeyShape, readSessionKeys } from "./pgpPackets";

export interface GpgPaths {
    gpg: string;
    gpgv: string;
    /** gpg-connect-agent, next to gpg: asks gpg-agent about passphrases (never for keys). */
    connectAgent?: string;
}

export interface GpgOptions extends GpgPaths {
    /** Only for tests: use this GnuPG home instead of the user's. */
    homedir?: string;
    /** Only for tests: keys without passphrases, no pinentry. */
    noPinentry?: boolean;
    maxConcurrent?: number;
}

/**
 * Oldest GnuPG Cipher accepts. Earlier releases could be tricked into
 * printing fake status lines (CVE-2018-12020, fixed in 2.2.8; CVE-2022-34903,
 * fixed in 2.2.36 and 2.3.7), which could fake a "signed by" badge.
 */
export function isSupportedGpgVersion([major, minor, patch]: number[]): boolean {
    if (major !== 2) return major > 2;
    if (minor >= 4) return true;
    if (minor === 3) return patch >= 7;
    if (minor === 2) return patch >= 36;
    return false;
}
const STDERR_LIMIT = 1024 * 1024;
const QUICK_TIMEOUT = 30_000;
/** Operations that may wait for the user to type a passphrase. */
const PINENTRY_TIMEOUT = 5 * 60_000;

/** Standard install locations only. PATH is deliberately not searched. */
export function findGpg(platform = process.platform, env = process.env): GpgPaths | null {
    const exe = platform === "win32" ? ".exe" : "";
    const candidates: string[] = [];
    if (platform === "win32") {
        for (const base of [env["ProgramFiles(x86)"], env.ProgramFiles, "C:\\Program Files (x86)", "C:\\Program Files"])
            if (base) candidates.push(join(base, "GnuPG", "bin", "gpg.exe"));
    } else if (platform === "darwin") {
        candidates.push("/opt/homebrew/bin/gpg", "/usr/local/bin/gpg", "/usr/local/MacGPG2/bin/gpg");
    } else {
        candidates.push("/usr/bin/gpg", "/usr/local/bin/gpg", "/bin/gpg");
    }
    for (const gpg of candidates) {
        const gpgv = join(dirname(gpg), "gpgv" + exe);
        if (!existsSync(gpg) || !existsSync(gpgv)) continue;
        const connectAgent = join(dirname(gpg), "gpg-connect-agent" + exe);
        return existsSync(connectAgent) ? { gpg, gpgv, connectAgent } : { gpg, gpgv };
    }
    return null;
}

interface RunResult {
    code: number | null;
    stdout: Buffer;
    status: string[][];
    stderr: string;
}

interface RunOptions {
    input?: Uint8Array | string;
    maxStdout: number;
    timeoutMs: number;
}

/** Status lines ("[GNUPG:] KEYWORD args...") split into words. */
function parseStatus(stderr: string): string[][] {
    const out: string[][] = [];
    for (const line of stderr.split(/\r?\n/)) {
        if (line.startsWith("[GNUPG:] ")) out.push(line.slice(9).trim().split(" "));
    }
    return out;
}

const has = (status: string[][], keyword: string) => status.some(s => s[0] === keyword);
const find = (status: string[][], keyword: string) => status.find(s => s[0] === keyword);

/** GnuPG status error codes are (source << 24 | code); 99 is GPG_ERR_CANCELED. */
function cancelled(status: string[][]) {
    return status.some(s => (s[0] === "ERROR" || s[0] === "FAILURE") && (Number(s[2]) & 0xFFFF) === 99);
}

export function decodeColonField(s: string): string {
    return s.replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
}

/** Parses `--with-colons` key listings. */
export function parseKeyListing(text: string, now = Date.now()): GpgKey[] {
    const keys: GpgKey[] = [];
    let cur: GpgKey | undefined;
    let wantFpr = false;
    for (const line of text.split(/\r?\n/)) {
        const f = line.split(":");
        const rec = f[0];
        if (rec === "pub" || rec === "sec") {
            const expires = f[6] ? Number(f[6]) * 1000 : undefined;
            const caps = f[11] ?? "";
            cur = {
                fingerprint: "",
                keyIds: [f[4].toUpperCase()],
                userIds: [],
                createdAt: f[5] ? Number(f[5]) * 1000 : undefined,
                expiresAt: expires,
                revoked: f[1] === "r",
                expired: f[1] === "e" || (expires !== undefined && expires <= now),
                canEncrypt: caps.includes("E"),
                canSign: caps.includes("S"),
                hasSecret: rec === "sec" ? ["+", ">"].includes(f[14] ?? "") : undefined
            };
            keys.push(cur);
            wantFpr = true;
        } else if (rec === "fpr" && cur && wantFpr) {
            cur.fingerprint = f[9].toUpperCase();
            wantFpr = false;
        } else if ((rec === "sub" || rec === "ssb") && cur) {
            cur.keyIds.push(f[4].toUpperCase());
            if (rec === "ssb" && ["+", ">"].includes(f[14] ?? "")) cur.hasSecret = true;
            wantFpr = false;
        } else if (rec === "uid" && cur && f[1] !== "r") {
            cur.userIds.push(decodeColonField(f[9] ?? ""));
        }
    }
    return keys.filter(k => k.fingerprint);
}

/**
 * Converts ASCII-armored OpenPGP data to binary (RFC 4880 §6.2). Used to
 * build a keyring file for gpgv without running gpg.
 */
export function dearmor(armored: string): Uint8Array {
    const lines = armored.replace(/\r\n/g, "\n").split("\n");
    const begin = lines.findIndex(l => /^-----BEGIN PGP [A-Z ]+-----$/.test(l.trim()));
    if (begin === -1) throw new PgpEngineError("invalid-key");
    let i = begin + 1;
    // Skip armor headers up to the blank line.
    while (i < lines.length && lines[i].trim() !== "") {
        if (!lines[i].includes(":")) break;
        i++;
    }
    let b64 = "";
    for (; i < lines.length; i++) {
        const l = lines[i].trim();
        if (l.startsWith("-----END PGP")) break;
        if (l.startsWith("=") && l.length === 5) continue; // CRC24 checksum
        if (l && !/^[A-Za-z0-9+/=]+$/.test(l)) throw new PgpEngineError("invalid-key");
        b64 += l;
    }
    if (!b64) throw new PgpEngineError("invalid-key");
    return Uint8Array.from(Buffer.from(b64, "base64"));
}

/**
 * Counts the session-key packets at the start of an OpenPGP message: public-key
 * and passphrase ones (see pgpPackets.ts). Throws on anything it can't read.
 */
export function sessionKeyPackets(data: Uint8Array): { publicKey: number; passphrase: number; } {
    try {
        const { publicKey, passphrase } = readSessionKeys(data);
        return { publicKey, passphrase };
    } catch {
        throw new PgpEngineError("decrypt-failed");
    }
}

const FPR_RE = /^(?:[0-9A-F]{40}|[0-9A-F]{64})$/;
const KEYGRIP_RE = /^[0-9A-F]{40}$/;

export interface AgentKeyInfo {
    /** D: on disk, T: smartcard, X: unknown. */
    type: string;
    cached: boolean;
    /** P: passphrase protected, C: not protected, -: unknown. */
    protection: string;
}

/** Parses gpg-agent's "S KEYINFO <grip> <type> <serial> <idstr> <cached> <protection> ..." lines. */
export function parseKeyInfo(text: string): Map<string, AgentKeyInfo> {
    const out = new Map<string, AgentKeyInfo>();
    for (const line of text.split(/\r?\n/)) {
        const f = line.trim().split(" ");
        if (f[0] !== "S" || f[1] !== "KEYINFO" || !KEYGRIP_RE.test((f[2] ?? "").toUpperCase())) continue;
        out.set(f[2].toUpperCase(), { type: f[3] ?? "X", cached: f[6] === "1", protection: f[7] ?? "-" });
    }
    return out;
}

export class GpgEngine implements PgpEngine {
    private running = 0;
    private queue: (() => void)[] = [];

    constructor(private opts: GpgOptions) { }

    private async slot<T>(fn: () => Promise<T>): Promise<T> {
        const max = this.opts.maxConcurrent ?? 2;
        if (this.running >= max) await new Promise<void>(r => this.queue.push(r));
        this.running++;
        try {
            return await fn();
        } finally {
            this.running--;
            this.queue.shift()?.();
        }
    }

    private baseArgs(): string[] {
        return [
            ...this.opts.homedir ? ["--homedir", this.opts.homedir] : [],
            // Ignore gpg.conf: nothing in it can add photo viewers, keyservers or other
            // behaviour to Cipher's calls. The keyring and gpg-agent are still the user's.
            "--no-options",
            "--batch", "--no-tty", "--no-greeting", "--status-fd", "2",
            "--no-auto-key-retrieve", "--no-auto-key-locate", "--display-charset", "utf-8",
            "--list-options", "no-show-photos", "--verify-options", "no-show-photos"
        ];
    }

    private secretArgs(): string[] {
        return this.opts.noPinentry ? ["--pinentry-mode", "loopback", "--passphrase", ""] : [];
    }

    private exec(bin: string, args: string[], o: RunOptions): Promise<RunResult> {
        return this.slot(() => new Promise<RunResult>((resolve, reject) => {
            const child = spawn(bin, args, { windowsHide: true, stdio: ["pipe", "pipe", "pipe"], shell: false });
            const out: Buffer[] = [];
            let outLen = 0;
            let err = "";
            let failed: PgpEngineError | undefined;
            const fail = (e: PgpEngineError) => {
                if (failed) return;
                failed = e;
                child.kill();
            };
            const timer = setTimeout(() => fail(new PgpEngineError("failed", "GnuPG timed out")), o.timeoutMs);

            child.stdout.on("data", (d: Buffer) => {
                outLen += d.length;
                if (outLen > o.maxStdout) return fail(new PgpEngineError("too-large"));
                out.push(d);
            });
            child.stderr.on("data", (d: Buffer) => {
                if (err.length < STDERR_LIMIT) err += d.toString("utf8");
            });
            child.on("error", e => {
                clearTimeout(timer);
                reject(new PgpEngineError((e as NodeJS.ErrnoException).code === "ENOENT" ? "not-found" : "failed"));
            });
            child.on("close", code => {
                clearTimeout(timer);
                if (failed) return reject(failed);
                resolve({ code, stdout: Buffer.concat(out), status: parseStatus(err), stderr: err });
            });
            child.stdin.on("error", () => { /* gpg may exit before reading all input */ });
            child.stdin.end(o.input ?? "");
        }));
    }

    private gpg(args: string[], o: Partial<RunOptions> = {}) {
        return this.exec(this.opts.gpg, [...this.baseArgs(), ...args], { maxStdout: 4 * 1024 * 1024, timeoutMs: QUICK_TIMEOUT, ...o });
    }

    private supported?: Promise<PgpAvailability>;

    /** Refuses to work with a GnuPG that's too old (checked once). */
    async requireSupported(): Promise<void> {
        this.supported ??= this.available();
        const a = await this.supported;
        if (!a.ok) {
            this.supported = undefined;
            throw new PgpEngineError("not-found", a.reason);
        }
    }

    private async withTempDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
        const dir = await mkdtemp(join(tmpdir(), "cipher-"));
        try {
            return await fn(dir);
        } finally {
            await rm(dir, { recursive: true, force: true });
        }
    }

    async available(): Promise<PgpAvailability> {
        try {
            const r = await this.exec(this.opts.gpg, ["--version"], { maxStdout: 65536, timeoutMs: QUICK_TIMEOUT });
            const m = /^gpg \(GnuPG[^)]*\) (\d+)\.(\d+)\.(\d+)/m.exec(r.stdout.toString("utf8"));
            if (!m) return { ok: false, reason: "Couldn't identify the GnuPG version." };
            const v = [Number(m[1]), Number(m[2]), Number(m[3])];
            if (!isSupportedGpgVersion(v)) return { ok: false, reason: `GnuPG ${v.join(".")} is too old and has known security bugs; Cipher needs 2.2.36, 2.3.7, 2.4 or newer.` };
            return { ok: true, version: v.join(".") };
        } catch {
            return { ok: false, reason: "GnuPG isn't installed." };
        }
    }

    async inspect(armoredKeys: string): Promise<GpgKey[]> {
        if (/PRIVATE KEY BLOCK/.test(armoredKeys)) throw new PgpEngineError("invalid-input", "private key");
        if (!publicKeyShapeOk(armoredKeys)) throw new PgpEngineError("invalid-key");
        // show-only: parse and print, never import.
        const r = await this.gpg(["--with-colons", "--import-options", "show-only", "--import"], { input: armoredKeys });
        const keys = parseKeyListing(r.stdout.toString("utf8"));
        if (!keys.length) throw new PgpEngineError("invalid-key");
        return keys;
    }

    async listSecretKeys(): Promise<GpgKey[]> {
        const r = await this.gpg(["--with-colons", "--list-secret-keys"]);
        return parseKeyListing(r.stdout.toString("utf8"));
    }

    async exportPublicKey(fingerprint: string): Promise<string> {
        // export-minimal drops third-party signatures, keeping key shares short;
        // no-export-attributes drops photo IDs, which Cipher refuses.
        const r = await this.gpg(["--armor", "--export-options", "export-minimal,no-export-attributes", "--export", fingerprint]);
        const armored = r.stdout.toString("utf8");
        if (!armored.includes("BEGIN PGP PUBLIC KEY BLOCK") || !publicKeyShapeOk(armored)) throw new PgpEngineError("invalid-key");
        return armored;
    }

    async generateKey(userId: string): Promise<string> {
        // gpg parses any argument starting with "-" as an option, wherever it appears.
        if (!userId.trim() || userId.trimStart().startsWith("-")) throw new PgpEngineError("invalid-input");
        const r = await this.gpg([...this.secretArgs(), "--quick-gen-key", userId, "future-default", "default", "never"], { timeoutMs: PINENTRY_TIMEOUT });
        if (cancelled(r.status)) throw new PgpEngineError("cancelled");
        const created = find(r.status, "KEY_CREATED");
        if (!created?.[2]) throw new PgpEngineError("failed");
        return created[2].toUpperCase();
    }

    async importSecretKey(armored: string): Promise<string[]> {
        if (!armored.includes("BEGIN PGP PRIVATE KEY BLOCK")) throw new PgpEngineError("invalid-input");
        const r = await this.gpg([...this.secretArgs(), "--import"], { input: armored, timeoutMs: PINENTRY_TIMEOUT });
        if (cancelled(r.status)) throw new PgpEngineError("cancelled");
        const fprs = [...new Set(r.status.filter(s => s[0] === "IMPORT_OK" && s[2]).map(s => s[2].toUpperCase()))];
        if (!fprs.length) throw new PgpEngineError("invalid-key");
        return fprs;
    }

    async exportSecretKey(fingerprint: string): Promise<string> {
        const r = await this.gpg([...this.secretArgs(), "--armor", "--export-secret-keys", fingerprint], { timeoutMs: PINENTRY_TIMEOUT });
        if (cancelled(r.status)) throw new PgpEngineError("cancelled");
        const armored = r.stdout.toString("utf8");
        if (!armored.includes("BEGIN PGP PRIVATE KEY BLOCK")) throw new PgpEngineError("failed");
        return armored;
    }

    async encrypt({ recipientKeys, signFingerprint, data }: { recipientKeys: string[]; signFingerprint?: string; data: Uint8Array; }): Promise<string> {
        if (recipientKeys.length === 0) throw new PgpEngineError("invalid-input");
        if (!recipientKeys.every(publicKeyShapeOk)) throw new PgpEngineError("invalid-key");
        return this.withTempDir(async dir => {
            const files: string[] = [];
            for (const [i, key] of recipientKeys.entries()) {
                const f = join(dir, `r${i}.asc`);
                await writeFile(f, key, { mode: 0o600 });
                files.push(f);
            }
            const r = await this.gpg([
                ...signFingerprint ? this.secretArgs() : [],
                "--armor", "--trust-model", "always", "--no-encrypt-to", "--compress-algo", "none",
                ...files.flatMap(f => ["--recipient-file", f]),
                ...signFingerprint ? ["--sign", "--local-user", signFingerprint] : [],
                "--encrypt"
            ], { input: data, timeoutMs: signFingerprint ? PINENTRY_TIMEOUT : QUICK_TIMEOUT });
            if (cancelled(r.status)) throw new PgpEngineError("cancelled");
            if (has(r.status, "INV_RECP") || has(r.status, "INV_SGNR")) throw new PgpEngineError("invalid-key");
            if (!has(r.status, "END_ENCRYPTION") || (signFingerprint && !has(r.status, "SIG_CREATED"))) throw new PgpEngineError("failed");
            return r.stdout.toString("utf8");
        });
    }

    async signProof(fingerprint: string, statement: string): Promise<string> {
        // Only key-proof statements naming this very key: this must never sign arbitrary text.
        if (!/^[0-9A-F]{40}$/.test(fingerprint) || !isProofStatementFor(statement, fingerprint)) throw new PgpEngineError("invalid-input");
        // "!" makes gpg use the primary key itself, which is what the server checks.
        const r = await this.gpg([
            ...this.secretArgs(), "--armor", "--no-textmode", "--digest-algo", "SHA256", "--local-user", `${fingerprint}!`, "--detach-sign"
        ], { input: statement, maxStdout: 64 * 1024, timeoutMs: PINENTRY_TIMEOUT });
        if (cancelled(r.status)) throw new PgpEngineError("cancelled");
        // SIG_CREATED <type> <pkalgo> <hashalgo> <class> <time> <signing key fingerprint>
        const created = find(r.status, "SIG_CREATED");
        if (!created || created[1] !== "D" || created[4] !== "00" || (created[6] ?? "").toUpperCase() !== fingerprint)
            throw new PgpEngineError(has(r.status, "INV_SGNR") ? "invalid-key" : "failed");
        const armored = r.stdout.toString("utf8");
        if (!armored.includes("-----BEGIN PGP SIGNATURE-----")) throw new PgpEngineError("failed");
        return armored;
    }

    /** Keygrips of the key's primary key and subkeys (gpg-agent names secret keys by keygrip). */
    private async keygrips(fingerprint: string): Promise<string[]> {
        if (!FPR_RE.test(fingerprint)) throw new PgpEngineError("invalid-input");
        const r = await this.gpg(["--with-colons", "--with-keygrip", "--list-secret-keys", fingerprint], { maxStdout: 256 * 1024 });
        const grips = r.stdout.toString("utf8").split(/\r?\n/).map(l => l.split(":"))
            .filter(f => f[0] === "grp").map(f => (f[9] ?? "").toUpperCase()).filter(g => KEYGRIP_RE.test(g));
        return [...new Set(grips)];
    }

    private agent(commands: string[], autostart: boolean): Promise<RunResult> {
        if (!this.opts.connectAgent) throw new PgpEngineError("not-found");
        return this.exec(this.opts.connectAgent, [
            ...this.opts.homedir ? ["--homedir", this.opts.homedir] : [],
            ...autostart ? [] : ["--no-autostart"],
            ...commands, "/bye"
        ], { maxStdout: 64 * 1024, timeoutMs: QUICK_TIMEOUT });
    }

    async keyProtection(fingerprint: string): Promise<KeyProtection> {
        const grips = await this.keygrips(fingerprint);
        if (!grips.length) return { state: "unknown", cached: false };
        const info = parseKeyInfo((await this.agent(grips.map(g => `KEYINFO ${g}`), true)).stdout.toString("utf8"));
        const found = grips.map(g => info.get(g)).filter((i): i is AgentKeyInfo => !!i);
        if (!found.length) return { state: "unknown", cached: false };
        const cached = found.some(i => i.cached);
        if (found.some(i => i.type !== "T" && i.protection === "C")) return { state: "unprotected", cached };
        if (found.every(i => i.type === "T")) return { state: "card", cached };
        if (found.every(i => i.type === "T" || i.protection === "P")) return { state: "protected", cached };
        return { state: "unknown", cached };
    }

    async forgetPassphrase(fingerprint: string): Promise<void> {
        const grips = await this.keygrips(fingerprint);
        // Without a running gpg-agent nothing is remembered, so don't start one.
        if (grips.length) await this.agent(grips.map(g => `CLEAR_PASSPHRASE --mode=normal ${g}`), false);
    }

    async recipientsOf(armoredMessage: string): Promise<string[]> {
        const r = await this.gpg(["--list-only", "--decrypt"], { input: armoredMessage, maxStdout: 65536 });
        return r.status.filter(s => s[0] === "ENC_TO" && s[1]).map(s => s[1].toUpperCase());
    }

    async decrypt({ armoredMessage, verificationKeys, maxBytes }: { armoredMessage: string; verificationKeys: string[]; maxBytes: number; }): Promise<PgpDecryptResult> {
        // Only public-key messages. A passphrase packet would make gpg pop up a
        // passphrase prompt chosen by whoever posted the message: on its own,
        // and also next to a public-key packet that fails to decrypt (gpg then
        // falls back to the passphrase). Cipher never sends one, so refuse any.
        let esk: ReturnType<typeof sessionKeyPackets>;
        try {
            const bin = dearmor(armoredMessage);
            esk = sessionKeyPackets(bin);
            if (esk.passphrase > 0 || esk.publicKey === 0) throw new PgpEngineError("not-recipient");
            // The whole outer message, not just its start: one encrypted packet, nothing after it.
            checkMessageShape(bin);
        } catch (e) {
            throw e instanceof PgpEngineError ? e : new PgpEngineError("decrypt-failed");
        }
        if ((await this.recipientsOf(armoredMessage)).length === 0) throw new PgpEngineError("not-recipient");

        // 1. Remove the encryption layer, keeping any signature intact.
        const unwrap = await this.gpg([...this.secretArgs(), "--unwrap", "--decrypt"], { input: armoredMessage, timeoutMs: PINENTRY_TIMEOUT });
        if (cancelled(unwrap.status)) throw new PgpEngineError("cancelled");
        if (!has(unwrap.status, "DECRYPTION_OKAY") || has(unwrap.status, "BADMDC") || has(unwrap.status, "DECRYPTION_FAILED")) {
            const encTo = unwrap.status.filter(s => s[0] === "ENC_TO").length;
            const noSec = unwrap.status.filter(s => s[0] === "NO_SECKEY").length;
            throw new PgpEngineError(encTo > 0 && noSec >= encTo ? "not-recipient" : "decrypt-failed");
        }
        const inner = unwrap.stdout;
        // The decrypted packets are the sender's too: only literal data and one signature go on.
        try {
            checkInnerShape(inner);
        } catch (e) {
            throw new PgpEngineError(e instanceof Error && e.message === "compressed" ? "compressed" : "decrypt-failed");
        }

        // 2. Check the signature (if any) with gpgv against the given keys only.
        const verified = await this.withTempDir(async dir => {
            const ring = join(dir, "verify.gpg");
            const parts: Uint8Array[] = [];
            for (const k of verificationKeys) {
                try {
                    const bin = dearmor(k);
                    checkPublicKeyShape(bin);
                    parts.push(bin);
                } catch {
                    // A broken or odd contact key must not stop decryption; it's just left out.
                }
            }
            await writeFile(ring, Buffer.concat(parts), { mode: 0o600 });
            // gpgv gets an empty home of its own, so no default "trustedkeys"
            // keyring can add signers beyond the keys passed in.
            return this.exec(this.opts.gpgv, [
                "--homedir", dir,
                "--status-fd", "2", "--keyring", ring, "--output", "-", "-"
            ], { input: inner, maxStdout: maxBytes, timeoutMs: QUICK_TIMEOUT });
        });

        if (!has(verified.status, "NEWSIG")) {
            // 3. Unsigned: just unpack the literal data. --pinentry-mode error
            // guarantees this can never ask for a passphrase.
            const plain = await this.gpg(["--pinentry-mode", "error", "--skip-verify", "--decrypt"], { input: inner, maxStdout: maxBytes });
            if (!has(plain.status, "PLAINTEXT")) throw new PgpEngineError("decrypt-failed");
            return { data: Uint8Array.from(plain.stdout), signature: { status: "unsigned" } };
        }

        if (!has(verified.status, "PLAINTEXT")) throw new PgpEngineError("decrypt-failed");
        return { data: Uint8Array.from(verified.stdout), signature: signatureVerdict(verified.status) };
    }
}

/** Reads gpgv's status lines for a signed message. */
export function signatureVerdict(status: string[][]): SignatureStatus {
    const valid = find(status, "VALIDSIG");
    const errSig = find(status, "ERRSIG");
    // More than one signature: Cipher only ever makes one, so refuse to guess.
    if (status.filter(s => s[0] === "NEWSIG").length !== 1) return { status: "invalid" };
    if (valid && !has(status, "BADSIG") && !errSig) {
        // VALIDSIG <fpr> <date> <ts> <exp> <ver> <res> <pkalgo> <hash> <class> <primary-fpr>
        const primary = (valid[10] ?? valid[1]).toUpperCase();
        const keyWarning = has(status, "REVKEYSIG") ? "revoked" : has(status, "EXPKEYSIG") ? "expired" : undefined;
        return { status: "valid", signerFingerprint: primary, ...keyWarning ? { keyWarning } : {} };
    }
    // ERRSIG <keyid> <pkalgo> <hash> <class> <time> <rc>; rc 9 = no public key
    if (errSig && errSig[6] === "9") return { status: "unknown-signer", signerKeyId: (errSig[1] ?? "").toUpperCase() };
    return { status: "invalid" };
}

export { parseStatus };
