import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { afterAll, describe, expect, it } from "vitest";

import { primaryKeyBody, verifyPrimarySignature } from "../server/src/pgpVerify";
import { utf8Encode } from "../src/core/bytes";
import { GpgEngine, parseKeyInfo } from "../src/core/gpg";
import { ageChallengeText, isProofStatementFor, proofStatement, readAgeChallenge } from "../src/core/keyProof";
import { gpgPaths, pgpUser } from "./helpers";

/* All GnuPG work here uses throwaway homes; the user's own GnuPG is never touched. */

const USER = "80351110224678912";
const ticketFor = (fpr: string, type = "pgp") => `p1.${USER}.${type}.${fpr}.${Date.now() + 60_000}.${"A".repeat(22)}.${"B".repeat(43)}`;

describe("key-proof formats", () => {
    it("answers only a real challenge for this very ticket", () => {
        const t = ticketFor("C".repeat(64), "age");
        const nonce = "n".repeat(43);
        expect(readAgeChallenge(ageChallengeText(t, nonce), t)).toBe(nonce);
        // A server can't use the challenge to get other messages decrypted for it.
        for (const plain of ["hello", ageChallengeText(t, nonce) + "more", ageChallengeText(ticketFor("D".repeat(64), "age"), nonce), `Cipher key proof v1\nticket: ${t}\nnonce: short\n`])
            expect(readAgeChallenge(plain, t), plain).toBeNull();
    });

    it("lets GnuPG sign only a statement naming the signing key", () => {
        const fpr = "E".repeat(40), other = "F".repeat(40);
        const st = proofStatement("https://cipher.example", USER, fpr, ticketFor(fpr));
        expect(isProofStatementFor(st, fpr)).toBe(true);
        expect(isProofStatementFor(proofStatement("http://localhost:8787", USER, fpr, ticketFor(fpr)), fpr)).toBe(true);
        for (const bad of [
            st.replace(fpr, other), st + "x", "x" + st, st.replace("\n", "\r\n"),
            proofStatement("https://cipher.example", USER, fpr, ticketFor(other)),
            proofStatement("https://cipher.example", USER, fpr, ticketFor("C".repeat(64), "age")),
            proofStatement("https://cipher.example", "80351110224678999", fpr, ticketFor(fpr)),
            proofStatement("http://evil.example", USER, fpr, ticketFor(fpr)),
            proofStatement("https://cipher.example\nuser: 1", USER, fpr, ticketFor(fpr))
        ]) expect(isProofStatementFor(bad, fpr), bad).toBe(false);
        expect(isProofStatementFor(st, other)).toBe(false);
    });
});

describe("GnuPG: proof signatures", () => {
    it("signs a proof with the primary key, and nothing else", async () => {
        const u = await pgpUser("prover");
        const other = await pgpUser("other");
        const fpr = u.fingerprint!;
        const st = proofStatement("https://cipher.example", USER, fpr, ticketFor(fpr));
        const sig = await u.engine!.signProof(fpr, st);
        expect(await verifyPrimarySignature(primaryKeyBody(u.publicKey)!, sig, utf8Encode(st), Date.now())).toBe(true);
        expect(await verifyPrimarySignature(primaryKeyBody(other.publicKey)!, sig, utf8Encode(st), Date.now())).toBe(false);
        expect(await verifyPrimarySignature(primaryKeyBody(u.publicKey)!, sig, utf8Encode(st + " "), Date.now())).toBe(false);
        for (const bad of ["hello", st.replace(fpr, other.fingerprint!), proofStatement("https://cipher.example", USER, fpr, ticketFor(other.fingerprint!))])
            await expect(u.engine!.signProof(fpr, bad), bad).rejects.toMatchObject({ code: "invalid-input" });
        // A key that isn't in this GnuPG can't sign.
        const st2 = proofStatement("https://cipher.example", USER, other.fingerprint!, ticketFor(other.fingerprint!));
        await expect(u.engine!.signProof(other.fingerprint!, st2)).rejects.toThrow();
    }, 60_000);
});

describe("GnuPG: passphrase check and forgetting the cached passphrase", () => {
    const homes: string[] = [];
    const gpgconf = join(dirname(gpgPaths.gpg), "gpgconf" + (process.platform === "win32" ? ".exe" : ""));
    afterAll(() => {
        for (const h of homes) {
            spawnSync(gpgconf, ["--homedir", h, "--kill", "all"], { windowsHide: true });
            rmSync(h, { recursive: true, force: true });
        }
    });
    const gpg = (home: string, args: string[], input?: string) =>
        spawnSync(gpgPaths.gpg, ["--homedir", home, "--batch", "--no-tty", ...args], { input, windowsHide: true });

    it("parses gpg-agent KEYINFO lines", () => {
        const g = "0123456789ABCDEF0123456789ABCDEF01234567";
        const info = parseKeyInfo(`S KEYINFO ${g} D - - 1 P - - -\nS KEYINFO ${g.toLowerCase().replace("0", "1")} T D2760001 OPENPGP.1 - - - - -\nOK\n`);
        expect(info.get(g)).toEqual({ type: "D", cached: true, protection: "P" });
        expect([...info.values()][1]).toEqual({ type: "T", cached: false, protection: "-" });
        expect(parseKeyInfo("ERR 67108891 Not found <GPG Agent>\nS KEYINFO nothex D - - - P").size).toBe(0);
    });

    it("finds a key without a passphrase", async () => {
        const u = await pgpUser("nopass");
        expect(await u.engine!.keyProtection(u.fingerprint!)).toMatchObject({ state: "unprotected" });
    }, 60_000);

    it("finds a protected key, and makes gpg-agent forget its passphrase", async () => {
        expect(gpgPaths.connectAgent).toBeTruthy();
        const home = mkdtempSync(join(tmpdir(), "cipher-test-gnupg-"));
        homes.push(home);
        const make = gpg(home, ["--pinentry-mode", "loopback", "--passphrase", "correct horse", "--quick-gen-key", "locked (t)", "future-default", "default", "never"]);
        expect(make.status).toBe(0);
        const engine = new GpgEngine({ ...gpgPaths, homedir: home });
        const fpr = (await engine.listSecretKeys())[0].fingerprint;

        // Sign once with the passphrase, so gpg-agent remembers it.
        expect(gpg(home, ["--pinentry-mode", "loopback", "--passphrase", "correct horse", "--detach-sign", "--armor"], "x").status).toBe(0);
        expect(await engine.keyProtection(fpr)).toEqual({ state: "protected", cached: true });
        // Remembered: signing now works without giving the passphrase.
        const noPassphrase = () => gpg(home, ["--pinentry-mode", "error", "--detach-sign", "--armor"], "x").status;
        expect(noPassphrase()).toBe(0);

        await engine.forgetPassphrase(fpr);
        expect(await engine.keyProtection(fpr)).toEqual({ state: "protected", cached: false });
        expect(noPassphrase()).not.toBe(0);
    }, 60_000);
});
