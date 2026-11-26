import { describe, expect, it } from "vitest";

import { ageEncrypt } from "../src/core/ageCipher";
import { decryptArmored } from "../src/core/compose";
import { CipherError, safeMessage } from "../src/core/errors";
import { inspectPasted } from "../src/core/keys";
import { decodePayload, deflate, encodePayload, MAX_PLAINTEXT_BYTES } from "../src/core/payload";
import { pgpDecrypt, pgpEncrypt } from "../src/core/pgpCipher";
import { unsealIdentity } from "../src/core/vault";
import { ageUser, newGpgHome, pgpUser, rawGpg } from "./helpers";

const SECRET = "the launch code is 0000";

async function captureError(p: Promise<unknown>): Promise<unknown> {
    try {
        await p;
    } catch (e) {
        return e;
    }
    throw new Error("expected rejection");
}

function assertClean(err: unknown, ...forbidden: string[]) {
    expect(err).toBeInstanceOf(CipherError);
    const e = err as CipherError;
    const all = `${e.message}\n${e.stack ?? ""}\n${JSON.stringify(e)}\n${safeMessage(e)}`;
    for (const f of forbidden) expect(all).not.toContain(f);
}

describe("no plaintext or key material in errors", () => {
    it("age decryption failures", async () => {
        const a = await ageUser("a");
        const b = await ageUser("b");
        const armored = await ageEncrypt([a.publicKey], await encodePayload(SECRET, false));
        const err = await captureError(decryptArmored("age", armored, b.keys));
        assertClean(err, SECRET, b.keys.ageIdentity!, a.publicKey);
    });

    it("PGP decryption failures", async () => {
        const a = await pgpUser("a");
        const b = await pgpUser("b");
        const armored = await pgpEncrypt(a.engine!, [a.publicKey], await encodePayload(SECRET, false));
        const err = await captureError(decryptArmored("pgp", armored, b.keys));
        assertClean(err, SECRET, "PRIVATE KEY", "[GNUPG:]", "gpg:");
    });

    it("pasting a private key", async () => {
        const a = await pgpUser("a");
        const secret = await a.engine!.exportSecretKey(a.fingerprint!);
        const err = await captureError(inspectPasted(secret));
        assertClean(err, "PRIVATE KEY BLOCK", secret.split("\n")[3]);
    });

    it("wrong passphrase", async () => {
        const err = await captureError(unsealIdentity({ v: 2, public: {}, sealed: "garbage that is not armor" }, "hunter2hunter2"));
        assertClean(err, "hunter2hunter2", "garbage");
    });

    it("unknown errors become a generic message", () => {
        expect(safeMessage(new Error(SECRET))).not.toContain(SECRET);
    });
});

describe("payload framing", () => {
    it("round-trips with and without compression", async () => {
        for (const c of [false, true]) expect(await decodePayload(await encodePayload("héllo ".repeat(50), c))).toBe("héllo ".repeat(50));
    });

    it("refuses decompression bombs", async () => {
        const bomb = await deflate(new Uint8Array(MAX_PLAINTEXT_BYTES + 10));
        const framed = new Uint8Array([0xC1, 0x43, 0x50, 0x01, 1, ...bomb]);
        await expect(decodePayload(framed)).rejects.toMatchObject({ code: "too-large" });
    });

    it("refuses PGP compression bombs (signed and unsigned) before inflating them", async () => {
        const victim = await pgpUser("victim");
        const attacker = newGpgHome();
        const attackerFpr = await attacker.engine.generateKey("attacker (test)");
        rawGpg(attacker.home, ["--import"], victim.publicKey);
        // 16 MiB of zeros compresses to a few KiB: small enough to post in chat.
        const zeros = new Uint8Array(16 * 1024 * 1024);
        for (const sign of [false, true]) {
            const armored = rawGpg(attacker.home, [
                "--armor", "--trust-model", "always", "--compress-algo", "zlib", "--compress-level", "9",
                "--recipient", victim.fingerprint!, ...sign ? ["--sign", "--local-user", attackerFpr] : [], "--encrypt"
            ], zeros).stdout.toString();
            expect(armored.length).toBeLessThan(200_000);
            // Refused before anything is decompressed: compressed data never reaches GnuPG's inflater.
            await expect(pgpDecrypt(victim.engine!, armored, [])).rejects.toMatchObject({ code: "compressed-pgp" });
        }
    }, 120_000);

    it("rejects unknown flags and invalid UTF-8", async () => {
        await expect(decodePayload(new Uint8Array([0xC1, 0x43, 0x50, 0x01, 0x80, 65]))).rejects.toMatchObject({ code: "malformed" });
        await expect(decodePayload(new Uint8Array([0xFF, 0xFE]))).rejects.toMatchObject({ code: "not-text" });
    });
});
