import { writeFileSync } from "node:fs";
import { join } from "node:path";

import { beforeAll, describe, expect, it } from "vitest";

import { checkPgpPublicKey } from "../server/src/validate";
import { decryptArmored } from "../src/core/compose";
import { inspectKey } from "../src/core/keys";
import { pgpDecrypt, pgpEncrypt } from "../src/core/pgpCipher";
import { checkInnerShape, checkMessageShape, checkPublicKeyShape, dearmorPgp } from "../src/core/pgpPackets";
import { encodePayload } from "../src/core/payload";
import { newGpgHome, pgpUser, rawGpg, type TestUser } from "./helpers";

/* Everything here runs in throwaway GnuPG homes. */

const armorAs = (home: string, bin: Uint8Array, kind: "PUBLIC KEY BLOCK" | "MESSAGE") =>
    rawGpg(home, ["--enarmor"], bin).stdout.toString().replace(/ARMORED FILE/g, kind).replace(/^Comment:.*\n/m, "");

let alice: TestUser;
let home: string;
beforeAll(async () => {
    alice = await pgpUser("alice-shape");
    home = newGpgHome().home;
    rawGpg(home, ["--import"], alice.publicKey);
}, 60_000);

describe("keys are checked in JavaScript before GnuPG parses them", () => {
    it("refuses a key carrying a photo ID (user attribute) everywhere", async () => {
        const bin = rawGpg(home, ["--dearmor"], alice.publicKey).stdout;
        // Control: the key itself passes.
        expect(() => checkPublicKeyShape(bin)).not.toThrow();
        // A user attribute packet (tag 17, new format) with a tiny fake image subpacket.
        const photo = Buffer.concat([bin, Buffer.from([0xD1, 6, 5, 1, 0x10, 0, 1, 0xFF])]);
        const armored = armorAs(home, photo, "PUBLIC KEY BLOCK");
        expect(() => checkPublicKeyShape(dearmorPgp(armored))).toThrow("photo ID");
        await expect(inspectKey("pgp", armored, Date.now(), alice.engine)).rejects.toMatchObject({ code: "invalid-key" });
        // The engine itself refuses before running gpg, and so does the server.
        await expect(alice.engine!.inspect(armored)).rejects.toMatchObject({ code: "invalid-key" });
        await expect(checkPgpPublicKey(armored)).rejects.toThrow();
        // Encrypting to it or using it to check signatures never hands it to gpg either.
        await expect(pgpEncrypt(alice.engine!, [armored], await encodePayload("x", false))).rejects.toMatchObject({ code: "invalid-key" });
    });

    it("refuses secret, trust and literal packets, partial lengths and oversize keys", () => {
        const bin = rawGpg(home, ["--dearmor"], alice.publicKey).stdout;
        for (const extra of [[0xC5, 1, 4], [0xCC, 1, 0], [0xCB, 3, 0x62, 0, 0], [0xCD, 0xE1, 0, 0]])
            expect(() => checkPublicKeyShape(Buffer.concat([bin, Buffer.from(extra)])), JSON.stringify(extra)).toThrow();
        expect(() => checkPublicKeyShape(new Uint8Array(70 * 1024))).toThrow();
        expect(() => checkPublicKeyShape(Buffer.concat([bin, bin]))).toThrow("more than one key");
    });
});

describe("messages are checked in JavaScript before GnuPG decrypts them", () => {
    let good: string;
    beforeAll(async () => {
        good = await pgpEncrypt(alice.engine!, [alice.publicKey], await encodePayload("shape", false));
    });

    it("accepts Cipher's own messages", async () => {
        expect(() => checkMessageShape(dearmorPgp(good))).not.toThrow();
        expect((await decryptArmored("pgp", good, alice.keys)).text).toBe("shape");
    });

    it("refuses anything appended after the encrypted packet, without running GnuPG", async () => {
        const bin = dearmorPgp(good);
        for (const tail of [[0xCB, 3, 0x62, 0, 0], [0xC8, 2, 1, 0], [0xC2, 1, 4]]) {
            const bad = armorAs(home, Buffer.concat([bin, Buffer.from(tail)]), "MESSAGE");
            expect(() => checkMessageShape(dearmorPgp(bad))).toThrow();
            await expect(pgpDecrypt(alice.engine!, bad, [])).rejects.toMatchObject({ code: "decrypt-failed" });
        }
    });

    it("refuses messages that aren't session keys then encrypted data", () => {
        const pkesk = [0xC1, 12, 3, 1, 2, 3, 4, 5, 6, 7, 8, 18, 0, 0];
        const seipd = [0xD2, 3, 1, 0, 0];
        expect(() => checkMessageShape(Uint8Array.from([...pkesk, ...seipd]))).not.toThrow();
        expect(() => checkMessageShape(Uint8Array.from(seipd))).toThrow();
        expect(() => checkMessageShape(Uint8Array.from([...pkesk, 0xCB, 3, 0x62, 0, 0]))).toThrow();
        expect(() => checkMessageShape(Uint8Array.from([...pkesk, 0xC3, 2, 4, 9, ...seipd]))).toThrow("passphrase packet");
        expect(() => checkMessageShape(Uint8Array.from([...pkesk, ...seipd, ...seipd]))).toThrow();
    });

    it("lets only literal data and one signature through after decryption", () => {
        const lit = [0xCB, 3, 0x62, 0, 0], ops = [0xC4, 1, 3], sig = [0xC2, 1, 4], comp = [0xC8, 2, 1, 0];
        for (const ok of [lit, [...sig, ...lit], [...ops, ...lit, ...sig]]) expect(() => checkInnerShape(Uint8Array.from(ok))).not.toThrow();
        expect(() => checkInnerShape(Uint8Array.from(comp))).toThrow("compressed");
        expect(() => checkInnerShape(Uint8Array.from([0xA3, 1, 0x78, 0x9C]))).toThrow("compressed");
        for (const bad of [[...lit, ...lit], [...sig, ...sig, ...lit], [...ops, ...lit], sig, [...ops, ...lit, ...sig, ...sig]])
            expect(() => checkInnerShape(Uint8Array.from(bad)), JSON.stringify(bad)).toThrow();
    });
});

describe("gpg.conf can't change what Cipher's gpg calls do", () => {
    it("ignores the user's gpg.conf", async () => {
        const { home: h, engine } = newGpgHome();
        const fpr = await engine.generateKey("conf (test)");
        // Without --no-options, gpg would refuse to start with this file (and could be told
        // to run a photo viewer or use a keyserver).
        writeFileSync(join(h, "gpg.conf"), "this-is-not-an-option\nlist-options show-photos\nphoto-viewer \"calc.exe %i\"\nauto-key-retrieve\n");
        expect(rawGpg(h, ["--list-keys"]).code).not.toBe(0);
        expect((await engine.listSecretKeys()).map(k => k.fingerprint)).toEqual([fpr]);
        const pub = await engine.exportPublicKey(fpr);
        const ct = await pgpEncrypt(engine, [pub], await encodePayload("conf", false), fpr);
        expect((await pgpDecrypt(engine, ct, [pub])).signature.status).toBe("valid");
    }, 60_000);
});
