import { armor, Encrypter } from "age-encryption";
import { beforeAll, describe, expect, it } from "vitest";

import { ageEncrypt } from "../src/core/ageCipher";
import { decryptArmored } from "../src/core/compose";
import { dearmor, parseStatus, sessionKeyPackets, signatureVerdict } from "../src/core/gpg";
import { encodePayload } from "../src/core/payload";
import { pgpEncrypt } from "../src/core/pgpCipher";
import { ageUser, newGpgHome, pgpUser, rawGpg, type TestUser } from "./helpers";

const TEXT = "Meet at 7. Bring the 🔑 — ünïcödé too.";

describe("age round trips", () => {
    let users: TestUser[];
    beforeAll(async () => {
        users = await Promise.all(Array.from({ length: 10 }, (_, i) => ageUser(`age${i}`)));
    });

    it("two people", async () => {
        const [me, them] = users;
        const armored = await ageEncrypt([me.publicKey, them.publicKey], await encodePayload(TEXT, false));
        for (const u of [me, them]) {
            const r = await decryptArmored("age", armored, u.keys);
            expect(r.text).toBe(TEXT);
            expect(r.signature.status).toBe("not-supported");
        }
    });

    it("ten people, every one can decrypt", async () => {
        const armored = await ageEncrypt(users.map(u => u.publicKey), await encodePayload(TEXT, true));
        for (const u of users) expect((await decryptArmored("age", armored, u.keys)).text).toBe(TEXT);
    });

    it("says clearly when you're not a recipient", async () => {
        const outsider = await ageUser("outsider");
        const armored = await ageEncrypt([users[0].publicKey], await encodePayload(TEXT, false));
        await expect(decryptArmored("age", armored, outsider.keys)).rejects.toMatchObject({ code: "not-recipient" });
        await expect(decryptArmored("age", armored, {})).rejects.toMatchObject({ code: "missing-key" });
    });

    it("reads messages encrypted by plain age (no Cipher framing)", async () => {
        const e = new Encrypter();
        e.addRecipient(users[1].publicKey);
        const armored = armor.encode(await e.encrypt("hand made"));
        expect((await decryptArmored("age", armored, users[1].keys)).text).toBe("hand made");
    });

    it("rejects tampered ciphertext", async () => {
        const armored = await ageEncrypt([users[0].publicKey], await encodePayload(TEXT, false));
        const lines = armored.trim().split("\n");
        const i = lines.length - 2;
        lines[i] = (lines[i][0] === "A" ? "B" : "A") + lines[i].slice(1);
        await expect(decryptArmored("age", lines.join("\n"), users[0].keys)).rejects.toMatchObject({ code: expect.stringMatching(/decrypt-failed|malformed/) });
    });
});

describe("PGP via GnuPG: round trips and signatures", () => {
    let users: TestUser[];
    beforeAll(async () => {
        users = await Promise.all(Array.from({ length: 10 }, (_, i) => pgpUser(`pgp${i}`)));
    }, 120_000);

    it("two people, signed, signature valid", async () => {
        const [me, them] = users;
        const armored = await pgpEncrypt(me.engine!, [me.publicKey, them.publicKey], await encodePayload(TEXT, false), me.fingerprint);
        for (const u of [me, them]) {
            const r = await decryptArmored("pgp", armored, u.keys, [me.publicKey]);
            expect(r.text).toBe(TEXT);
            expect(r.signature).toEqual({ status: "valid", signerFingerprint: me.fingerprint });
        }
    });

    it("ten people, every one can decrypt", async () => {
        const armored = await pgpEncrypt(users[0].engine!, users.map(u => u.publicKey), await encodePayload(TEXT, true), users[0].fingerprint);
        for (const u of users) {
            const r = await decryptArmored("pgp", armored, u.keys, [users[0].publicKey]);
            expect(r.text).toBe(TEXT);
            expect(r.signature.status).toBe("valid");
        }
    }, 120_000);

    it("reports unsigned and unknown-signer messages", async () => {
        const [a, b, c] = users;
        const unsigned = await pgpEncrypt(a.engine!, [b.publicKey], await encodePayload(TEXT, false));
        const r0 = await decryptArmored("pgp", unsigned, b.keys, [a.publicKey]);
        expect(r0).toMatchObject({ text: TEXT, signature: { status: "unsigned" } });

        const signedByC = await pgpEncrypt(c.engine!, [b.publicKey], await encodePayload(TEXT, false), c.fingerprint);
        const r = await decryptArmored("pgp", signedByC, b.keys, [a.publicKey]);
        expect(r.signature.status).toBe("unknown-signer");
        expect(r.text).toBe(TEXT);
        // With c's key available the signer is identified, so the UI can say "signed by c, posted by a".
        const r2 = await decryptArmored("pgp", signedByC, b.keys, [a.publicKey, c.publicKey]);
        expect(r2.signature).toEqual({ status: "valid", signerFingerprint: c.fingerprint });
    });

    it("never consults the recipient's own keyring for signers", async () => {
        const [a, b] = users;
        // Put a's key into b's GnuPG keyring: signature checks must still only use the keys Cipher passes.
        rawGpg((b.engine as any).opts.homedir, ["--import"], a.publicKey);
        const signed = await pgpEncrypt(a.engine!, [b.publicKey], await encodePayload(TEXT, false), a.fingerprint);
        expect((await decryptArmored("pgp", signed, b.keys, [])).signature.status).toBe("unknown-signer");
    });

    it("reads signature verdicts from real gpgv status output", () => {
        const good = parseStatus([
            "[GNUPG:] PLAINTEXT 62 1795602724 ", "[GNUPG:] NEWSIG",
            "[GNUPG:] GOODSIG 8899AABBCCDDEEFF bob (Cipher test)",
            "[GNUPG:] VALIDSIG DEADBEEF00112233445566778899AABBCCDDEEFF 2026-11-25 1795602724 0 4 0 22 10 00 DEADBEEF00112233445566778899AABBCCDDEEFF"
        ].join("\n"));
        expect(signatureVerdict(good)).toEqual({ status: "valid", signerFingerprint: "DEADBEEF00112233445566778899AABBCCDDEEFF" });
        const bad = parseStatus("[GNUPG:] NEWSIG\n[GNUPG:] BADSIG 8899AABBCCDDEEFF bob (Cipher test)");
        expect(signatureVerdict(bad)).toEqual({ status: "invalid" });
        const unknown = parseStatus("[GNUPG:] NEWSIG\n[GNUPG:] ERRSIG 8899AABBCCDDEEFF 22 10 00 1795602724 9 DEADBEEF00112233445566778899AABBCCDDEEFF\n[GNUPG:] NO_PUBKEY 8899AABBCCDDEEFF");
        expect(signatureVerdict(unknown)).toEqual({ status: "unknown-signer", signerKeyId: "8899AABBCCDDEEFF" });
        const expired = parseStatus([...good.map(s => "[GNUPG:] " + s.join(" ")), "[GNUPG:] EXPKEYSIG 8899AABBCCDDEEFF bob"].join("\n"));
        expect(signatureVerdict(expired)).toMatchObject({ status: "valid", keyWarning: "expired" });
        const twoSigs = parseStatus("[GNUPG:] NEWSIG\n[GNUPG:] NEWSIG\n" + good.slice(2).map(s => "[GNUPG:] " + s.join(" ")).join("\n"));
        expect(signatureVerdict(twoSigs)).toEqual({ status: "invalid" });
    });

    it("says clearly when you're not a recipient", async () => {
        const outsider = await pgpUser("outsider");
        const armored = await pgpEncrypt(users[0].engine!, [users[0].publicKey], await encodePayload(TEXT, false));
        await expect(decryptArmored("pgp", armored, outsider.keys)).rejects.toMatchObject({ code: "not-recipient" });
    });

    it("refuses passphrase-only messages instead of prompting", async () => {
        const { home } = newGpgHome();
        const sym = rawGpg(home, ["--armor", "--symmetric", "--passphrase", "x"], "hi").stdout.toString();
        await expect(decryptArmored("pgp", sym, users[0].keys)).rejects.toMatchObject({ code: "not-recipient" });
    });

    it("refuses a message that also carries a passphrase, even one it could decrypt", async () => {
        // gpg falls back to the passphrase when the public-key packet doesn't work,
        // so the sender of such a message could make GnuPG open a prompt.
        const u = users[3];
        const { home } = newGpgHome();
        rawGpg(home, ["--import"], u.publicKey);
        const mixed = rawGpg(home, ["--armor", "--trust-model", "always", "--passphrase", "x", "--recipient", u.fingerprint!, "--symmetric", "--encrypt"], "hi").stdout.toString();
        expect(sessionKeyPackets(dearmor(mixed))).toEqual({ publicKey: 1, passphrase: 1 });
        await expect(decryptArmored("pgp", mixed, u.keys)).rejects.toMatchObject({ code: "not-recipient" });
    });

    it("counts session-key packets in new and old header formats", () => {
        const pkt = (tag: number, body: number[]) => [0xC0 | tag, body.length, ...body];
        const oldPkt = (tag: number, body: number[]) => [0x80 | (tag << 2), body.length, ...body];
        const data = (...p: number[][]) => Uint8Array.from(p.flat());
        // A v3 public-key session-key body: version 3, 8-byte key ID, algorithm, then key material.
        const v3 = (id: number) => [3, 0, 0, 0, 0, 0, 0, 0, id, 18, 0xAA];
        expect(sessionKeyPackets(data(pkt(1, v3(1)), pkt(1, v3(2)), pkt(18, [9, 9])))).toEqual({ publicKey: 2, passphrase: 0 });
        expect(sessionKeyPackets(data(oldPkt(1, v3(1)), oldPkt(3, [2]), oldPkt(9, [0])))).toEqual({ publicKey: 1, passphrase: 1 });
        expect(sessionKeyPackets(data(pkt(10, [0x50, 0x47, 0x50]), pkt(3, [1]), pkt(18, [])))).toEqual({ publicKey: 0, passphrase: 1 });
        // Truncated or malformed headers are refused, never skipped past.
        expect(() => sessionKeyPackets(data([0xC1, 5, 1]))).toThrow();
        expect(() => sessionKeyPackets(data([0x01, 0x02]))).toThrow();
        expect(() => sessionKeyPackets(data([0xC1]))).toThrow();
        expect(() => sessionKeyPackets(data([0xC3, 0xE1, 0]))).toThrow();
        for (let n = 0; n < 2000; n++) {
            const junk = Uint8Array.from({ length: Math.floor(Math.random() * 12) }, () => Math.floor(Math.random() * 256));
            try { sessionKeyPackets(junk); } catch (e) { expect((e as { code?: string; }).code).toBe("decrypt-failed"); }
        }
    });

    it("reads a message made by plain gpg without compression, and refuses a compressed one", async () => {
        const u = users[3];
        const { home } = newGpgHome();
        rawGpg(home, ["--import"], u.publicKey);
        const make = (extra: string[]) => rawGpg(home, ["--armor", "--trust-model", "always", ...extra, "--recipient", u.fingerprint!, "--encrypt"], "from gpg").stdout.toString();
        expect((await decryptArmored("pgp", make(["--compress-algo", "none"]), u.keys)).text).toBe("from gpg");
        // gpg's default compresses: refused before GnuPG decompresses anything.
        await expect(decryptArmored("pgp", make([]), u.keys)).rejects.toMatchObject({ code: "compressed-pgp" });
    });

    it("refuses an expired recipient key at encryption time", async () => {
        const { home, engine } = newGpgHome();
        rawGpg(home, ["--faked-system-time", "20200101T000000", "--quick-gen-key", "old (test)", "future-default", "default", "1d"]);
        const [k] = await engine.listSecretKeys();
        const expired = await engine.exportPublicKey(k.fingerprint);
        await expect(pgpEncrypt(users[0].engine!, [expired], await encodePayload(TEXT, false))).rejects.toMatchObject({ code: "invalid-key" });
    });
});
