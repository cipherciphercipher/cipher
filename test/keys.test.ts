import { describe, expect, it } from "vitest";

import { AGE_RECIPIENT_RE, generateAgeIdentity } from "../src/core/ageCipher";
import { CipherError } from "../src/core/errors";
import { comparisonCode, detectKey, formatFingerprint, inspectKey, inspectPasted, isUsable } from "../src/core/keys";
import { newGpgHome, pgpUser, rawGpg, readRevocation } from "./helpers";

describe("key generation", () => {
    it("generates a native X25519 age identity", async () => {
        const { identity, recipient } = await generateAgeIdentity();
        expect(identity).toMatch(/^AGE-SECRET-KEY-1[0-9A-Z]{58}$/);
        expect(recipient).toMatch(AGE_RECIPIENT_RE);
    });

    it("creates a Curve25519 GnuPG key, not RSA", async () => {
        const { home, engine } = newGpgHome();
        const fpr = await engine.generateKey("alice (Cipher)");
        const listing = rawGpg(home, ["--with-colons", "--list-keys", fpr]).stdout.toString();
        // pub algo 22 = EdDSA (ed25519), sub algo 18 = ECDH (cv25519)
        expect(listing).toMatch(/^pub:[^:]*:255:22:/m);
        expect(listing).toMatch(/^sub:[^:]*:255:18:.*:cv25519:/m);
        const [key] = await engine.listSecretKeys();
        expect(key).toMatchObject({ fingerprint: fpr, canEncrypt: true, canSign: true, hasSecret: true, revoked: false, expired: false });
        expect(key.userIds).toEqual(["alice (Cipher)"]);
    });
});

describe("detectKey", () => {
    it("auto-detects age and PGP public keys", async () => {
        const { recipient } = await generateAgeIdentity();
        expect(detectKey(`here is my key: ${recipient} thanks`)).toEqual({ kind: "public", type: "age", material: recipient });
        const u = await pgpUser("bob");
        expect(detectKey("blah\n" + u.publicKey + "\nblah")).toMatchObject({ kind: "public", type: "pgp" });
    });

    it("recognises private keys so they can be refused", async () => {
        const { identity } = await generateAgeIdentity();
        expect(detectKey(identity)).toEqual({ kind: "private", type: "age" });
        const u = await pgpUser("bob");
        const secret = await u.engine!.exportSecretKey(u.fingerprint!);
        expect(detectKey(secret)).toEqual({ kind: "private", type: "pgp" });
        await expect(inspectPasted(secret)).rejects.toMatchObject({ code: "private-key-pasted" });
        await expect(inspectPasted(identity)).rejects.toMatchObject({ code: "private-key-pasted" });
    });

    it("rejects garbage and unsupported keys", async () => {
        expect(detectKey("hello world")).toBeNull();
        await expect(inspectPasted("hello")).rejects.toBeInstanceOf(CipherError);
        // Post-quantum keys are supported, but a truncated one isn't a key at all.
        expect(detectKey("age1pq1" + "q".repeat(100))).toBeNull();
        expect(detectKey("age1tag1" + "q".repeat(60))).toMatchObject({ kind: "unsupported" });
        await expect(inspectKey("age", "age1" + "q".repeat(58))).rejects.toMatchObject({ code: "invalid-key" });
        await expect(inspectKey("pgp", "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----")).rejects.toMatchObject({ code: "invalid-key" });
    });
});

describe("PGP key warnings", () => {
    it("flags an expired key", async () => {
        const { home, engine } = newGpgHome();
        rawGpg(home, ["--faked-system-time", "20200101T000000", "--quick-gen-key", "old (test)", "future-default", "default", "1d"]);
        const [k] = await engine.listSecretKeys();
        const info = await inspectKey("pgp", await engine.exportPublicKey(k.fingerprint));
        expect(info.problems).toContain("expired");
        expect(isUsable(info)).toBe(false);
    });

    it("flags a revoked key", async () => {
        const { home, engine } = newGpgHome();
        const fpr = await engine.generateKey("rev (test)");
        rawGpg(home, ["--import"], readRevocation(home, fpr));
        const info = await inspectKey("pgp", await engine.exportPublicKey(fpr));
        expect(info.problems).toContain("revoked");
    });

    it("flags a key with no encryption subkey", async () => {
        const { home, engine } = newGpgHome();
        rawGpg(home, ["--quick-gen-key", "signonly (test)", "ed25519", "sign", "never"]);
        const [k] = await engine.listSecretKeys();
        const info = await inspectKey("pgp", await engine.exportPublicKey(k.fingerprint));
        expect(info.problems).toEqual(["no-encryption-subkey"]);
    });

    it("accepts a healthy key, including RSA", async () => {
        const u = await pgpUser("ok");
        expect(u.info.problems).toEqual([]);
        expect(u.info.userIds[0]).toContain("ok");
        expect(u.info.keyIds.length).toBe(2);

        const { home, engine } = newGpgHome();
        rawGpg(home, ["--quick-gen-key", "rsa (test)", "rsa3072", "cert,sign", "never"]);
        const [k] = await engine.listSecretKeys();
        rawGpg(home, ["--quick-add-key", k.fingerprint, "rsa3072", "encr", "never"]);
        const info = await inspectKey("pgp", await engine.exportPublicKey(k.fingerprint));
        expect(info.problems).toEqual([]);
    }, 120_000);

    it("wants exactly one key", async () => {
        const a = await pgpUser("a");
        const b = await pgpUser("b");
        await expect(inspectKey("pgp", a.publicKey + "\n" + b.publicKey)).rejects.toMatchObject({ code: "invalid-key" });
    });
});

describe("fingerprints and comparison codes", () => {
    it("is stable for a key and differs between keys", async () => {
        const a = await generateAgeIdentity();
        const b = await generateAgeIdentity();
        const ia = await inspectKey("age", a.recipient);
        const ia2 = await inspectKey("age", a.recipient);
        const ib = await inspectKey("age", b.recipient);
        expect(ia.code).toBe(ia2.code);
        expect(ia.code).not.toBe(ib.code);
        expect(ia.code).toMatch(/^\d{5}( \d{5}){5}$/);
        expect(ia.fingerprint).toMatch(/^[0-9A-F]{64}$/);
    });

    it("PGP fingerprints match what GnuPG reports", async () => {
        const u = await pgpUser("fp");
        expect(u.info.fingerprint).toBe(u.fingerprint);
    });

    it("binds the code to the key type", async () => {
        expect(await comparisonCode("age", "AB")).not.toBe(await comparisonCode("pgp", "AB"));
    });

    it("groups fingerprints in fours", () => {
        expect(formatFingerprint("abcdef0123")).toBe("ABCD EF01 23");
    });
});
