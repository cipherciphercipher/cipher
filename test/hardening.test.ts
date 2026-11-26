import { beforeAll, describe, expect, it } from "vitest";

import { ageEncrypt, ageStanzaCount, MAX_AGE_STANZAS } from "../src/core/ageCipher";
import { decryptArmored } from "../src/core/compose";
import { isSupportedGpgVersion } from "../src/core/gpg";
import { encodePayload } from "../src/core/payload";
import { pgpAddressedTo, pgpEncrypt } from "../src/core/pgpCipher";
import { dearmorPgp, readSessionKeys } from "../src/core/pgpPackets";
import { ageUser, newGpgHome, pgpUser, rawGpg, type TestUser } from "./helpers";

describe("PGP messages are read in JavaScript before GnuPG sees them", () => {
    let alice: TestUser, bob: TestUser;
    beforeAll(async () => {
        [alice, bob] = await Promise.all([pgpUser("alice"), pgpUser("bob")]);
    }, 60_000);

    it("finds the key IDs a message is for, without GnuPG", async () => {
        const armored = await pgpEncrypt(alice.engine!, [alice.publicKey, bob.publicKey], await encodePayload("hi", false));
        const s = readSessionKeys(dearmorPgp(armored));
        expect(s.publicKey).toBe(2);
        expect(s.anonymous).toBe(0);
        expect(s.keyIds.sort()).toEqual([...alice.info.keyIds, ...bob.info.keyIds].filter(id => s.keyIds.includes(id)).sort());
        expect(pgpAddressedTo(armored, alice.info.keyIds)).toBe("yes");
        expect(pgpAddressedTo(armored, ["0123456789ABCDEF"])).toBe("no");
    });

    it("reports hidden recipients separately, so they need a click", async () => {
        const { home } = newGpgHome();
        rawGpg(home, ["--import"], alice.publicKey);
        const hidden = rawGpg(home, ["--armor", "--trust-model", "always", "--compress-algo", "none", "--hidden-recipient", alice.fingerprint!, "--encrypt"], "secret").stdout.toString();
        expect(readSessionKeys(dearmorPgp(hidden)).anonymous).toBe(1);
        expect(pgpAddressedTo(hidden, alice.info.keyIds)).toBe("hidden");
        // When asked, it still decrypts.
        expect((await decryptArmored("pgp", hidden, alice.keys)).text).toBe("secret");
    });

    it("says no for passphrase messages and refuses junk", () => {
        const { home } = newGpgHome();
        const sym = rawGpg(home, ["--armor", "--symmetric", "--passphrase", "x"], "hi").stdout.toString();
        expect(pgpAddressedTo(sym, alice.info.keyIds)).toBe("no");
        expect(() => pgpAddressedTo("-----BEGIN PGP MESSAGE-----\n\n!!!!\n-----END PGP MESSAGE-----", alice.info.keyIds)).toThrow();
        expect(() => pgpAddressedTo("-----BEGIN PGP MESSAGE-----\n\nwcBMA\n", alice.info.keyIds)).toThrow();
    });

    it("refuses messages with dozens of session-key packets", () => {
        const pkesk = [0xC1, 10, 3, 1, 2, 3, 4, 5, 6, 7, 8, 18];
        const many = Uint8Array.from(Array.from({ length: 40 }, () => pkesk).flat());
        expect(() => readSessionKeys(many)).toThrow();
        expect(readSessionKeys(many.subarray(0, pkesk.length * 10)).publicKey).toBe(10);
    });

    it("reads v6 session-key packets", () => {
        const fpr4 = Array.from({ length: 20 }, (_, i) => i + 1);
        const v6 = [0xC1, 3 + 20 + 1, 6, 21, 4, ...fpr4, 18];
        expect(readSessionKeys(Uint8Array.from(v6)).keyIds).toEqual(["0D0E0F1011121314"]);
        expect(readSessionKeys(Uint8Array.from([0xC1, 3, 6, 0, 18])).anonymous).toBe(1);
    });

    it("never throws anything but a parse error on random input", () => {
        for (let n = 0; n < 3000; n++) {
            const junk = Uint8Array.from({ length: Math.floor(Math.random() * 40) }, () => Math.floor(Math.random() * 256));
            try { readSessionKeys(junk); } catch (e) { expect((e as Error).name).toBe("PacketError"); }
        }
    });
});

describe("age messages with too many recipient stanzas", () => {
    it("are refused before trying any key", async () => {
        const u = await ageUser("u");
        const armored = await ageEncrypt([u.publicKey], await encodePayload("hi", false));
        expect((await decryptArmored("age", armored, u.keys)).text).toBe("hi");

        // Forge a header with many stanzas (the MAC check would fail later anyway).
        const stanza = "-> X25519 " + "A".repeat(43) + "\n" + "B".repeat(43) + "\n";
        const head = "age-encryption.org/v1\n" + stanza.repeat(MAX_AGE_STANZAS + 1) + "--- " + "C".repeat(43) + "\n";
        expect(ageStanzaCount(new TextEncoder().encode(head))).toBe(MAX_AGE_STANZAS + 1);
        const forged = "-----BEGIN AGE ENCRYPTED FILE-----\n" + btoa(head + "payload").match(/.{1,64}/g)!.join("\n") + "\n-----END AGE ENCRYPTED FILE-----\n";
        await expect(decryptArmored("age", forged, u.keys)).rejects.toMatchObject({ code: "malformed" });
    });
});

describe("GnuPG version floor", () => {
    it("refuses releases with known status-line spoofing bugs", () => {
        expect(isSupportedGpgVersion([2, 2, 0])).toBe(false);
        expect(isSupportedGpgVersion([2, 2, 35])).toBe(false);
        expect(isSupportedGpgVersion([2, 2, 36])).toBe(true);
        expect(isSupportedGpgVersion([2, 3, 6])).toBe(false);
        expect(isSupportedGpgVersion([2, 3, 7])).toBe(true);
        expect(isSupportedGpgVersion([2, 4, 0])).toBe(true);
        expect(isSupportedGpgVersion([2, 5, 22])).toBe(true);
        expect(isSupportedGpgVersion([1, 4, 23])).toBe(false);
        expect(isSupportedGpgVersion([3, 0, 0])).toBe(true);
    });
});
