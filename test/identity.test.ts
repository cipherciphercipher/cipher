import { describe, expect, it } from "vitest";

import { decryptArmored } from "../src/core/compose";
import { MemoryKV } from "../src/core/contacts";
import { IdentityManager } from "../src/core/identity";
import { encodePayload } from "../src/core/payload";
import { pgpEncrypt } from "../src/core/pgpCipher";
import { newGpgHome, rawGpg } from "./helpers";

const PASS = "a long passphrase";

async function fresh(kv = new MemoryKV(), engine = newGpgHome().engine) {
    const m = new IdentityManager(kv, 10, Date.now, engine);
    await m.load();
    return { m, engine, kv };
}

describe("own age key", () => {
    it("sets the passphrase on first use and needs it afterwards", async () => {
        const { m, kv, engine } = await fresh();
        await expect(m.generateAge("short")).rejects.toMatchObject({ code: "weak-passphrase" });
        await m.generateAge(PASS);
        expect(m.isUnlocked).toBe(true);
        await expect(m.generateAge(PASS)).rejects.toThrow(/already have/);

        const next = (await fresh(kv, engine)).m;
        expect(next.publicIdentity.age?.recipient).toMatch(/^age1/);
        expect(next.isUnlocked).toBe(false);
        expect(next.ageIdentity).toBeUndefined();
        await expect(next.unlock("wrong passphrase")).rejects.toMatchObject({ code: "wrong-passphrase" });
        await next.unlock(PASS);
        expect(next.ageIdentity).toMatch(/^AGE-SECRET-KEY-1/);
        next.lock();
        expect(next.ageIdentity).toBeUndefined();
    });

    it("exports and re-imports an age key", async () => {
        const a = (await fresh()).m;
        await a.generateAge(PASS);
        const exported = await a.exportAge("export pass 1");
        expect(exported).toContain("BEGIN AGE ENCRYPTED FILE");
        const b = (await fresh()).m;
        await expect(b.importAge(exported, PASS)).rejects.toMatchObject({ code: "wrong-passphrase" });
        await b.importAge(exported, PASS, "export pass 1");
        expect(b.publicIdentity.age?.recipient).toBe(a.publicIdentity.age?.recipient);
        const c = (await fresh()).m;
        await c.importAge(a.ageIdentity!, PASS);
        expect(c.publicIdentity.age?.recipient).toBe(a.publicIdentity.age?.recipient);
    });

    it("deleting the age key removes the vault", async () => {
        const { m, kv, engine } = await fresh();
        await m.generateAge(PASS);
        await m.removeAge(PASS);
        expect(m.has("age")).toBe(false);
        expect((await fresh(kv, engine)).m.has("age")).toBe(false);
    });
});

describe("own PGP key in GnuPG", () => {
    it("lists GnuPG keys, uses one, and decrypts with it; no Cipher passphrase involved", async () => {
        const { m, engine, kv } = await fresh();
        expect(await m.gnupgKeys()).toEqual([]);
        await m.createPgpKey("me");
        const pgp = m.publicIdentity.pgp!;
        expect(pgp.fingerprint).toMatch(/^[0-9A-F]{40}$/);
        expect(pgp.publicKey).toContain("BEGIN PGP PUBLIC KEY BLOCK");
        expect(m.needsPassphrase).toBe(false);
        await m.unlock();
        expect(m.isUnlocked).toBe(true);

        const armored = await pgpEncrypt(engine, [pgp.publicKey], await encodePayload("hello", false), pgp.fingerprint);
        const r = await decryptArmored("pgp", armored, { pgp: engine }, [pgp.publicKey]);
        expect(r).toMatchObject({ text: "hello", signature: { status: "valid", signerFingerprint: pgp.fingerprint } });

        // Persisted: only the public selection, never secret material.
        expect(JSON.stringify([...kv.data.values()])).not.toContain("PRIVATE KEY");
        const again = (await fresh(kv, engine)).m;
        expect(again.publicIdentity.pgp?.fingerprint).toBe(pgp.fingerprint);
    });

    it("imports a secret key file into GnuPG and selects it", async () => {
        const src = newGpgHome();
        const fpr = await src.engine.generateKey("old key (test)");
        const secret = await src.engine.exportSecretKey(fpr);
        const { m } = await fresh();
        await m.importPgpKey(secret);
        expect(m.publicIdentity.pgp?.fingerprint).toBe(fpr);
        expect(await m.exportPgp()).toContain("BEGIN PGP PRIVATE KEY BLOCK");
    });

    it("won't use keys that can't sign and encrypt", async () => {
        const { m, engine } = await fresh();
        rawGpg((engine as any).opts.homedir, ["--quick-gen-key", "signonly (test)", "ed25519", "sign", "never"]);
        const [k] = await m.gnupgKeys();
        expect(k.usable).toBe(false);
        await expect(m.usePgpKey(k.fingerprint)).rejects.toMatchObject({ code: "invalid-key" });
    });

    it("forgetting the PGP key leaves it in GnuPG", async () => {
        const { m } = await fresh();
        await m.createPgpKey("me");
        const fpr = m.publicIdentity.pgp!.fingerprint;
        await m.forgetPgp();
        expect(m.has("pgp")).toBe(false);
        expect((await m.gnupgKeys()).map(k => k.fingerprint)).toContain(fpr);
    });

    it("never passes a user ID gpg could read as an option", async () => {
        const { m, engine } = await fresh();
        await expect(engine.generateKey("--homedir=elsewhere")).rejects.toMatchObject({ code: "invalid-input" });
        await expect(engine.generateKey("  -x")).rejects.toMatchObject({ code: "invalid-input" });
        // The UI path strips leading dashes from the name instead of failing.
        await m.createPgpKey("--evil name");
        expect((await m.gnupgKeys())[0].userIds).toEqual(["evil name (Cipher)"]);
    });

    it("holds an age key and a PGP key at the same time", async () => {
        const { m } = await fresh();
        await m.generateAge(PASS);
        await m.createPgpKey("me");
        expect(m.has("age") && m.has("pgp")).toBe(true);
        expect(m.needsPassphrase).toBe(true);
    });
});
