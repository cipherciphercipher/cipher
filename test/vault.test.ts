import { describe, expect, it } from "vitest";

import { agePassphraseDecrypt, generateAgeIdentity } from "../src/core/ageCipher";
import { utf8Decode } from "../src/core/bytes";
import { type PublicIdentity, type SecretBundle, sealIdentity, unsealIdentity } from "../src/core/vault";

// Low scrypt work factor keeps the tests fast; the plugin uses 18.
const LOG_N = 10;

async function makeIdentity() {
    const age = await generateAgeIdentity();
    const pub: PublicIdentity = { age: { recipient: age.recipient, createdAt: 1 } };
    const secrets: SecretBundle = { age: { identity: age.identity } };
    return { pub, secrets };
}

describe("age key at rest", () => {
    it("seals the secret key with a passphrase and unseals it", async () => {
        const { pub, secrets } = await makeIdentity();
        const stored = await sealIdentity(pub, secrets, "correct horse battery", LOG_N);
        expect(stored.sealed).toContain("BEGIN AGE ENCRYPTED FILE");
        expect(JSON.stringify(stored)).not.toContain(secrets.age!.identity);
        expect(JSON.stringify(stored)).not.toContain("AGE-SECRET-KEY");
        expect(await unsealIdentity(stored, "correct horse battery")).toEqual(secrets);
    });

    it("rejects a wrong passphrase", async () => {
        const { pub, secrets } = await makeIdentity();
        const stored = await sealIdentity(pub, secrets, "correct horse battery", LOG_N);
        await expect(unsealIdentity(stored, "wrong passphrase")).rejects.toMatchObject({ code: "wrong-passphrase" });
    });

    it("rejects short passphrases", async () => {
        const { pub, secrets } = await makeIdentity();
        await expect(sealIdentity(pub, secrets, "short", LOG_N)).rejects.toMatchObject({ code: "weak-passphrase" });
    });

    it("detects a swapped public key", async () => {
        const { pub, secrets } = await makeIdentity();
        const stored = await sealIdentity(pub, secrets, "correct horse battery", LOG_N);
        stored.public.age!.recipient = (await generateAgeIdentity()).recipient;
        await expect(unsealIdentity(stored, "correct horse battery")).rejects.toMatchObject({ code: "key-mismatch" });
    });

    it("sealed data is a standard age file (can be opened with `age -d`)", async () => {
        const { pub, secrets } = await makeIdentity();
        const stored = await sealIdentity(pub, secrets, "correct horse battery", LOG_N);
        const plain = utf8Decode(await agePassphraseDecrypt(stored.sealed, "correct horse battery"));
        expect(JSON.parse(plain)).toEqual(secrets);
    });
});
