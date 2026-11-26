import * as age from "age-encryption";
import { describe, expect, it } from "vitest";

import { AGE_PQ_RECIPIENT_RE, ageEncrypt, ageStanzaCount, generateAgeIdentity, MAX_AGE_STANZAS } from "../src/core/ageCipher";
import { bech32Decode, bech32Encode } from "../src/core/bech32";
import { buildOutgoing, decryptArmored } from "../src/core/compose";
import { MemoryKV } from "../src/core/contacts";
import { DISCORD_CHAR_LIMIT, formatKeyShare, parseContent } from "../src/core/envelope";
import { IdentityManager } from "../src/core/identity";
import { inspectPasted, keyLabel } from "../src/core/keys";
import { encodePayload } from "../src/core/payload";
import { type Candidate, planEncryption } from "../src/core/recipients";

async function pqUser(id: string) {
    const { identity, recipient } = await generateAgeIdentity({ postQuantum: true });
    return { id, identity, recipient };
}

const cand = (userId: string, material: string): Candidate =>
    ({ userId, name: userId, type: "age", material, problems: [], verified: true, pendingKeyChange: false });

describe("post-quantum age keys", () => {
    it("generate, validate and round-trip", async () => {
        const u = await pqUser("1");
        expect(u.identity).toMatch(/^AGE-SECRET-KEY-PQ-1/);
        expect(u.recipient).toMatch(AGE_PQ_RECIPIENT_RE);
        const info = await inspectPasted(u.recipient);
        expect(info.type).toBe("age");
        expect(keyLabel("age", info.material)).toBe("age PQ");
        const armored = await ageEncrypt([u.recipient], await encodePayload("quantum-safe hello", false));
        expect((await decryptArmored("age", armored, { ageIdentity: u.identity })).text).toBe("quantum-safe hello");
    });

    it("our bech32 matches the age library exactly", async () => {
        for (let i = 0; i < 5; i++) {
            const { recipient } = await pqUser(String(i));
            const { hrp, bytes } = bech32Decode(recipient);
            expect(hrp).toBe("age1pq");
            expect(bytes.length).toBe(1216);
            expect(bech32Encode(hrp, bytes)).toBe(recipient);
        }
        const classic = await age.identityToRecipient(await age.generateX25519Identity());
        expect(bech32Encode("age", bech32Decode(classic).bytes)).toBe(classic);
        // A changed character fails the checksum.
        const { recipient } = await pqUser("x");
        const bad = recipient.slice(0, 20) + (recipient[20] === "q" ? "p" : "q") + recipient.slice(21);
        expect(() => bech32Decode(bad)).toThrow();
    });

    it("key shares fit in one Discord message and read back exactly", async () => {
        const u = await pqUser("1");
        const info = await inspectPasted(u.recipient);
        const share = formatKeyShare("age", u.recipient, info.code);
        expect(share.length).toBeLessThanOrEqual(DISCORD_CHAR_LIMIT);
        expect(parseContent(share)).toEqual({ kind: "key", type: "age", material: u.recipient, marked: true });
        // Any 1216 bytes read as some key (like any edited key share would, which is
        // why codes are compared), but a body of the wrong length is rejected.
        expect(parseContent(share.replace(/```\n[A-Za-z0-9+/]{10}/, "```\nAAAAAAAAAA"))).toMatchObject({ kind: "key" });
        expect(parseContent(share.replace(/```\n[A-Za-z0-9+/]{10}/, "```\n"))).toBeNull();
    });

    it("are never mixed with normal age keys in one message", async () => {
        const pq1 = await pqUser("1"), pq2 = await pqUser("2");
        const classic = await generateAgeIdentity();
        const map = new Map([cand("1", pq1.recipient), cand("2", pq2.recipient), cand("3", classic.recipient)].map(c => [c.userId, c]));
        const lookup = (id: string) => map.get(id);

        const mixed = planEncryption({ self: { userId: "me", age: classic.recipient }, selectedIds: ["1", "3"], lookup, allowSplit: false });
        expect(mixed).toMatchObject({ ok: false, error: { code: "mixed-age" } });

        const split = planEncryption({ self: { userId: "me", age: classic.recipient }, selectedIds: ["1", "2", "3"], lookup, allowSplit: true });
        if (!split.ok) throw new Error("expected a plan");
        expect(split.ciphertexts).toHaveLength(2);
        const pqCopy = split.ciphertexts.find(c => c.keys.some(k => k.startsWith("age1pq1")))!;
        // The post-quantum copy holds no normal key, not even the sender's own.
        expect(pqCopy.keys.every(k => k.startsWith("age1pq1"))).toBe(true);
        expect(pqCopy.includesSelf).toBe(false);
        expect(split.warnings).toContainEqual({ code: "self-not-post-quantum" });

        // A post-quantum sender can be in a normal copy: it doesn't weaken it.
        const pqSelf = planEncryption({ self: { userId: "me", age: pq1.recipient }, selectedIds: ["3"], lookup, allowSplit: false });
        if (!pqSelf.ok) throw new Error("expected a plan");
        expect(pqSelf.ciphertexts[0].includesSelf).toBe(true);

        // All post-quantum: one copy, sender included.
        const allPq = planEncryption({ self: { userId: "me", age: pq1.recipient }, selectedIds: ["2"], lookup, allowSplit: false });
        if (!allPq.ok) throw new Error("expected a plan");
        expect(allPq.ciphertexts).toHaveLength(1);
        expect(allPq.ciphertexts[0].keys).toEqual([pq2.recipient, pq1.recipient]);
    });

    it("send and read with 10 post-quantum readers", async () => {
        const users = await Promise.all(Array.from({ length: 10 }, (_, i) => pqUser(String(i))));
        const plan = planEncryption({
            self: { userId: "0", age: users[0].recipient }, selectedIds: users.slice(1).map(u => u.id),
            lookup: id => cand(id, users[Number(id)].recipient), allowSplit: false
        });
        if (!plan.ok) throw new Error("expected a plan");
        const out = await buildOutgoing({ ciphertexts: plan.ciphertexts, text: "to ten", maxMessages: 4 });
        // ~2 KB per post-quantum reader: ten of them go out as an attachment.
        expect(out.kind).toBe("file");
        if (out.kind !== "file") return;
        const armored = out.files[0].content;
        expect(ageStanzaCount(age.armor.decode(armored))).toBeLessThanOrEqual(MAX_AGE_STANZAS);
        for (const u of [users[0], users[9]])
            expect((await decryptArmored("age", armored, { ageIdentity: u.identity })).text).toBe("to ten");
    });

    it("are sealed in the vault like normal keys", async () => {
        const kv = new MemoryKV();
        const m = new IdentityManager(kv, 10);
        await m.generateAge("correct horse", { postQuantum: true });
        expect(m.publicIdentity.age?.recipient).toMatch(AGE_PQ_RECIPIENT_RE);
        const again = new IdentityManager(kv, 10);
        await again.load();
        await again.unlock("correct horse");
        expect(again.ageIdentity).toMatch(/^AGE-SECRET-KEY-PQ-1/);
        await expect(new IdentityManager(kv, 10).load().then(async () => { const x = new IdentityManager(kv, 10); await x.load(); await x.unlock("wrong pass"); })).rejects.toBeTruthy();
    });
});
