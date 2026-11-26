import { beforeAll, describe, expect, it } from "vitest";

import { buildOutgoing, decryptArmored } from "../src/core/compose";
import { attachmentHeader, DISCORD_CHAR_LIMIT, fileNotice, formatKeyShare, isPureCipherContent, parseAttachmentName, parseContent, reassemble, splitArmored } from "../src/core/envelope";
import { planEncryption } from "../src/core/recipients";
import { ageUser, lookupOf, newGpgHome, pgpUser, randomText, type TestUser } from "./helpers";

function partsOf(messages: string[]) {
    return messages.map(m => {
        const p = parseContent(m);
        if (p?.kind !== "part") throw new Error("not a part: " + m.slice(0, 80));
        return p;
    });
}

function shuffle<T>(a: T[]): T[] {
    return a.map(v => [Math.random(), v] as const).sort((x, y) => x[0] - y[0]).map(x => x[1]);
}

describe("envelope format", () => {
    it("splits armor into parts that each fit and reassemble in any order", () => {
        const armored = "-----BEGIN AGE ENCRYPTED FILE-----\n" + Array.from({ length: 120 }, () => "A".repeat(64)).join("\n") + "\nAAAA\n-----END AGE ENCRYPTED FILE-----\n";
        const msgs = splitArmored(armored, { type: "age", ref: "abcd1234", limit: DISCORD_CHAR_LIMIT });
        expect(msgs.length).toBeGreaterThan(3);
        for (const m of msgs) expect(m.length).toBeLessThanOrEqual(DISCORD_CHAR_LIMIT);
        const r = reassemble(shuffle(partsOf(msgs)));
        expect(r).toEqual({ armored });
    });

    it("randomized: every part fits the limit and parts rejoin exactly", () => {
        const b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (let round = 0; round < 300; round++) {
            const count = 1 + Math.floor(Math.random() * 400);
            const line = (n: number) => Array.from({ length: n }, () => b64[Math.floor(Math.random() * 64)]).join("");
            const lines = Array.from({ length: count }, (_, i) => line(i === count - 1 ? 4 * (1 + Math.floor(Math.random() * 16)) : 64));
            const type = Math.random() < 0.5 ? "age" : "pgp";
            const armored = type === "age"
                ? `-----BEGIN AGE ENCRYPTED FILE-----\n${lines.join("\n")}\n-----END AGE ENCRYPTED FILE-----\n`
                : `-----BEGIN PGP MESSAGE-----\n\n${lines.join("\n")}\n-----END PGP MESSAGE-----\n`;
            const limit = 200 + Math.floor(Math.random() * 1790);
            const msgs = splitArmored(armored, { type, ref: "abcd1234", set: Math.random() < 0.5 ? "zzzz9999" : undefined, limit });
            for (const m of msgs) expect(m.length).toBeLessThanOrEqual(limit);
            const parts = partsOf(msgs);
            expect(parts.every(p => p.total === msgs.length && p.type === type)).toBe(true);
            expect(reassemble(shuffle(parts))).toEqual({ armored });
        }
    });

    it("keeps the blank line in PGP armor when a part boundary falls next to it", () => {
        const armored = "-----BEGIN PGP MESSAGE-----\n\n" + Array.from({ length: 6 }, () => "C".repeat(64)).join("\n") + "\n-----END PGP MESSAGE-----\n";
        // Small enough that part 1 holds only the BEGIN line and the blank line after it.
        const msgs = splitArmored(armored, { type: "pgp", ref: "abcd1234", limit: 125 });
        expect(partsOf(msgs)[0].body).toBe("-----BEGIN PGP MESSAGE-----\n");
        expect(reassemble(partsOf(msgs))).toEqual({ armored });
    });

    it("never throws on junk content", () => {
        const pieces = ["-# 🔒 Cipher v1", " · ", "age", "pgp", "1/2", "99/99", "0/1", "ref abcd1234", "ref x", "set qqqq2222", "file", "attachment", "```", "\n", "-----BEGIN PGP MESSAGE-----", "-----END PGP MESSAGE-----", "-# 🔑 Cipher v1", "public key", "\u0000", "💥", ""];
        for (let i = 0; i < 5000; i++) {
            const s = Array.from({ length: Math.floor(Math.random() * 12) }, () => pieces[Math.floor(Math.random() * pieces.length)]).join("");
            expect(() => parseContent(s)).not.toThrow();
        }
    });

    it("reports missing parts", () => {
        const armored = "-----BEGIN PGP MESSAGE-----\n\n" + Array.from({ length: 80 }, () => "B".repeat(64)).join("\n") + "\n-----END PGP MESSAGE-----";
        const parts = partsOf(splitArmored(armored, { type: "pgp", ref: "zz99zz99" }));
        expect(reassemble(parts.slice(1))).toEqual({ missing: [1] });
    });

    it("parses headers, key shares and hand-pasted armor", () => {
        expect(parseContent("-# 🔒 Cipher v1 · file · ref abcd1234 · set qqqq2222 · encrypted message attached above"))
            .toEqual({ kind: "file-notice", ref: "abcd1234", set: "qqqq2222" });
        expect(parseContent(formatKeyShare("age", "age1xyz", "1 2"))).toEqual({ kind: "key", type: "age", material: "age1xyz", marked: true });
        expect(parseContent("look\n-----BEGIN PGP MESSAGE-----\nabc\n-----END PGP MESSAGE-----\nok")).toMatchObject({ kind: "raw", type: "pgp" });
        expect(parseContent("just chatting")).toBeNull();
        expect(parseContent("-# 🔒 Cipher v1 · age · 3/2 · ref abcd1234\n```\nx\n```")).toBeNull();
        expect(parseAttachmentName("cipher-abcd1234.asc")).toEqual({ ref: "abcd1234", type: "pgp" });
        expect(parseAttachmentName("evil.asc")).toBeNull();
    });

    it("leaves the ref out only where there is nothing to link", () => {
        const short = "-----BEGIN PGP MESSAGE-----\n\nAAAA\n-----END PGP MESSAGE-----\n";
        const [lone] = splitArmored(short, { type: "pgp", ref: "abcd1234" });
        expect(lone.split("\n")[0]).toBe("-# 🔒 Cipher v1 · pgp · 1/1");
        expect(parseContent(lone)).toEqual({ kind: "part", type: "pgp", ref: undefined, set: undefined, part: 1, total: 1, body: short.trimEnd() });

        // A copy linked to another key type keeps both ref and set, even in one part.
        const [copy] = splitArmored(short, { type: "pgp", ref: "abcd1234", set: "zzzz9999" });
        expect(parseContent(copy)).toMatchObject({ ref: "abcd1234", set: "zzzz9999", total: 1 });

        // Split messages keep the ref on every part.
        const long = "-----BEGIN PGP MESSAGE-----\n\n" + Array.from({ length: 80 }, () => "B".repeat(64)).join("\n") + "\n-----END PGP MESSAGE-----\n";
        const parts = partsOf(splitArmored(long, { type: "pgp", ref: "abcd1234" }));
        expect(parts.length).toBeGreaterThan(1);
        expect(parts.every(p => p.ref === "abcd1234")).toBe(true);

        // Messages from before this change, with a ref on 1/1, still parse.
        expect(parseContent("-# 🔒 Cipher v1 · age · 1/1 · ref abcd1234\n```\nx\n```")).toMatchObject({ ref: "abcd1234", total: 1 });
        // Without a ref, only a lone message is accepted.
        expect(parseContent("-# 🔒 Cipher v1 · age · 1/2\n```\nx\n```")).toBeNull();
        expect(parseContent("-# 🔒 Cipher v1 · age · 1/1 · set zzzz9999\n```\nx\n```")).toBeNull();
        expect(parseContent("-# 🔒 Cipher v1 · age · 1/1 · set !!\n```\nx\n```")).toBeNull();
        expect(parseContent("-# 🔒 Cipher v1 · file · encrypted message attached above")).toBeNull();
        expect(parseContent("-# 🔒 Cipher v1 · attachment")).toBeNull();
    });
});

describe("which messages get their text replaced by the decrypted text", () => {
    const armor = "-----BEGIN PGP MESSAGE-----\n\nAAAA\n-----END PGP MESSAGE-----";
    it("Cipher parts, file notices and bare armor", () => {
        const [part] = splitArmored(armor, { type: "pgp", ref: "abcd1234" });
        expect(isPureCipherContent(part)).toBe(true);
        expect(isPureCipherContent(fileNotice("abcd1234"))).toBe(true);
        expect(isPureCipherContent(armor)).toBe(true);
        expect(isPureCipherContent("\r\n" + armor.replace(/\n/g, "\r\n") + "\r\n")).toBe(true);
    });
    it("never hides other text, key shares or ordinary messages", () => {
        expect(isPureCipherContent(`see this:\n${armor}\nthanks`)).toBe(false);
        expect(isPureCipherContent(formatKeyShare("age", "age1xyz", "1 2"))).toBe(false);
        expect(isPureCipherContent("hello")).toBe(false);
        expect(isPureCipherContent("")).toBe(false);
        expect(isPureCipherContent(undefined)).toBe(false);
    });
    it("never hides text smuggled around a Cipher message (it would be visible only to people without Cipher)", () => {
        const parts = splitArmored("-----BEGIN PGP MESSAGE-----\n\n" + "A".repeat(64) + "\n-----END PGP MESSAGE-----", { type: "pgp", ref: "abcd1234", set: "wxyz9876" });
        const [part] = parts;
        // Controls: what Cipher writes is hidden, in every shape it writes.
        expect(isPureCipherContent(part)).toBe(true);
        expect(isPureCipherContent(part.replace(/\n/g, "\r\n") + "\n")).toBe(true);
        const [lone] = splitArmored(armor, { type: "pgp", ref: "abcd1234" });
        expect(lone.split("\n")[0]).not.toContain("ref");
        expect(isPureCipherContent(lone)).toBe(true);
        // Older builds wrote a ref on lone messages too.
        expect(isPureCipherContent(lone.replace("1/1", "1/1 · ref abcd1234"))).toBe(true);
        expect(isPureCipherContent(attachmentHeader("abcd1234", "wxyz9876"))).toBe(true);
        // Still parsed (so still decrypted), but shown as it is, not hidden.
        for (const sneaky of [
            part + "\nfree nitro at evil.example",
            part.replace("\n```", " · free nitro at evil.example\n```"),
            part.replace("\n```\n", "\nfree nitro\n```\n"),
            part + "\n```\nmore\n```",
            fileNotice("abcd1234") + "\nfree nitro",
            fileNotice("abcd1234").replace("encrypted message attached above", "free nitro"),
            attachmentHeader("abcd1234") + " · free nitro"
        ]) {
            expect(parseContent(sneaky), sneaky).not.toBeNull();
            expect(isPureCipherContent(sneaky), sneaky).toBe(false);
        }
    });
});

describe("Discord length handling", () => {
    let me: TestUser;
    let pgpTen: TestUser[];
    let ageTen: TestUser[];
    beforeAll(async () => {
        pgpTen = await Promise.all(Array.from({ length: 10 }, (_, i) => pgpUser(`p${i}`)));
        ageTen = await Promise.all(Array.from({ length: 10 }, (_, i) => ageUser(`a${i}`)));
        me = pgpTen[0];
    }, 120_000);

    function planFor(users: TestUser[], self: TestUser) {
        const others = users.filter(u => u !== self);
        const plan = planEncryption({
            self: { userId: self.userId, [self.type]: self.publicKey },
            selectedIds: others.map(u => u.userId),
            lookup: lookupOf(others),
            allowSplit: true
        });
        if (!plan.ok) throw new Error("plan failed");
        return plan;
    }

    async function decryptAll(messages: string[], users: TestUser[], signer?: TestUser) {
        const parts = partsOf(messages);
        const r = reassemble(shuffle(parts));
        if (!("armored" in r)) throw new Error("reassembly failed");
        const out: string[] = [];
        for (const u of users) {
            const d = await decryptArmored(parts[0].type, r.armored, u.keys, signer ? [signer.publicKey] : []);
            if (signer) expect(d.signature.status).toBe("valid");
            out.push(d.text);
        }
        return out;
    }

    it("short message to 10 PGP recipients (signed) fits and decrypts for everyone", async () => {
        const out = await buildOutgoing({ ciphertexts: planFor(pgpTen, me).ciphertexts, text: "hi all", signFingerprint: me.fingerprint, pgp: me.engine });
        expect(out.kind).toBe("messages");
        if (out.kind !== "messages") return;
        for (const m of out.messages) expect(m.length).toBeLessThanOrEqual(DISCORD_CHAR_LIMIT);
        expect(await decryptAll(out.messages, pgpTen, me)).toEqual(Array(10).fill("hi all"));
    });

    it("worst case: 4000 incompressible chars to 10 PGP recipients, signed, splits correctly", async () => {
        const text = randomText(4000);
        const out = await buildOutgoing({ ciphertexts: planFor(pgpTen, me).ciphertexts, text, signFingerprint: me.fingerprint, pgp: me.engine, maxMessages: 20 });
        expect(out.kind).toBe("messages");
        if (out.kind !== "messages") return;
        expect(out.messages.length).toBeGreaterThan(4);
        for (const m of out.messages) expect(m.length).toBeLessThanOrEqual(DISCORD_CHAR_LIMIT);
        expect(await decryptAll(out.messages, pgpTen, me)).toEqual(Array(10).fill(text));
    });

    it("worst case falls back to an attachment once it needs too many messages", async () => {
        const text = randomText(4000);
        const out = await buildOutgoing({ ciphertexts: planFor(pgpTen, me).ciphertexts, text, signFingerprint: me.fingerprint, pgp: me.engine });
        expect(out.kind).toBe("file");
        if (out.kind !== "file") return;
        expect(out.notice.length).toBeLessThanOrEqual(DISCORD_CHAR_LIMIT);
        expect(parseContent(out.notice)).toMatchObject({ kind: "file-notice" });
        expect(parseContent(out.attachmentContent)).toMatchObject({ kind: "attachment" });
        expect(out.files).toHaveLength(1);
        const [file] = out.files;
        expect(parseAttachmentName(file.name)).toMatchObject({ type: "pgp" });
        for (const u of pgpTen) {
            const d = await decryptArmored("pgp", file.content, u.keys, [me.publicKey]);
            expect(d.text).toBe(text);
            expect(d.signature.status).toBe("valid");
        }
    });

    it("compresses long compressible text before splitting", async () => {
        const text = "the quick brown fox jumps over the lazy dog. ".repeat(80);
        const out = await buildOutgoing({ ciphertexts: planFor(ageTen, ageTen[0]).ciphertexts, text });
        expect(out.compressed).toBe(true);
        expect(out.kind).toBe("messages");
        if (out.kind === "messages") expect(await decryptAll(out.messages, ageTen)).toEqual(Array(10).fill(text));
    });

    it("does not compress short messages", async () => {
        const out = await buildOutgoing({ ciphertexts: planFor(ageTen, ageTen[0]).ciphertexts, text: "short" });
        expect(out.compressed).toBe(false);
    });

    it("mixed selection sent as two linked ciphertexts", async () => {
        const meAge = ageTen[0];
        const mixed = [...ageTen.slice(1, 5), ...pgpTen.slice(0, 5)];
        const plan = planEncryption({
            self: { userId: meAge.userId, age: meAge.publicKey },
            selectedIds: mixed.map(u => u.userId), lookup: lookupOf(mixed), allowSplit: true
        });
        if (!plan.ok) throw new Error("plan failed");
        const out = await buildOutgoing({ ciphertexts: plan.ciphertexts, text: "both formats", pgp: pgpTen[0].engine });
        if (out.kind !== "messages") throw new Error("expected messages");
        const parts = partsOf(out.messages);
        const sets = new Set(parts.map(p => p.set));
        expect(sets.size).toBe(1);
        expect([...sets][0]).toBeTruthy();
        const age = parts.filter(p => p.type === "age");
        const pgp = parts.filter(p => p.type === "pgp");
        const ageArmor = reassemble(age);
        const pgpArmor = reassemble(pgp);
        if (!("armored" in ageArmor) || !("armored" in pgpArmor)) throw new Error("reassembly failed");
        for (const u of [meAge, ...ageTen.slice(1, 5)]) expect((await decryptArmored("age", ageArmor.armored, u.keys)).text).toBe("both formats");
        for (const u of pgpTen.slice(0, 5)) expect((await decryptArmored("pgp", pgpArmor.armored, u.keys)).text).toBe("both formats");
        // Age users can't read the PGP copy and vice versa: reported, not crashed.
        await expect(decryptArmored("pgp", pgpArmor.armored, { pgp: newGpgHome().engine })).rejects.toMatchObject({ code: "not-recipient" });
    });
});
