import { beforeAll, describe, expect, it } from "vitest";

import { describePlanError, MAX_RECIPIENTS, planEncryption, restrictToType } from "../src/core/recipients";
import { ageUser, candidate, lookupOf, pgpUser, type TestUser } from "./helpers";

let me: TestUser;
let meBoth: { userId: string; age: string; pgp: string; };
let ages: TestUser[];
let pgps: TestUser[];

beforeAll(async () => {
    me = await ageUser("me");
    const mePgp = await pgpUser("me");
    meBoth = { userId: me.userId, age: me.publicKey, pgp: mePgp.publicKey };
    ages = await Promise.all(Array.from({ length: 10 }, (_, i) => ageUser(`a${i}`)));
    pgps = await Promise.all(Array.from({ length: 10 }, (_, i) => pgpUser(`p${i}`)));
});

describe("recipient planning", () => {
    it("two-person DM: one ciphertext, includes me", () => {
        const plan = planEncryption({ self: meBoth, selectedIds: [ages[0].userId], lookup: lookupOf(ages), allowSplit: false });
        expect(plan.ok).toBe(true);
        if (!plan.ok) return;
        expect(plan.ciphertexts).toHaveLength(1);
        expect(plan.ciphertexts[0]).toMatchObject({ type: "age", includesSelf: true, readerIds: [ages[0].userId, me.userId] });
        expect(plan.ciphertexts[0].keys).toEqual([ages[0].publicKey, me.publicKey]);
    });

    it("blocks when nobody else is selected", () => {
        const plan = planEncryption({ self: meBoth, selectedIds: [me.userId], lookup: lookupOf(ages), allowSplit: false });
        expect(plan).toEqual({ ok: false, error: { code: "no-recipients" } });
    });

    it(`allows exactly ${MAX_RECIPIENTS} people including me`, () => {
        const nine = ages.slice(0, 9).map(u => u.userId);
        const plan = planEncryption({ self: meBoth, selectedIds: nine, lookup: lookupOf(ages), allowSplit: false });
        expect(plan.ok).toBe(true);
        if (plan.ok) expect(plan.ciphertexts[0].readerIds).toHaveLength(10);
    });

    it("blocks the 11th person with a clear message", () => {
        const ten = ages.map(u => u.userId);
        const plan = planEncryption({ self: meBoth, selectedIds: ten, lookup: lookupOf(ages), allowSplit: false });
        expect(plan).toEqual({ ok: false, error: { code: "over-cap", count: 11, max: 10 } });
        if (!plan.ok) expect(describePlanError(plan.error, id => id)).toMatch(/limit is 10 including you/);
    });

    it("counts people, not ciphertexts, for the cap when splitting", () => {
        const sel = [...ages.slice(0, 5), ...pgps.slice(0, 4)].map(u => u.userId);
        const plan = planEncryption({ self: meBoth, selectedIds: sel, lookup: lookupOf([...ages, ...pgps]), allowSplit: true });
        expect(plan.ok).toBe(true);
        const over = [...ages.slice(0, 5), ...pgps.slice(0, 5)].map(u => u.userId);
        expect(planEncryption({ self: meBoth, selectedIds: over, lookup: lookupOf([...ages, ...pgps]), allowSplit: true }).ok).toBe(false);
    });

    it("refuses a mixed selection unless splitting was allowed, and never drops anyone", () => {
        const sel = [ages[0].userId, ages[1].userId, pgps[0].userId];
        const lookup = lookupOf([...ages, ...pgps]);
        const blocked = planEncryption({ self: meBoth, selectedIds: sel, lookup, allowSplit: false });
        expect(blocked.ok).toBe(false);
        if (!blocked.ok && blocked.error.code === "mixed-types") {
            expect(blocked.error.age.map(c => c.userId)).toEqual([ages[0].userId, ages[1].userId]);
            expect(blocked.error.pgp.map(c => c.userId)).toEqual([pgps[0].userId]);
        } else throw new Error("expected mixed-types");

        const split = planEncryption({ self: meBoth, selectedIds: sel, lookup, allowSplit: true });
        expect(split.ok).toBe(true);
        if (!split.ok) return;
        expect(split.ciphertexts.map(c => c.type)).toEqual(["age", "pgp"]);
        const everyone = new Set(split.ciphertexts.flatMap(c => c.readerIds));
        for (const id of [...sel, me.userId]) expect(everyone.has(id)).toBe(true);
        expect(split.ciphertexts.every(c => c.includesSelf)).toBe(true);
    });

    it("restrictToType reports exactly who would be removed", () => {
        const sel = [ages[0].userId, pgps[0].userId, ages[1].userId];
        const r = restrictToType(sel, lookupOf([...ages, ...pgps]), "age");
        expect(r).toEqual({ kept: [ages[0].userId, ages[1].userId], removed: [pgps[0].userId] });
    });

    it("blocks when a selected person has no key", () => {
        const plan = planEncryption({ self: meBoth, selectedIds: [ages[0].userId, "999"], lookup: lookupOf(ages), allowSplit: false });
        expect(plan).toEqual({ ok: false, error: { code: "missing-key", userIds: ["999"] } });
    });

    it("blocks when a selected key is expired or revoked", () => {
        const bad = candidate(pgps[0], { problems: ["expired"] });
        const plan = planEncryption({ self: meBoth, selectedIds: [bad.userId], lookup: id => id === bad.userId ? bad : undefined, allowSplit: false });
        expect(plan.ok).toBe(false);
        if (!plan.ok) expect(plan.error.code).toBe("unusable-key");
    });

    it("warns when I can't read my own message", () => {
        const plan = planEncryption({ self: { userId: me.userId, age: me.publicKey }, selectedIds: [pgps[0].userId], lookup: lookupOf(pgps), allowSplit: false });
        expect(plan.ok).toBe(true);
        if (plan.ok) {
            expect(plan.ciphertexts[0].includesSelf).toBe(false);
            expect(plan.warnings).toContainEqual({ code: "self-cannot-read", type: "pgp" });
        }
    });

    it("warns about unverified keys and pending key changes", () => {
        const plan = planEncryption({ self: meBoth, selectedIds: [ages[0].userId], lookup: lookupOf(ages, { verified: false, pendingKeyChange: true }), allowSplit: false });
        expect(plan.ok && plan.warnings.map(w => w.code)).toEqual(["unverified", "pending-key-change"]);
    });
});
