import { beforeEach, describe, expect, it } from "vitest";

import { candidatesFor } from "../src/core/candidates";
import { ChannelPrefs } from "../src/core/channelPrefs";
import { ContactBook, KeyChangeError, MemoryKV } from "../src/core/contacts";
import { GroupStore, MAX_GROUP_MEMBERS } from "../src/core/groups";
import { ageUser, pgpUser } from "./helpers";

describe("contact book and key-change detection", () => {
    let kv: MemoryKV;
    let book: ContactBook;
    beforeEach(async () => {
        kv = new MemoryKV();
        book = new ContactBook(kv);
        await book.load();
    });

    it("adds, persists and reloads a contact", async () => {
        const u = await ageUser("alice");
        expect(await book.add(u.userId, "alice", u.info)).toBe("added");
        const again = new ContactBook(kv);
        await again.load();
        expect(again.get(u.userId)).toMatchObject({ displayName: "alice", verified: false, key: { type: "age", fingerprint: u.info.fingerprint } });
    });

    it("adding the same key again is a no-op", async () => {
        const u = await ageUser("alice");
        await book.add(u.userId, "alice", u.info);
        expect(await book.add(u.userId, "alice", u.info)).toBe("unchanged");
    });

    it("refuses to silently replace a key", async () => {
        const u = await ageUser("alice");
        const other = await pgpUser("alice-new");
        await book.add(u.userId, "alice", u.info);
        await expect(book.add(u.userId, "alice", other.info)).rejects.toBeInstanceOf(KeyChangeError);
        expect(book.get(u.userId)!.key.fingerprint).toBe(u.info.fingerprint);
    });

    it("parks a changed shared key as pending without using it", async () => {
        const u = await ageUser("alice");
        const next = await ageUser("alice2");
        await book.add(u.userId, "alice", u.info);
        await book.setVerified(u.userId, true);

        expect(await book.observeSharedKey(u.userId, u.info)).toEqual({ kind: "same" });
        const r = await book.observeSharedKey(u.userId, next.info, "msg1");
        expect(r.kind).toBe("changed");
        const c = book.get(u.userId)!;
        expect(c.key.fingerprint).toBe(u.info.fingerprint);
        expect(c.pendingKey?.fingerprint).toBe(next.info.fingerprint);
        expect(c.verified).toBe(true);
        expect(book.checkKey(u.userId, "age", next.info.fingerprint)).toBe("changed");
    });

    it("accepting a new key records history and resets verification", async () => {
        const u = await ageUser("alice");
        const next = await ageUser("alice2");
        await book.add(u.userId, "alice", u.info);
        await book.setVerified(u.userId, true);
        await book.observeSharedKey(u.userId, next.info);
        await book.replaceKey(u.userId, next.info);
        const c = book.get(u.userId)!;
        expect(c.key.fingerprint).toBe(next.info.fingerprint);
        expect(c.verified).toBe(false);
        expect(c.pendingKey).toBeUndefined();
        expect(c.history).toEqual([expect.objectContaining({ fingerprint: u.info.fingerprint, type: "age" })]);
    });

    it("keeping the old key stops the same new key being flagged again", async () => {
        const u = await ageUser("alice");
        const next = await ageUser("alice2");
        await book.add(u.userId, "alice", u.info);
        await book.observeSharedKey(u.userId, next.info);
        await book.dismissPendingKey(u.userId);
        expect(book.get(u.userId)!.pendingKey).toBeUndefined();
        expect(await book.observeSharedKey(u.userId, next.info)).toEqual({ kind: "dismissed" });
        expect(book.get(u.userId)!.key.fingerprint).toBe(u.info.fingerprint);
        // A third, different key is still flagged.
        const third = await ageUser("alice3");
        expect((await book.observeSharedKey(u.userId, third.info)).kind).toBe("changed");
    });

    it("unknown users are reported as unknown", async () => {
        const u = await ageUser("stranger");
        expect(await book.observeSharedKey(u.userId, u.info)).toEqual({ kind: "unknown" });
        expect(book.checkKey(u.userId, "age", u.info.fingerprint)).toBe("unknown");
    });

    it("removes contacts", async () => {
        const u = await ageUser("alice");
        await book.add(u.userId, "alice", u.info);
        await book.remove(u.userId);
        expect(book.get(u.userId)).toBeUndefined();
    });
});

describe("planner candidates", () => {
    it("re-checks keys, and reports a key it can't check instead of skipping it", async () => {
        const good = await pgpUser("good");
        const contacts = [
            { userId: good.userId, displayName: "good", key: { type: "pgp" as const, material: good.publicKey, fingerprint: good.info.fingerprint, addedAt: 1 }, verified: true, history: [] },
            { userId: "777", displayName: "broken", key: { type: "pgp" as const, material: "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----", fingerprint: "00", addedAt: 1 }, verified: false, history: [] }
        ];
        const out = await candidatesFor(contacts, c => c.displayName);
        expect(out.get(good.userId)).toMatchObject({ problems: [], verified: true, pendingKeyChange: false });
        expect(out.get("777")?.problems).toEqual(["check-failed"]);
    });
});

describe("recipient groups", () => {
    it("creates, edits and deletes groups, capped at the recipient limit", async () => {
        const groups = new GroupStore(new MemoryKV());
        await groups.load();
        const g = await groups.create("Close friends", ["1", "2", "2"]);
        expect(g.memberIds).toEqual(["1", "2"]);
        await groups.update(g.id, "Besties", ["1", "3"]);
        expect(groups.get(g.id)).toMatchObject({ name: "Besties", memberIds: ["1", "3"] });
        await expect(groups.create("Too big", Array.from({ length: MAX_GROUP_MEMBERS + 1 }, (_, i) => String(i)))).rejects.toThrow(/at most 9/);
        await expect(groups.create("  ", [])).rejects.toThrow(/name/);
        await groups.remove(g.id);
        expect(groups.list()).toEqual([]);
    });
});

describe("channel encryption modes", () => {
    it("defaults to off and never turns on by itself", async () => {
        const prefs = new ChannelPrefs(new MemoryKV());
        await prefs.load();
        expect(prefs.get("c1")).toEqual({ mode: "off", recipients: [], allowSplit: false });
    });

    it("once applies to one message, sticky persists across reloads", async () => {
        const kv = new MemoryKV();
        const prefs = new ChannelPrefs(kv);
        await prefs.load();
        await prefs.set("c1", { mode: "once", recipients: ["a"], allowSplit: false });
        await prefs.set("c2", { mode: "sticky", recipients: ["b", "b"], allowSplit: true });
        expect(prefs.get("c1").mode).toBe("once");
        prefs.consumeOnce("c1");
        expect(prefs.get("c1").mode).toBe("off");

        const reloaded = new ChannelPrefs(kv);
        await reloaded.load();
        expect(reloaded.get("c2")).toEqual({ mode: "sticky", recipients: ["b"], allowSplit: true });
        await reloaded.turnOff("c2");
        const again = new ChannelPrefs(kv);
        await again.load();
        expect(again.get("c2").mode).toBe("off");
    });

    it("once-mode is not persisted", async () => {
        const kv = new MemoryKV();
        const prefs = new ChannelPrefs(kv);
        await prefs.set("c1", { mode: "once", recipients: ["a"], allowSplit: false });
        const reloaded = new ChannelPrefs(kv);
        await reloaded.load();
        expect(reloaded.get("c1").mode).toBe("off");
    });
});
