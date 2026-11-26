import { describe, expect, it } from "vitest";

import { handle } from "../server/src/index";
import { generateAgeIdentity } from "../src/core/ageCipher";
import { sha256 } from "../src/core/bytes";
import { buildLinkCiphertexts, decryptArmored, MAX_LINK_CIPHERTEXT, normalizeForServer } from "../src/core/compose";
import { formatLinkMessage, isPureCipherContent, parseContent } from "../src/core/envelope";
import { planEncryption } from "../src/core/recipients";
import { normalizeServerUrl, parseLinkUrl, serverRequestUrl } from "../src/core/serverApi";
import { randomText } from "./helpers";

const b64url = (b: Uint8Array) => btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const hashOf = async (armored: string) => b64url(await sha256(new TextEncoder().encode(normalizeForServer(armored))));

describe("what Cipher may ask a server for", () => {
    it("accepts only https origins (http only for localhost)", () => {
        expect(normalizeServerUrl("https://cipher.example.com")).toBe("https://cipher.example.com");
        expect(normalizeServerUrl("https://cipher.example.com/")).toBe("https://cipher.example.com");
        expect(normalizeServerUrl("http://localhost:8787")).toBe("http://localhost:8787");
        for (const bad of ["http://cipher.example.com", "https://cipher.example.com/api", "https://u:p@cipher.example.com", "https://x.com?a=1", "file:///etc/passwd", "javascript:alert(1)", "ftp://x.com", "not a url"])
            expect(normalizeServerUrl(bad), bad).toBeNull();
    });

    it("allows only the fixed list of requests", () => {
        const base = "https://cipher.example.com";
        expect(serverRequestUrl(base, "GET", "/v1/keys/80351110224678912")).toBe(base + "/v1/keys/80351110224678912");
        expect(serverRequestUrl(base, "POST", "/v1/messages")).toBe(base + "/v1/messages");
        expect(serverRequestUrl(base, "GET", "/m/7" + "A".repeat(22))).toBeTruthy();
        for (const [m, p] of [
            ["GET", "/admin"], ["POST", "/v1/keys"], ["GET", "/v1/keys/../../etc"], ["GET", "/m/7" + "A".repeat(22) + "?x"],
            ["DELETE", "/v1/messages"], ["GET", "//evil.com/m/x"], ["GET", "/v1/auth/callback?code=abc&redirect_uri=x"], ["CONNECT", "/v1/oauth"]
        ]) expect(serverRequestUrl(base, m, p), `${m} ${p}`).toBeNull();
        // The base must already be a clean origin.
        expect(serverRequestUrl("https://cipher.example.com/x", "GET", "/v1/oauth")).toBeNull();
        expect(serverRequestUrl("https://evil.com@cipher.example.com", "GET", "/v1/oauth")).toBeNull();
    });
});

describe("disappearing message links in Discord", () => {
    const link = { url: "https://cipher.example.com/m/7AbCdEfGhIjKlMnOpQrStUv", type: "age" as const, hash: "Q".repeat(43) };

    it("format and parse round-trip: a timestamp for everyone and no clickable link", () => {
        const text = formatLinkMessage(Date.UTC(2026, 11, 2) + 999, [link]);
        const lines = text.split("\n");
        expect(lines[0]).toBe(`-# 🔒 Cipher v1 · disappearing · expires <t:${Date.UTC(2026, 11, 2) / 1000}:R>`);
        expect(lines.slice(1, 3)).toEqual(["```", "-----BEGIN CIPHER DISAPPEARING MESSAGE-----"]);
        expect(lines.slice(-2)).toEqual(["-----END CIPHER DISAPPEARING MESSAGE-----", "```"]);
        // Discord only turns http(s):// text into links; none is left in the message.
        expect(text).not.toMatch(/https?:/);
        expect(text).not.toContain("cipher.example.com");
        expect(parseContent(text)).toEqual({ kind: "link", expiresAt: Date.UTC(2026, 11, 2), links: [{ ...link, origin: "https://cipher.example.com", id: "7AbCdEfGhIjKlMnOpQrStUv" }] });
        expect(isPureCipherContent(text)).toBe(true);
        // Four copies still fit in one Discord message.
        const four = formatLinkMessage(Date.UTC(2026, 11, 2), Array(4).fill({ ...link, url: "https://cipher-server.example-project.workers.dev/m/7AbCdEfGhIjKlMnOpQrStUv" }));
        expect(four.length).toBeLessThan(1000);
        expect(parseContent(four)).toMatchObject({ kind: "link" });
    });

    it("refuses blocks that don't hold plain Cipher message links", () => {
        const block = (entries: string[], extra: { before?: string; after?: string; b64?: string; } = {}) => {
            const b64 = extra.b64 ?? btoa(entries.join("\n"));
            return `-# 🔒 Cipher v1 · disappearing · expires <t:1767225600:R>\n${extra.before ?? ""}\`\`\`\n-----BEGIN CIPHER DISAPPEARING MESSAGE-----\n${b64}\n-----END CIPHER DISAPPEARING MESSAGE-----\n\`\`\`${extra.after ?? ""}`;
        };
        const good = `${link.url}#age.${link.hash}`;
        expect(parseContent(block([good]))).toMatchObject({ kind: "link" });
        for (const entry of [
            "http://cipher.example.com/m/7AbCdEfGhIjKlMnOpQrStUv#age." + "Q".repeat(43),
            "https://cipher.example.com/x/7AbCdEfGhIjKlMnOpQrStUv#age." + "Q".repeat(43),
            "https://cipher.example.com/m/7AbCdEfGhIjKlMnOpQrStUv?track=1#age." + "Q".repeat(43),
            "https://cipher.example.com/m/7AbCdEfGhIjKlMnOpQrStUv#rsa." + "Q".repeat(43),
            "https://cipher.example.com/m/7AbCdEfGhIjKlMnOpQrStUv#age.short",
            "javascript:alert(1)#age." + "Q".repeat(43),
            good + " "
        ]) expect(parseContent(block([entry])), entry).toBeNull();
        expect(parseContent(block(Array(5).fill(good)))).toBeNull();
        expect(parseContent(block([good], { b64: "not base64!" }))).toBeNull();
        expect(parseContent(block([good], { b64: btoa(good).replace(/=+$/, "") + "A" }))).toBeNull();
        expect(parseContent(block([good], { after: "\nhello" }))).toBeNull();
        expect(parseContent(block([good], { before: "hi\n" }))).toBeNull();
        // The old visible-link format is no longer read.
        expect(parseContent(`-# 🔒 Cipher v1 · link · expires <t:1767225600:R>\n<${good}>`)).toBeNull();
        expect(parseLinkUrl("https://a.example/m/1" + "B".repeat(22))).toEqual({ origin: "https://a.example", id: "1" + "B".repeat(22) });
    });

    it("go through the real server and come back byte for byte", async () => {
        const reader = await generateAgeIdentity({ postQuantum: true });
        const plan = planEncryption({
            self: { userId: "1" }, selectedIds: ["2"], allowSplit: false,
            lookup: () => ({ userId: "2", name: "r", type: "age", material: reader.recipient, problems: [], verified: true, pendingKeyChange: false })
        });
        if (!plan.ok) throw new Error("plan");
        const [ct] = await buildLinkCiphertexts({ ciphertexts: plan.ciphertexts, text: "this will disappear" });
        expect(ct.armored.length).toBeLessThan(MAX_LINK_CIPHERTEXT);

        // A minimal in-memory server.
        const { DatabaseSync } = await import("node:sqlite");
        const { readFileSync } = await import("node:fs");
        const db = new DatabaseSync(":memory:");
        db.exec(readFileSync("server/schema.sql", "utf8"));
        const objects = new Map<string, { value: string; customMetadata?: Record<string, string>; }>();
        const env = {
            SECRET: "k".repeat(40), DISCORD_CLIENT_ID: "1", DISCORD_CLIENT_SECRET: "x", PUBLIC_URL: "https://cipher.example.com",
            DB: { prepare: (sql: string) => { const mk = (v: unknown[]): any => ({ bind: (...x: unknown[]) => mk(x), first: async () => db.prepare(sql).get(...v as never[]) ?? null, run: async () => db.prepare(sql).run(...v as never[]), all: async () => ({ results: db.prepare(sql).all(...v as never[]) }) }); return mk([]); } },
            MESSAGES: {
                get: async (k: string) => { const o = objects.get(k); return o ? { customMetadata: o.customMetadata, text: async () => o.value } : null; },
                head: async (k: string) => objects.get(k) ?? null,
                put: async (k: string, value: string, o?: { customMetadata?: Record<string, string>; }) => void objects.set(k, { value, customMetadata: o?.customMetadata }),
                delete: async (k: string) => void objects.delete(k)
            }
        };
        const deps = { now: Date.now, fetch: async () => { throw new Error("no"); } };
        const { makeToken } = await import("../server/src/index");
        const { token } = await makeToken(env as never, "80351110224678912", Date.now());
        const up = await handle(new Request("https://cipher.example.com/v1/messages", {
            method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
            body: JSON.stringify({ ciphertext: ct.armored, ttlDays: 1 })
        }), env as never, deps);
        expect(up.status).toBe(201);
        const { id } = await up.json() as { id: string; };
        const got = await (await handle(new Request(`https://cipher.example.com/m/${id}`), env as never, deps)).text();
        // The hash Cipher puts in the Discord message matches what the server returns.
        expect(await hashOf(got)).toBe(await hashOf(ct.armored));
        expect((await decryptArmored("age", got, { ageIdentity: reader.identity })).text).toBe("this will disappear");
        // A server that swaps the text is caught by the hash.
        expect(await hashOf(got.replace("A", "B"))).not.toBe(await hashOf(ct.armored));
    });

    it("refuse messages too long for the server instead of splitting them", async () => {
        const r = await generateAgeIdentity();
        const plan = planEncryption({
            self: { userId: "1" }, selectedIds: ["2"], allowSplit: false,
            lookup: () => ({ userId: "2", name: "r", type: "age", material: r.recipient, problems: [], verified: true, pendingKeyChange: false })
        });
        if (!plan.ok) throw new Error("plan");
        await expect(buildLinkCiphertexts({ ciphertexts: plan.ciphertexts, text: randomText(12_000) })).rejects.toMatchObject({ code: "too-large" });
    });
});
