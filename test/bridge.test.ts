import { spawnSync } from "node:child_process";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { linkLoadPolicy } from "../src/core/serverApi";
import { proofStatement } from "../src/core/keyProof";

/*
 * The main-process bridge (src/native.ts) with Electron and GnuPG mocked:
 * nothing here runs gpg or touches any GnuPG home.
 */

const dialogAnswer = { response: 0 };
const importSpy = vi.fn(async () => ["F".repeat(40)]);
const signSpy = vi.fn(async () => "-----BEGIN PGP SIGNATURE-----\n\n-----END PGP SIGNATURE-----");

vi.mock("electron", () => ({
    BrowserWindow: { fromWebContents: () => null },
    dialog: { showMessageBox: async () => dialogAnswer },
    powerMonitor: { getSystemIdleTime: () => 0, getSystemIdleState: () => "active" }
}));

vi.mock("../src/core/gpg", () => ({
    findGpg: () => ({ gpg: "gpg", gpgv: "gpgv" }),
    GpgEngine: class {
        requireSupported = async () => { };
        importSecretKey = importSpy;
        signProof = signSpy;
        exportSecretKey = async () => "secret";
    }
}));

// native.ts needs Electron's types, which only exist inside a Vencord checkout (where
// it's typechecked); load it untyped here so the standalone typecheck doesn't need them.
const nativePath = "../src/native";
const native = await import(/* @vite-ignore */ nativePath) as Record<string, (...a: unknown[]) => any>;

const discord = { senderFrame: { parent: null, url: "https://canary.discord.com/channels/@me" }, sender: {} } as never;
const iframe = { senderFrame: { parent: {}, url: "https://canary.discord.com/activities" }, sender: {} } as never;
const otherSite = { senderFrame: { parent: null, url: "https://evil.example/" }, sender: {} } as never;

describe("main-process bridge", () => {
    it("only answers Discord's own top-level page", async () => {
        expect(await native.listSecretKeys(iframe)).toEqual({ ok: false, code: "invalid-input" });
        expect(await native.listSecretKeys(otherSite)).toEqual({ ok: false, code: "invalid-input" });
        expect(native.systemIdle(iframe)).toEqual({ ok: false });
    });

    it("throttles proof signing so the page can't spam passphrase prompts", async () => {
        const fpr = "A".repeat(40);
        const ticket = `p1.80351110224678912.pgp.${fpr}.${Date.now() + 60_000}.${"B".repeat(22)}.${"C".repeat(43)}`;
        const st = proofStatement("https://cipher.example", "80351110224678912", fpr, ticket);
        const codes = [];
        for (let i = 0; i < 8; i++) codes.push(await native.signProof(discord, fpr, st));
        expect(codes.slice(0, 6).every(r => r.ok)).toBe(true);
        expect(codes.slice(6)).toEqual([{ ok: false, code: "invalid-input" }, { ok: false, code: "invalid-input" }]);
        expect(signSpy).toHaveBeenCalledTimes(6);
        // Anything that isn't a proof statement for that key is refused outright.
        expect(await native.signProof(discord, fpr, "sign this please")).toEqual({ ok: false, code: "invalid-input" });
    });

    it("imports or exports a secret key only after a click in a native window", async () => {
        const key = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nxx\n-----END PGP PRIVATE KEY BLOCK-----";
        dialogAnswer.response = 0;
        expect(await native.importSecretKey(discord, key)).toEqual({ ok: false, code: "cancelled" });
        expect(importSpy).not.toHaveBeenCalled();
        expect(await native.exportSecretKey(discord, "F".repeat(40))).toEqual({ ok: false, code: "cancelled" });
        dialogAnswer.response = 1;
        expect((await native.importSecretKey(discord, key)).ok).toBe(true);
        expect(importSpy).toHaveBeenCalledTimes(1);
    });
});

describe("main-process server requests", () => {
    const realFetch = globalThis.fetch;
    let calls: { url: string; init: RequestInit; }[];
    beforeEach(() => {
        calls = [];
        globalThis.fetch = (async (url: string, init: RequestInit) => {
            calls.push({ url, init });
            return new Response("{\"ok\":true}", { status: 200 });
        }) as never;
    });
    afterEach(() => {
        globalThis.fetch = realFetch;
        delete process.env.CIPHER_DEV_HTTP;
    });

    it("refuses plain http (even localhost) unless CIPHER_DEV_HTTP=1", async () => {
        expect(await native.serverFetch(discord, "http://localhost:8787", "GET", "/v1/oauth", undefined, undefined, undefined)).toEqual({ ok: false, code: "invalid-input" });
        expect(calls).toHaveLength(0);
        process.env.CIPHER_DEV_HTTP = "1";
        expect((await native.serverFetch(discord, "http://localhost:8787", "GET", "/v1/oauth", undefined, undefined, undefined)).ok).toBe(true);
        expect(calls).toHaveLength(1);
    });

    it("sends only allowed requests, never follows redirects, and caps the answer", async () => {
        expect(await native.serverFetch(discord, "https://cipher.example", "GET", "/admin", undefined, undefined, undefined)).toEqual({ ok: false, code: "invalid-input" });
        expect(await native.serverFetch(discord, "https://cipher.example", "GET", "/v1/oauth", undefined, "not-a-token", undefined)).toEqual({ ok: false, code: "invalid-input" });
        expect(await native.serverFetch(iframe, "https://cipher.example", "GET", "/v1/oauth", undefined, undefined, undefined)).toEqual({ ok: false, code: "invalid-input" });
        await native.serverFetch(discord, "https://cipher.example", "GET", "/v1/oauth", undefined, undefined, undefined);
        expect(calls[0].init.redirect).toBe("error");
        globalThis.fetch = (async () => new Response("x".repeat(70 * 1024))) as never;
        expect(await native.serverFetch(discord, "https://cipher.example", "GET", "/v1/oauth", undefined, undefined, undefined)).toEqual({ ok: false, code: "failed" });
    });
});

describe("which servers Cipher may contact for disappearing messages", () => {
    const own = "https://cipher-server.example-project.workers.dev";
    it("with your own server set: only it, and strangers' links need a click", () => {
        expect(linkLoadPolicy(own, own, true)).toBe("auto");
        expect(linkLoadPolicy(own, own, false)).toBe("ask");
        expect(linkLoadPolicy(own, "https://other.example.com", true)).toBe("never");
        expect(linkLoadPolicy(own, "https://192.168.1.1", true)).toBe("never");
    });
    it("without one: public hosts after a click, never local addresses", () => {
        expect(linkLoadPolicy(null, "https://other.example.com", true)).toBe("ask");
        for (const bad of ["https://192.168.1.1", "https://localhost", "https://nas.local", "http://127.0.0.1:8787", "not a url"])
            expect(linkLoadPolicy(null, bad, true), bad).toBe("never");
    });
});

describe("developer check script", () => {
    it("refuses a Vencord ref that could inject shell commands, before running anything", () => {
        const r = spawnSync(process.execPath, ["scripts/vencord-check.mjs"], { env: { ...process.env, VENCORD_REF: "v1.15.19&calc" }, encoding: "utf8", timeout: 30_000 });
        expect(r.status).not.toBe(0);
        expect(r.stderr).toContain("VENCORD_REF must be a plain tag or branch name");
    });
});

describe("the default server", () => {
    it("is a clean https origin on a public host, so every safety check applies to it", async () => {
        const { DEFAULT_SERVER_URL, normalizeServerUrl, isPublicHostname, serverRequestUrl } = await import("../src/core/serverApi");
        expect(normalizeServerUrl(DEFAULT_SERVER_URL)).toBe(DEFAULT_SERVER_URL);
        expect(DEFAULT_SERVER_URL.startsWith("https://")).toBe(true);
        expect(isPublicHostname(new URL(DEFAULT_SERVER_URL).hostname)).toBe(true);
        expect(serverRequestUrl(DEFAULT_SERVER_URL, "GET", "/v1/oauth")).toBe(DEFAULT_SERVER_URL + "/v1/oauth");
        // With it set, no other server is ever contacted.
        expect(linkLoadPolicy(DEFAULT_SERVER_URL, "https://other.example.com", true)).toBe("never");
    });
});
