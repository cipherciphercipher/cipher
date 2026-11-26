import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

/*
 * Cipher-Setup.exe against a FAKE Discord and AppData in a temp folder. The exe's
 * test mode needs explicit folders and never looks at or closes real Discord.
 * Runs on Windows once `node scripts/build-exe.mjs` has built the exe.
 */

const exe = join(__dirname, "..", "dist-exe", "Cipher-Setup.exe");
const run = process.platform === "win32" && existsSync(exe) ? describe : describe.skip;

/** An asar reader written independently of the C# writer (Electron's pickle layout). */
function readAsar(buf: Buffer): Record<string, string> {
    expect(buf.readUInt32LE(0)).toBe(4);
    const headerLen = buf.readUInt32LE(4);
    expect(buf.readUInt32LE(8)).toBe(headerLen - 4);
    const jsonLen = buf.readUInt32LE(12);
    const header = JSON.parse(buf.subarray(16, 16 + jsonLen).toString("utf8")) as { files: Record<string, { size: number; offset: string; }>; };
    const out: Record<string, string> = {};
    for (const [name, e] of Object.entries(header.files))
        out[name] = buf.subarray(8 + headerLen + Number(e.offset), 8 + headerLen + Number(e.offset) + e.size).toString("utf8");
    return out;
}

function writeAsar(files: Record<string, string>): Buffer {
    let offset = 0;
    const entries: Record<string, { size: number; offset: string; }> = {};
    const bodies = Object.entries(files).map(([name, text]) => {
        const b = Buffer.from(text);
        entries[name] = { size: b.length, offset: String(offset) };
        offset += b.length;
        return b;
    });
    const json = Buffer.from(JSON.stringify({ files: entries }));
    const padded = (json.length + 3) & ~3;
    const header = Buffer.alloc(8 + padded);
    header.writeUInt32LE(4 + padded, 0);
    header.writeUInt32LE(json.length, 4);
    json.copy(header, 8);
    const size = Buffer.alloc(8);
    size.writeUInt32LE(4, 0);
    size.writeUInt32LE(header.length, 4);
    return Buffer.concat([size, header, ...bodies]);
}

const sha = (p: string) => createHash("sha256").update(readFileSync(p)).digest("hex");

run("Cipher-Setup.exe (fake Discord folders only)", () => {
    let root: string, local: string, roaming: string, dist: string;
    const res = (flavor: string, app: string) => join(local, flavor, app, "resources");
    const exec = (...a: string[]) => spawnSync(exe, ["--local-appdata", local, "--appdata", roaming, ...a], { encoding: "utf8", timeout: 60_000 });

    beforeAll(() => {
        root = mkdtempSync(join(tmpdir(), "cipher-exe-test-"));
        local = join(root, "Local");
        roaming = join(root, "Roaming");
        dist = join(roaming, "Vencord", "dist");
        // Stable: unmodified, two versions (the newest must be picked).
        for (const app of ["app-1.0.9100", "app-1.0.9270"]) {
            mkdirSync(res("Discord", app), { recursive: true });
            writeFileSync(join(res("Discord", app), "app.asar"), Buffer.alloc(700 * 1024, app === "app-1.0.9270" ? 7 : 1));
        }
        // PTB: set up by Vencord (or a custom stub built on it) loading the usual folder.
        mkdirSync(res("DiscordPTB", "app-1.0.1235"), { recursive: true });
        writeFileSync(join(res("DiscordPTB", "app-1.0.1235"), "_app.asar"), Buffer.alloc(700 * 1024, 3));
        writeFileSync(join(res("DiscordPTB", "app-1.0.1235"), "app.asar"), writeAsar({
            "index.js": `require("./other-bridge.js");\nrequire(${JSON.stringify(join(dist, "patcher.js"))});`, "package.json": "{\"main\":\"index.js\"}"
        }));
        // Canary: modified by some other tool. Must never be touched.
        mkdirSync(res("DiscordCanary", "app-1.0.1364"), { recursive: true });
        writeFileSync(join(res("DiscordCanary", "app-1.0.1364"), "_app.asar"), Buffer.alloc(700 * 1024, 5));
        writeFileSync(join(res("DiscordCanary", "app-1.0.1364"), "app.asar"), writeAsar({ "index.js": "require('C:/SomethingElse/inject.js');", "package.json": "{}" }));
        // An existing official Vencord install.
        mkdirSync(dist, { recursive: true });
        writeFileSync(join(dist, "renderer.js"), "official vencord");
        writeFileSync(join(dist, "patcher.js"), "official vencord patcher");
    });
    afterAll(() => rmSync(root, { recursive: true, force: true }));

    it("refuses to run without explicit folders", () => {
        const r = spawnSync(exe, ["--install", "Discord"], { encoding: "utf8", timeout: 30_000 });
        expect(r.status).toBe(2);
    });

    it("tells unmodified, Vencord and foreign installs apart", () => {
        const r = exec("--list");
        expect(r.status, r.stderr).toBe(0);
        expect(r.stdout).toContain("Discord\tClean");
        expect(r.stdout).toContain("DiscordPTB\tVencordStub");
        expect(r.stdout).toContain("DiscordCanary\tForeign");
    });

    it("installs into an unmodified Discord, keeping the original and backing up Vencord", () => {
        const app = res("Discord", "app-1.0.9270");
        const before = sha(join(app, "app.asar"));
        const old = sha(join(res("Discord", "app-1.0.9100"), "app.asar"));
        const r = exec("--install", "Discord");
        expect(r.status, r.stderr + r.stdout).toBe(0);
        expect(sha(join(app, "_app.asar"))).toBe(before);
        const stub = readAsar(readFileSync(join(app, "app.asar")));
        expect(Object.keys(stub).sort()).toEqual(["index.js", "package.json"]);
        expect(stub["index.js"].startsWith("// Cipher stub v1")).toBe(true);
        expect(stub["index.js"]).toContain(`require(${JSON.stringify(join(dist, "patcher.js"))})`);
        expect(JSON.parse(stub["package.json"])).toEqual({ name: "discord", main: "index.js" });
        // The older version folder is left alone.
        expect(sha(join(res("Discord", "app-1.0.9100"), "app.asar"))).toBe(old);
        // New files in place, the official ones backed up.
        for (const f of ["patcher.js", "preload.js", "renderer.js", "renderer.css", "package.json", "cipher-build.txt"]) expect(existsSync(join(dist, f)), f).toBe(true);
        expect(readFileSync(join(dist, "renderer.js"), "utf8")).toContain("Cipher");
        const backups = readdirSync(join(roaming, "Vencord")).filter(n => n.startsWith("dist.backup-"));
        expect(backups).toHaveLength(1);
        expect(readFileSync(join(roaming, "Vencord", backups[0], "renderer.js"), "utf8")).toBe("official vencord");
        expect(exec("--list").stdout).toContain("Discord\tCipherStub");
    });

    it("never touches a Discord modified by other software", () => {
        const app = res("DiscordCanary", "app-1.0.1364");
        const before = [sha(join(app, "app.asar")), sha(join(app, "_app.asar"))];
        const r = exec("--install", "DiscordCanary");
        expect(r.status).toBe(1);
        expect([sha(join(app, "app.asar")), sha(join(app, "_app.asar"))]).toEqual(before);
    });

    it("leaves an existing Vencord stub exactly as it is", () => {
        const app = res("DiscordPTB", "app-1.0.1235");
        const before = sha(join(app, "app.asar"));
        const r = exec("--install", "DiscordPTB");
        expect(r.status, r.stderr).toBe(0);
        expect(sha(join(app, "app.asar"))).toBe(before);
        // Already Cipher's files: no second backup.
        expect(readdirSync(join(roaming, "Vencord")).filter(n => n.startsWith("dist.backup-"))).toHaveLength(1);
    });

    it("uninstalls: original Discord back, previous Vencord back, others untouched", () => {
        const ptb = sha(join(res("DiscordPTB", "app-1.0.1235"), "app.asar"));
        const canary = sha(join(res("DiscordCanary", "app-1.0.1364"), "app.asar"));
        const original = sha(join(res("Discord", "app-1.0.9270"), "_app.asar"));
        const r = exec("--uninstall");
        expect(r.status, r.stderr).toBe(0);
        const app = res("Discord", "app-1.0.9270");
        expect(existsSync(join(app, "_app.asar"))).toBe(false);
        expect(sha(join(app, "app.asar"))).toBe(original);
        expect(readFileSync(join(dist, "renderer.js"), "utf8")).toBe("official vencord");
        expect(existsSync(join(dist, "cipher-build.txt"))).toBe(false);
        expect(sha(join(res("DiscordPTB", "app-1.0.1235"), "app.asar"))).toBe(ptb);
        expect(sha(join(res("DiscordCanary", "app-1.0.1364"), "app.asar"))).toBe(canary);
        expect(exec("--list").stdout).toContain("Discord\tClean");
    });
});

run("Cipher-Setup.exe: which backup uninstall restores", () => {
    const roots: string[] = [];
    afterAll(() => roots.forEach(r => rmSync(r, { recursive: true, force: true })));

    function world(withVencord: boolean) {
        const root = mkdtempSync(join(tmpdir(), "cipher-exe-test-"));
        roots.push(root);
        const local = join(root, "Local"), roaming = join(root, "Roaming");
        const app = join(local, "Discord", "app-1.0.9270", "resources");
        mkdirSync(app, { recursive: true });
        writeFileSync(join(app, "app.asar"), Buffer.alloc(700 * 1024, 7));
        // A leftover backup folder from something else, newer by name than any real one.
        const stale = join(roaming, "Vencord", "dist.backup-29990101-000000");
        mkdirSync(stale, { recursive: true });
        writeFileSync(join(stale, "renderer.js"), "unrelated old files");
        const dist = join(roaming, "Vencord", "dist");
        if (withVencord) {
            mkdirSync(dist, { recursive: true });
            writeFileSync(join(dist, "renderer.js"), "official vencord");
            writeFileSync(join(dist, "patcher.js"), "official vencord patcher");
        }
        const exec = (...a: string[]) => spawnSync(exe, ["--local-appdata", local, "--appdata", roaming, ...a], { encoding: "utf8", timeout: 60_000 });
        return { dist, stale, exec };
    }

    it("puts back the files it replaced, not some other backup folder, even after an update", () => {
        const w = world(true);
        expect(w.exec("--install", "Discord").status).toBe(0);
        // Running the installer again (an update) must keep the record of the first backup.
        expect(w.exec("--install", "Discord").status).toBe(0);
        expect(readFileSync(join(w.dist, "cipher-build.txt"), "utf8")).toMatch(/^Backup: dist\.backup-\d{8}-\d{6}$/m);
        expect(w.exec("--uninstall").status).toBe(0);
        expect(readFileSync(join(w.dist, "renderer.js"), "utf8")).toBe("official vencord");
        expect(existsSync(w.stale)).toBe(true);
    });

    it("restores nothing when there was no Vencord before", () => {
        const w = world(false);
        expect(w.exec("--install", "Discord").status).toBe(0);
        expect(readFileSync(join(w.dist, "cipher-build.txt"), "utf8")).toMatch(/^Backup: none$/m);
        expect(w.exec("--uninstall").status).toBe(0);
        expect(existsSync(w.dist)).toBe(false);
        expect(readFileSync(join(w.stale, "renderer.js"), "utf8")).toBe("unrelated old files");
    });
});
