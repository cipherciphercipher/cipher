#!/usr/bin/env node
/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Builds dist-exe/Cipher-Setup.exe (Windows only):
 *  1. the same checked, standalone Vencord + Cipher build the installer makes
 *     (scripts/install.mjs --build-only: pinned Vencord commit, audited deps);
 *  2. installer/CipherSetup.cs compiled with the C# compiler that ships with
 *     Windows (.NET Framework 4.8), with the built files embedded.
 * Nothing is downloaded beyond what install.mjs already fetches.
 *
 *   node scripts/build-exe.mjs [--vencord <checkout>]
 */

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const args = process.argv.slice(2);
const vIdx = args.indexOf("--vencord");
const vencord = resolve(vIdx >= 0 ? args[vIdx + 1] : join(homedir(), "Vencord-Cipher"));

if (process.platform !== "win32") {
    console.error("Cipher-Setup.exe is built on Windows (it uses the C# compiler that comes with Windows).");
    process.exit(1);
}
const csc = join(process.env.WINDIR ?? "C:\\Windows", "Microsoft.NET", "Framework64", "v4.0.30319", "csc.exe");
if (!existsSync(csc)) {
    console.error(`The C# compiler that ships with Windows wasn't found at ${csc}.`);
    process.exit(1);
}

// The files Discord needs (no source maps, nothing for Vesktop). Must match Core.DistFiles in CipherSetup.cs.
const DIST_FILES = ["package.json", "patcher.js", "preload.js", "renderer.js", "renderer.css", "patcher.js.LEGAL.txt", "renderer.js.LEGAL.txt"];

console.log("▶ Building Vencord + Cipher (standalone, updater off)");
execFileSync(process.execPath, [join(root, "scripts", "install.mjs"), "--build-only", ...vIdx >= 0 ? ["--vencord", vencord] : ["--dir", vencord]], { stdio: "inherit" });

const built = join(vencord, "dist");
const work = join(root, "installer", "build");
mkdirSync(work, { recursive: true });
// Vencord's own installer puts an empty package.json next to the files; so do we.
writeFileSync(join(work, "package.json"), "{}");
const source = (f) => f === "package.json" ? join(work, f) : join(built, f);
for (const f of DIST_FILES) if (!existsSync(source(f))) throw new Error(`The build is missing ${f}.`);
// The embedded files must not carry anything about the machine that built them.
for (const f of DIST_FILES) {
    const text = readFileSync(source(f), "utf8");
    if (/[A-Za-z]:[\\/]+Users[\\/]/i.test(text) || text.includes(homedir())) throw new Error(`${f} contains a local path; refusing to embed it.`);
}

const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
let commit = "local";
try { commit = execFileSync("git", ["rev-parse", "--short=12", "HEAD"], { cwd: root, encoding: "utf8" }).trim(); } catch { /* not a git checkout */ }
if (!/^\d+\.\d+\.\d+$/.test(pkg.version) || !/^[\w]+$/.test(commit)) throw new Error("Unexpected version or commit.");

const out = join(root, "dist-exe");
mkdirSync(out, { recursive: true });
writeFileSync(join(work, "Version.cs"),
    `[assembly: System.Reflection.AssemblyVersion("${pkg.version}.0")]\n` +
    `[assembly: System.Reflection.AssemblyFileVersion("${pkg.version}.0")]\n` +
    `[assembly: System.Reflection.AssemblyInformationalVersion("${pkg.version}+${commit}")]\n`);

const exe = join(out, "Cipher-Setup.exe");
console.log("▶ Compiling Cipher-Setup.exe with the built-in C# compiler");
execFileSync(csc, [
    "/nologo", "/target:winexe", "/optimize+",
    `/out:${exe}`,
    `/win32manifest:${join(root, "installer", "app.manifest")}`,
    "/reference:System.Windows.Forms.dll", "/reference:System.Drawing.dll", "/reference:System.Web.Extensions.dll",
    ...DIST_FILES.map(f => `/resource:${source(f)},dist/${f}`),
    join(root, "installer", "CipherSetup.cs"), join(work, "Version.cs")
], { stdio: "inherit" });

const hash = createHash("sha256").update(readFileSync(exe)).digest("hex");
writeFileSync(`${exe}.sha256`, `${hash}  Cipher-Setup.exe\n`);
console.log(`\n✔ ${exe}\n  SHA-256 ${hash}`);
