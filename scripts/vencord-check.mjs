#!/usr/bin/env node
/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Integration check: builds Cipher inside a real Vencord checkout.
 *
 *   1. shallow-clones Vencord at VENCORD_REF into .vencord/ (if missing)
 *   2. installs Vencord's dependencies with the pnpm version it pins
 *   3. adds Cipher's runtime dependencies at the versions in package.json
 *   4. copies src/ to .vencord/src/userplugins/cipher
 *   5. runs Vencord's TypeScript check and its production build
 */

import { execFileSync } from "node:child_process";
import { cpSync, existsSync, readFileSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const vencord = join(root, ".vencord");
const ref = process.env.VENCORD_REF ?? "v1.15.19";
if (!/^[\w./-]+$/.test(ref)) throw new Error("VENCORD_REF must be a plain tag or branch name.");
const isWin = process.platform === "win32";

/**
 * Runs a program. Only npx needs a shell on Windows (it's a .cmd script), and
 * a shell would read metacharacters, so every argument is checked first:
 * some come from the downloaded Vencord's package.json or the environment.
 */
function run(cmd, args, cwd = vencord) {
    const viaShell = isWin && cmd === "npx";
    if (viaShell) for (const a of args) if (!/^[\w@./:=-]+$/.test(a)) throw new Error(`Refusing to pass an unusual argument to npx: ${a}`);
    console.log(`\n$ ${cmd} ${args.join(" ")}`);
    execFileSync(viaShell ? "npx.cmd" : cmd, args, { cwd, stdio: "inherit", shell: viaShell });
}

if (!existsSync(vencord)) {
    run("git", ["clone", "--depth", "1", "--branch", ref, "https://github.com/Vendicated/Vencord.git", vencord], root);
}

const vencordPkg = JSON.parse(readFileSync(join(vencord, "package.json"), "utf8"));
const pnpmSpec = vencordPkg.packageManager?.startsWith("pnpm@") ? vencordPkg.packageManager : "pnpm@latest";
const pnpm = (...args) => run("npx", ["-y", pnpmSpec, ...args]);

const ours = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const deps = Object.entries(ours.dependencies).map(([n, v]) => `${n}@${v}`);

pnpm("install", "--frozen-lockfile");
pnpm("add", "-w", ...deps);

const target = join(vencord, "src", "userplugins", "cipher");
rmSync(target, { recursive: true, force: true });
cpSync(join(root, "src"), target, { recursive: true });

run("npx", ["tsc", "--noEmit"]);
pnpm("build");

console.log("\nCipher typechecks and builds inside Vencord " + ref + ".");
