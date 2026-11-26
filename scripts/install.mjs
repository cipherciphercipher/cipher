#!/usr/bin/env node
/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * One-command install: builds Vencord from source with Cipher in it.
 *
 *   node scripts/install.mjs                 build, then ask before installing into Discord
 *   node scripts/install.mjs --inject        build and run Vencord's own installer (pnpm inject)
 *   node scripts/install.mjs --deploy <dir>  build a standalone copy and put it into an existing
 *                                            Vencord dist folder (backed up first)
 *   node scripts/install.mjs --no-inject     only build
 *
 * Other options:
 *   --dir <path>      where to keep the Vencord checkout (default: ~/Vencord-Cipher)
 *   --vencord <path>  use an existing Vencord source checkout instead
 *
 * Running it again updates Cipher in place. Needs Node 18+ and git.
 *
 * What it checks:
 *  - Vencord is cloned at the release Cipher was tested with, and the commit
 *    hash must match (a moved tag stops the install);
 *  - after adding Cipher's one dependency, every package it pulls in must have
 *    exactly the integrity hash listed in scripts/audited-deps.json, i.e. the
 *    code that was reviewed in AUDIT.md;
 *  - an existing src/userplugins/cipher is only replaced if it is Cipher.
 */

import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { fileURLToPath } from "node:url";

import { compareClosure, dependencyClosure } from "./lockfile.mjs";

const VENCORD_TAG = "v1.15.19";
const VENCORD_COMMIT = "d086992fb674299a2fa05ac6432edc3a777389f3";
const VENCORD_REPO = "https://github.com/Vendicated/Vencord.git";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const isWin = process.platform === "win32";

/* ---------- arguments ---------- */

const args = process.argv.slice(2);
const flag = name => args.includes(name);
const option = name => {
    const i = args.indexOf(name);
    if (i === -1) return undefined;
    const v = args[i + 1];
    if (!v || v.startsWith("--")) fail(`${name} needs a value.`);
    return v;
};
const known = new Set(["--inject", "--no-inject", "--deploy", "--dir", "--vencord", "--help", "-h"]);
for (let i = 0; i < args.length; i++) {
    if (!known.has(args[i])) fail(`Unknown option ${args[i]}. Run with --help.`);
    if (["--deploy", "--dir", "--vencord"].includes(args[i])) i++;
}
if (flag("--help") || flag("-h")) {
    console.log(readFileSync(fileURLToPath(import.meta.url), "utf8").split("\n").slice(6, 20).map(l => l.replace(/^ \* ?/, "")).join("\n"));
    process.exit(0);
}

const deployTo = option("--deploy");
const ownCheckout = option("--vencord");
const vencord = resolve(ownCheckout ?? option("--dir") ?? join(homedir(), "Vencord-Cipher"));
if ([flag("--inject"), flag("--no-inject"), !!deployTo].filter(Boolean).length > 1)
    fail("Use only one of --inject, --no-inject and --deploy.");

/* ---------- helpers ---------- */

function fail(message) {
    console.error(`\n✖ ${message}`);
    process.exit(1);
}

function step(text) {
    console.log(`\n▶ ${text}`);
}

/** Runs a program directly (no shell), so paths with spaces are safe. */
function run(cmd, cmdArgs, cwd = vencord, capture = false) {
    if (!capture) console.log(`  $ ${cmd} ${cmdArgs.join(" ")}`);
    return execFileSync(cmd, cmdArgs, { cwd, stdio: capture ? ["ignore", "pipe", "inherit"] : "inherit", encoding: "utf8" });
}

/** npx is a .cmd script on Windows, which needs a shell; its arguments here never contain spaces or quotes. */
function npx(cmdArgs, cwd = vencord) {
    for (const a of cmdArgs) if (!/^[\w@./:=-]+$/.test(a)) fail(`Refusing to pass an unusual argument to npx: ${a}`);
    console.log(`  $ npx ${cmdArgs.join(" ")}`);
    execFileSync(isWin ? "npx.cmd" : "npx", cmdArgs, { cwd, stdio: "inherit", shell: isWin });
}

async function ask(question) {
    if (!process.stdin.isTTY) return false;
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    const answer = await rl.question(`${question} [y/N] `);
    rl.close();
    return /^y(es)?$/i.test(answer.trim());
}

/* ---------- 1. tools ---------- */

step("Checking Node and git");
const [major] = process.versions.node.split(".").map(Number);
if (major < 18) fail(`Node 18 or newer is needed; this is ${process.versions.node}. Get it from https://nodejs.org.`);
try {
    run("git", ["--version"], root, true);
} catch {
    fail("git isn't installed (or not on PATH). Get it from https://git-scm.com.");
}

/* ---------- 2. Vencord source ---------- */

const head = () => run("git", ["rev-parse", "HEAD"], vencord, true).trim();

if (ownCheckout) {
    step(`Using your Vencord checkout at ${vencord}`);
    const pkg = existsSync(join(vencord, "package.json")) && JSON.parse(readFileSync(join(vencord, "package.json"), "utf8"));
    if (pkg?.name !== "vencord") fail(`${vencord} doesn't look like a Vencord source checkout.`);
    if (head() !== VENCORD_COMMIT) console.log(`  Note: Cipher was tested with Vencord ${VENCORD_TAG}; yours is at another commit. It will probably work.`);
} else if (!existsSync(vencord)) {
    step(`Downloading Vencord ${VENCORD_TAG} into ${vencord}`);
    run("git", ["clone", "--depth", "1", "--branch", VENCORD_TAG, VENCORD_REPO, vencord], root);
} else {
    step(`Updating the Vencord checkout in ${vencord}`);
    if (!existsSync(join(vencord, ".git"))) fail(`${vencord} exists but isn't a git checkout. Pick another folder with --dir.`);
    if (head() !== VENCORD_COMMIT) {
        // The previous run added Cipher's dependency to these two files.
        run("git", ["checkout", "--", "package.json", "pnpm-lock.yaml"]);
        run("git", ["fetch", "--depth", "1", "origin", "tag", VENCORD_TAG]);
        run("git", ["checkout", "--detach", VENCORD_COMMIT]);
    }
}
if (!ownCheckout && head() !== VENCORD_COMMIT)
    fail(`Vencord's ${VENCORD_TAG} tag points at ${head()}, not the expected ${VENCORD_COMMIT}. Stopping in case it was tampered with.`);

/* ---------- 3. dependencies ---------- */

const vencordPkg = JSON.parse(readFileSync(join(vencord, "package.json"), "utf8"));
const pnpmSpec = /^pnpm@[\d.]+$/.test(vencordPkg.packageManager ?? "") ? vencordPkg.packageManager : "pnpm@10";
const pnpm = (...a) => npx(["-y", pnpmSpec, ...a]);

const audited = JSON.parse(readFileSync(join(root, "scripts", "audited-deps.json"), "utf8"));
const ours = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const depSpecs = Object.entries(ours.dependencies).map(([n, v]) => `${n}@${v}`);
if (depSpecs.length !== 1 || depSpecs[0] !== audited.root) fail("package.json and scripts/audited-deps.json disagree about Cipher's dependencies.");

step("Installing Vencord's dependencies (from its lockfile)");
pnpm("install", "--frozen-lockfile");

step(`Adding Cipher's dependency ${audited.root}`);
pnpm("add", "-w", ...depSpecs);

step("Checking the added packages against the reviewed ones (AUDIT.md)");
const actual = dependencyClosure(readFileSync(join(vencord, "pnpm-lock.yaml"), "utf8"), audited.root);
const problems = compareClosure(audited.packages, actual);
if (problems.length) {
    fail("The packages npm delivered aren't the ones that were reviewed:\n  " + problems.join("\n  ")
        + "\nNothing was built. Please report this at the project's GitHub issues.");
}
console.log(`  ${Object.keys(actual).length} packages, all identical to the reviewed versions.`);

/* ---------- 4. Cipher itself ---------- */

step("Copying Cipher into Vencord");
const userplugins = join(vencord, "src", "userplugins");
const target = join(userplugins, "cipher");
if (existsSync(target)) {
    const index = join(target, "index.tsx");
    const isCipher = existsSync(index) && /name:\s*"Cipher"/.test(readFileSync(index, "utf8"));
    if (!isCipher) fail(`${target} exists and isn't Cipher. Move it away and run this again.`);
    rmSync(target, { recursive: true, force: true });
}
mkdirSync(userplugins, { recursive: true });
cpSync(join(root, "src"), target, { recursive: true });

/* ---------- 5. build ---------- */

const standalone = !!deployTo;
step(standalone ? "Building Vencord (standalone, updater off)" : "Building Vencord");
// The standalone copy has Vencord's updater turned off: an update from the
// official releases would replace this build and remove Cipher. Run this
// script again to update.
pnpm("build", ...standalone ? ["--standalone", "--disable-updater"] : []);

/* ---------- 6. install into Discord ---------- */

const DIST_FILES = /^(?:patcher|preload|renderer)\.(?:js|css)(?:\.map|\.LEGAL\.txt)?$/;

if (deployTo) {
    const dest = resolve(deployTo);
    if (!existsSync(dest)) fail(`${dest} doesn't exist.`);
    const existing = readdirSync(dest);
    if (!existing.includes("renderer.js") && !existing.includes("patcher.js")) fail(`${dest} doesn't look like a Vencord dist folder.`);
    const stamp = new Date().toISOString().replace(/[:T]/g, "-").slice(0, 19);
    const backup = `${dest}.backup-${stamp}`;
    step(`Backing up ${dest} to ${backup}`);
    cpSync(dest, backup, { recursive: true });
    step(`Copying the build into ${dest}`);
    const built = join(vencord, "dist");
    const files = readdirSync(built).filter(f => DIST_FILES.test(f));
    for (const f of files) {
        cpSync(join(built, f), join(dest, f));
        if (!readFileSync(join(built, f)).equals(readFileSync(join(dest, f)))) fail(`Copying ${f} failed. Restore from ${backup}.`);
    }
    console.log(`  ${files.length} files copied and checked.`);
    console.log("\n✔ Done. Fully quit Discord (from the tray icon too) and open it again, then enable Cipher in Settings → Vencord → Plugins.");
} else {
    const inject = flag("--inject") || (!flag("--no-inject") && await ask("\nInstall into Discord now with Vencord's installer (pnpm inject)?"));
    if (inject) {
        step("Running Vencord's installer");
        pnpm("inject");
        console.log("\n✔ Done. Restart Discord, then enable Cipher in Settings → Vencord → Plugins.");
    } else {
        console.log(`\n✔ Built in ${join(vencord, "dist")}. To install into Discord later, run this script with --inject,`);
        console.log(`  or run "npx ${pnpmSpec} inject" in ${vencord}.`);
    }
}
