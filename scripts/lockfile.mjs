/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Reads a pnpm v9 lockfile just far enough to list a package and everything
 * it depends on, with each package's integrity hash. Used to check that the
 * code an install pulls in is exactly the code that was reviewed (AUDIT.md).
 */

const KEY_RE = /^ {2}'?([^'\s][^']*?)'?:(?:\s*\{\})?\s*$/;
const DEP_RE = /^ {6}'?([^'\s][^']*?)'?:\s*'?([^'\s]+?)'?\s*$/;

/** @returns {{ integrity: Map<string, string>, deps: Map<string, string[]> }} */
export function parseLockfile(text) {
    const integrity = new Map();
    const deps = new Map();
    let section = "";
    let key = "";
    let inDeps = false;
    for (const raw of text.replace(/\r\n/g, "\n").split("\n")) {
        if (/^\S/.test(raw)) {
            section = raw.replace(/:.*$/, "");
            key = "";
            continue;
        }
        const k = KEY_RE.exec(raw);
        if (k) {
            key = k[1];
            inDeps = false;
            if (section === "snapshots" && !deps.has(key)) deps.set(key, []);
            continue;
        }
        if (!key) continue;
        if (section === "packages") {
            const m = /integrity: ([^,}\s]+)/.exec(raw);
            if (m) integrity.set(key, m[1]);
        } else if (section === "snapshots") {
            if (/^ {4}\S/.test(raw)) inDeps = /^ {4}(?:dependencies|optionalDependencies):\s*$/.test(raw);
            else if (inDeps) {
                const d = DEP_RE.exec(raw);
                if (d) deps.get(key).push(`${d[1]}@${d[2]}`);
            }
        }
    }
    return { integrity, deps };
}

/** Every package `root` (name@version) pulls in, including itself, sorted, with integrity hashes. */
export function dependencyClosure(text, root) {
    const { integrity, deps } = parseLockfile(text);
    if (!integrity.has(root)) throw new Error(`${root} isn't in the lockfile`);
    const seen = new Set();
    const todo = [root];
    while (todo.length) {
        const id = todo.pop();
        if (seen.has(id)) continue;
        seen.add(id);
        todo.push(...deps.get(id) ?? []);
    }
    return Object.fromEntries([...seen].sort().map(id => [id, integrity.get(id) ?? null]));
}

/** Differences between an expected and an actual closure, as readable lines. */
export function compareClosure(expected, actual) {
    const problems = [];
    for (const [id, hash] of Object.entries(actual)) {
        if (!(id in expected)) problems.push(`not reviewed: ${id}`);
        else if (expected[id] !== hash) problems.push(`different contents: ${id} (expected ${expected[id]}, got ${hash})`);
    }
    for (const id of Object.keys(expected)) if (!(id in actual)) problems.push(`missing: ${id}`);
    return problems;
}
