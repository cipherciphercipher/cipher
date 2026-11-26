#!/usr/bin/env node
/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Mechanical checks used by AUDIT.md for files that duplicate code which was
 * read line by line:
 *
 *  1. Every shipped `.ts` source compiles (types and comments stripped) to
 *     exactly the same program as its `.js` counterpart.
 *  2. Every doc-comment line in a `.d.ts` appears verbatim in the `.ts` sources,
 *     and the non-comment lines of each `.d.ts` are printed for reading.
 *  3. `.map` files are plain source maps that only reference the package's own
 *     sources, and any embedded `sourcesContent` equals those sources.
 *
 * Usage: node scripts/audit-check.mjs <package dir> [--print-dts]
 */

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import ts from "typescript";

const dir = resolve(process.argv[2] ?? ".");
const printDts = process.argv.includes("--print-dts");

function walk(d, out = []) {
    for (const name of readdirSync(d)) {
        if (name === "node_modules") continue;
        const p = join(d, name);
        if (statSync(p).isDirectory()) walk(p, out);
        else out.push(p);
    }
    return out;
}

const files = walk(dir);
const rel = p => relative(dir, p).replace(/\\/g, "/");

const printer = ts.createPrinter({ removeComments: true });
function canonical(code, fileName) {
    const js = ts.transpileModule(code, {
        fileName,
        compilerOptions: { target: ts.ScriptTarget.ESNext, module: ts.ModuleKind.ESNext, removeComments: true, useDefineForClassFields: true, verbatimModuleSyntax: false, rewriteRelativeImportExtensions: true }
    }).outputText;
    const sf = ts.createSourceFile("x.js", js, ts.ScriptTarget.ESNext, false, ts.ScriptKind.JS);
    return printer.printFile(sf);
}

// The .js file a .ts source compiles to: src/a/b.ts -> a/b.js, index.ts -> index.js
function jsFor(tsPath) {
    const r = rel(tsPath).replace(/\.ts$/, ".js");
    for (const cand of [r.replace(/^src\//, ""), r]) {
        const p = join(dir, cand);
        if (existsSync(p)) return p;
    }
    return null;
}

let failures = 0;
const sources = files.filter(f => f.endsWith(".ts") && !f.endsWith(".d.ts"));
console.log(`## ${rel(dir) || dir}: ${files.length} files, ${sources.length} .ts sources`);

for (const t of sources) {
    const j = jsFor(t);
    if (!j) {
        console.log(`NO-JS   ${rel(t)}  (no compiled counterpart: read it in full)`);
        failures++;
        continue;
    }
    const a = canonical(readFileSync(t, "utf8"), t);
    const b = canonical(readFileSync(j, "utf8"), j);
    if (a === b) console.log(`SAME    ${rel(t)} == ${rel(j)}`);
    else {
        failures++;
        const al = a.split("\n"), bl = b.split("\n");
        let i = 0;
        while (i < al.length && al[i] === bl[i]) i++;
        console.log(`DIFFER  ${rel(t)} vs ${rel(j)} at canonical line ${i + 1}:\n  ts: ${al[i]}\n  js: ${bl[i]}`);
    }
}

const sourceLines = new Set(sources.flatMap(t => readFileSync(t, "utf8").split("\n").map(l => l.trim())));
for (const d of files.filter(f => f.endsWith(".d.ts"))) {
    const lines = readFileSync(d, "utf8").split("\n");
    let comments = 0;
    const missing = [];
    const code = [];
    let inComment = false;
    lines.forEach((l, i) => {
        const t = l.trim();
        const isComment = inComment || t.startsWith("/*") || t.startsWith("*") || t.startsWith("//");
        if (t.startsWith("/*")) inComment = !t.includes("*/");
        else if (inComment && t.includes("*/")) inComment = false;
        if (isComment) {
            comments++;
            // The standard pointer to this file's own source map is expected.
            const ownMap = t === `//# sourceMappingURL=${d.split(/[\\/]/).pop()}.map`;
            if (sources.length && !ownMap && !sourceLines.has(t)) missing.push(`${i + 1}: ${t}`);
        } else if (t) code.push(`${String(i + 1).padStart(5)}  ${l}`);
    });
    if (missing.length) failures++;
    console.log(`DTS     ${rel(d)}: ${comments} comment lines, ${missing.length} not verbatim in sources, ${code.length} code lines`);
    for (const m of missing) console.log(`        unmatched comment ${m}`);
    if (printDts) for (const c of code) console.log(`        ${c}`);
}

for (const m of files.filter(f => f.endsWith(".map"))) {
    let map;
    try {
        map = JSON.parse(readFileSync(m, "utf8"));
    } catch {
        console.log(`MAP-BAD ${rel(m)}: not JSON`);
        failures++;
        continue;
    }
    const keys = Object.keys(map).sort().join(",");
    const problems = [];
    if (!/^(file,)?(ignoreList,)?mappings,(names,)?sourceRoot,sources(,sourcesContent)?,version$|^(file,)?mappings,(names,)?sources(,sourcesContent)?,version$/.test(keys)) problems.push(`unexpected keys ${keys}`);
    if (map.version !== 3) problems.push("version != 3");
    if (typeof map.mappings !== "string" || !/^[A-Za-z0-9+/,;]*$/.test(map.mappings)) problems.push("mappings not base64-VLQ");
    (map.sources ?? []).forEach((s, i) => {
        const target = resolve(dirname(m), map.sourceRoot ?? "", s);
        if (!target.startsWith(dir)) problems.push(`source outside package: ${s}`);
        else if (!existsSync(target)) problems.push(`missing source: ${s}`);
        else if (map.sourcesContent?.[i] != null && map.sourcesContent[i] !== readFileSync(target, "utf8")) problems.push(`sourcesContent differs from ${s}`);
    });
    if (problems.length) failures++;
    console.log(`MAP     ${rel(m)}: ${problems.length ? "PROBLEMS: " + problems.join("; ") : `ok (${(map.sources ?? []).length} source, ${map.sourcesContent ? "with" : "no"} embedded content)`}`);
}

console.log(failures ? `\n${failures} item(s) need manual reading.` : "\nAll mechanical checks passed.");
process.exitCode = failures ? 1 : 0;
