import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { compareClosure, dependencyClosure } from "../scripts/lockfile.mjs";

const root = join(__dirname, "..");
const audited = JSON.parse(readFileSync(join(root, "scripts", "audited-deps.json"), "utf8"));

describe("install-time dependency check", () => {
    it("the audited list is exactly what this repository's lockfile resolves", () => {
        const closure = dependencyClosure(readFileSync(join(root, "pnpm-lock.yaml"), "utf8"), audited.root);
        expect(closure).toEqual(audited.packages);
        expect(Object.keys(closure)).toHaveLength(8);
        expect(Object.values(closure).every(h => typeof h === "string" && h.startsWith("sha512-"))).toBe(true);
    });

    it("the audited list matches package.json", () => {
        const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
        expect(Object.entries(pkg.dependencies).map(([n, v]) => `${n}@${v}`)).toEqual([audited.root]);
    });

    it("reports changed, extra and missing packages", () => {
        const expected = { "a@1": "sha512-A", "b@1": "sha512-B" };
        expect(compareClosure(expected, { "a@1": "sha512-A", "b@1": "sha512-B" })).toEqual([]);
        expect(compareClosure(expected, { "a@1": "sha512-X", "b@1": "sha512-B" })).toEqual([expect.stringContaining("different contents: a@1")]);
        expect(compareClosure(expected, { "a@1": "sha512-A", "b@1": "sha512-B", "evil@1": "sha512-E" })).toEqual(["not reviewed: evil@1"]);
        expect(compareClosure(expected, { "a@1": "sha512-A" })).toEqual(["missing: b@1"]);
    });

    it("follows dependencies through a pnpm lockfile", () => {
        const lock = [
            "lockfileVersion: '9.0'",
            "packages:",
            "  top@1.0.0:",
            "    resolution: {integrity: sha512-T}",
            "  '@s/mid@2.0.0':",
            "    resolution: {integrity: sha512-M}",
            "  leaf@3.0.0:",
            "    resolution: {integrity: sha512-L}",
            "  other@9.0.0:",
            "    resolution: {integrity: sha512-O}",
            "snapshots:",
            "  top@1.0.0:",
            "    dependencies:",
            "      '@s/mid': 2.0.0",
            "  '@s/mid@2.0.0':",
            "    dependencies:",
            "      leaf: 3.0.0",
            "  leaf@3.0.0: {}",
            "  other@9.0.0: {}",
            ""
        ].join("\r\n");
        expect(dependencyClosure(lock, "top@1.0.0")).toEqual({ "@s/mid@2.0.0": "sha512-M", "leaf@3.0.0": "sha512-L", "top@1.0.0": "sha512-T" });
        expect(() => dependencyClosure(lock, "absent@1.0.0")).toThrow();
    });
});
