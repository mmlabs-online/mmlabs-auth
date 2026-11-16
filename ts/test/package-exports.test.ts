import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8")) as Record<
  string,
  unknown
>;

const IMPORT_RE = /(?:import|export)\s+(?:type\s+)?(?:[^'"]*?\s+from\s+)?["']([^"']+)["']/g;

/** Every module specifier in the files reachable from `entry` via relative imports. */
function importGraph(entry: string): { files: string[]; specifiers: string[] } {
  const files = new Set<string>();
  const specifiers: string[] = [];
  const visit = (file: string) => {
    if (files.has(file)) return;
    files.add(file);
    for (const [, spec] of readFileSync(file, "utf8").matchAll(IMPORT_RE)) {
      if (spec === undefined) continue;
      specifiers.push(spec);
      if (!spec.startsWith(".")) continue;
      const base = resolve(dirname(file), spec).replace(/\.js$/, "");
      const next = [`${base}.ts`, `${base}.tsx`].find((f) => existsSync(f));
      if (next === undefined) throw new Error(`unresolved import ${spec} in ${file}`);
      visit(next);
    }
  };
  visit(entry);
  return { files: [...files], specifiers };
}

describe("package exports", () => {
  it("exports . and ./react", () => {
    expect(pkg.exports).toEqual({
      ".": { types: "./dist/index.d.ts", import: "./dist/index.js" },
      "./react": { types: "./dist/react/index.d.ts", import: "./dist/react/index.js" },
    });
    expect(existsSync(resolve(root, "src/index.ts"))).toBe(true);
    expect(existsSync(resolve(root, "src/react/index.tsx"))).toBe(true);
    expect(pkg.peerDependencies).toEqual({ react: ">=18" });
    expect(pkg.peerDependenciesMeta).toEqual({ react: { optional: true } });
  });

  it("core does not import react", () => {
    const { files, specifiers } = importGraph(resolve(root, "src/index.ts"));
    expect(files.length).toBeGreaterThan(5);
    expect(files.some((f) => f.includes(`${resolve(root, "src/react")}`))).toBe(false);
    expect(specifiers.filter((s) => s === "react" || s.startsWith("react/"))).toEqual([]);
    expect(specifiers.filter((s) => !s.startsWith("."))).toEqual([]);
    // The React entry does import react (the graph walk sees real imports).
    expect(importGraph(resolve(root, "src/react/index.tsx")).specifiers).toContain("react");
  });

  it("no runtime dependencies", () => {
    const deps = pkg.dependencies as Record<string, string> | undefined;
    expect(deps === undefined || Object.keys(deps).length === 0).toBe(true);
    expect(pkg.optionalDependencies).toBeUndefined();
    expect(pkg.bundleDependencies ?? pkg.bundledDependencies).toBeUndefined();
  });

  it("no lifecycle scripts", () => {
    const scripts = Object.keys((pkg.scripts as Record<string, string> | undefined) ?? {});
    const lifecycle = [
      "preinstall",
      "install",
      "postinstall",
      "prepublish",
      "preprepare",
      "prepare",
      "postprepare",
      "prepack",
      "postpack",
      "prepublishOnly",
      "publish",
      "postpublish",
    ];
    expect(scripts.filter((s) => lifecycle.includes(s))).toEqual([]);
    expect(scripts.sort()).toEqual(["build", "lint", "test", "typecheck"]);
  });
});
