import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { rankVulnsByReach } from "../src/reachvuln.js";

/**
 * All tests are pure local computation over inline graphs:
 * no filesystem and no network. Direct and transitive
 * reachability through local edges, cycles, the names
 * intersection hit/miss, empty vulnerable_exports, the
 * imported-unreachable and not-imported classes, reached_via
 * contents and sorting, rank ordering with its tie-breaks,
 * counts, empty inputs, and every validation path are each
 * pinned.
 */

const rank = (args: unknown) => rankVulnsByReach(args);

describe("rankVulnsByReach — direct reachability", () => {
  it("an entry point importing the vulnerable export is reachable", () => {
    const out = rank({
      vulnerabilities: [
        { id: "CVE-1", package: "lodash", severity: "high", vulnerable_exports: ["merge"] },
      ],
      modules: [
        { path: "src/app.ts", imports: [{ package: "lodash", names: ["merge"] }] },
      ],
      entry_points: ["src/app.ts"],
    });
    assert.deepEqual(out, {
      ranked: [
        {
          id: "CVE-1",
          package: "lodash",
          severity: "high",
          reachability: "reachable",
          rank_score: 90,
          reached_via: ["src/app.ts"],
        },
      ],
      counts: { reachable: 1, imported_unreachable: 0, not_imported: 0 },
    });
  });

  it("severity weights are critical 40, high 30, medium 20, low 10 (x3 reachable)", () => {
    const scores: Record<string, number> = {};
    for (const severity of ["critical", "high", "medium", "low"]) {
      const out = rank({
        vulnerabilities: [{ id: "V", package: "p", severity }],
        modules: [{ path: "m", imports: [{ package: "p", names: [] }] }],
        entry_points: ["m"],
      });
      scores[severity] = out.ranked[0].rank_score;
    }
    assert.deepEqual(scores, { critical: 120, high: 90, medium: 60, low: 30 });
  });
});

describe("rankVulnsByReach — transitive reachability and cycles", () => {
  const graph = [
    { path: "src/main.ts", imports: [{ package: "src/a.ts", names: [] }] },
    { path: "src/a.ts", imports: [{ package: "src/b.ts", names: [] }] },
    { path: "src/b.ts", imports: [{ package: "evilpkg", names: ["run"] }] },
    { path: "src/dead.ts", imports: [{ package: "otherpkg", names: ["run"] }] },
  ];

  it("reachability flows transitively through local edges", () => {
    const out = rank({
      vulnerabilities: [
        { id: "V1", package: "evilpkg", severity: "critical", vulnerable_exports: ["run"] },
      ],
      modules: graph,
      entry_points: ["src/main.ts"],
    });
    assert.equal(out.ranked[0].reachability, "reachable");
    assert.deepEqual(out.ranked[0].reached_via, ["src/b.ts"]);
    assert.equal(out.ranked[0].rank_score, 120);
  });

  it("a module not reached through local edges does not make a finding reachable", () => {
    const out = rank({
      vulnerabilities: [
        { id: "V2", package: "otherpkg", severity: "critical", vulnerable_exports: ["run"] },
      ],
      modules: graph,
      entry_points: ["src/main.ts"],
    });
    assert.equal(out.ranked[0].reachability, "imported_unreachable");
    assert.deepEqual(out.ranked[0].reached_via, []);
    assert.equal(out.ranked[0].rank_score, 40);
  });

  it("cycles in local edges are safe and still reach behind the cycle", () => {
    const out = rank({
      vulnerabilities: [
        { id: "V3", package: "loopkg", severity: "medium", vulnerable_exports: [] },
      ],
      modules: [
        { path: "a", imports: [{ package: "b", names: [] }] },
        {
          path: "b",
          imports: [
            { package: "a", names: [] },
            { package: "loopkg", names: ["anything"] },
          ],
        },
      ],
      entry_points: ["a"],
    });
    assert.equal(out.ranked[0].reachability, "reachable");
    assert.deepEqual(out.ranked[0].reached_via, ["b"]);
  });

  it("a self-importing module terminates and is reachable as an entry point", () => {
    const out = rank({
      vulnerabilities: [{ id: "V4", package: "selfpkg", severity: "low" }],
      modules: [
        {
          path: "s",
          imports: [
            { package: "s", names: [] },
            { package: "selfpkg", names: [] },
          ],
        },
      ],
      entry_points: ["s"],
    });
    assert.equal(out.ranked[0].reachability, "reachable");
  });
});

describe("rankVulnsByReach — names intersection", () => {
  const base = (names: string[], vulnExports?: string[]) => ({
    vulnerabilities: [
      {
        id: "V",
        package: "pkg",
        severity: "high",
        ...(vulnExports === undefined ? {} : { vulnerable_exports: vulnExports }),
      },
    ],
    modules: [{ path: "m", imports: [{ package: "pkg", names }] }],
    entry_points: ["m"],
  });

  it("an intersecting name makes the finding reachable", () => {
    const out = rank(base(["safe", "bad"], ["bad", "worse"]));
    assert.equal(out.ranked[0].reachability, "reachable");
  });

  it("no intersecting name makes it imported_unreachable, not reachable", () => {
    const out = rank(base(["safe"], ["bad"]));
    assert.equal(out.ranked[0].reachability, "imported_unreachable");
    assert.equal(out.ranked[0].rank_score, 30);
    assert.deepEqual(out.ranked[0].reached_via, []);
  });

  it("an empty names list cannot intersect", () => {
    const out = rank(base([], ["bad"]));
    assert.equal(out.ranked[0].reachability, "imported_unreachable");
  });

  it("empty vulnerable_exports means any import by a reachable module counts", () => {
    assert.equal(rank(base(["anything"], [])).ranked[0].reachability, "reachable");
    assert.equal(rank(base([], [])).ranked[0].reachability, "reachable");
  });

  it("omitted vulnerable_exports defaults to [] (any import counts)", () => {
    assert.equal(rank(base(["whatever"])).ranked[0].reachability, "reachable");
  });

  it("a names hit in an unreachable module does not satisfy the reachable condition", () => {
    const out = rank({
      vulnerabilities: [
        { id: "V", package: "pkg", severity: "critical", vulnerable_exports: ["bad"] },
      ],
      modules: [
        { path: "entry", imports: [{ package: "pkg", names: ["safe"] }] },
        { path: "dead", imports: [{ package: "pkg", names: ["bad"] }] },
      ],
      entry_points: ["entry"],
    });
    assert.equal(out.ranked[0].reachability, "imported_unreachable");
    assert.deepEqual(out.ranked[0].reached_via, []);
  });

  it("an empty-string name is accepted but never matches a vulnerable export", () => {
    const out = rank(base([""], ["bad"]));
    assert.equal(out.ranked[0].reachability, "imported_unreachable");
  });
});

describe("rankVulnsByReach — imported_unreachable and not_imported", () => {
  it("a package imported only by an unreachable module is imported_unreachable", () => {
    const out = rank({
      vulnerabilities: [{ id: "V", package: "pkg", severity: "medium" }],
      modules: [
        { path: "entry", imports: [] },
        { path: "dead", imports: [{ package: "pkg", names: [] }] },
      ],
      entry_points: ["entry"],
    });
    assert.equal(out.ranked[0].reachability, "imported_unreachable");
    assert.equal(out.ranked[0].rank_score, 20);
  });

  it("a package no module imports is not_imported with score 0", () => {
    const out = rank({
      vulnerabilities: [{ id: "V", package: "ghost", severity: "critical" }],
      modules: [{ path: "entry", imports: [{ package: "other", names: [] }] }],
      entry_points: ["entry"],
    });
    assert.equal(out.ranked[0].reachability, "not_imported");
    assert.equal(out.ranked[0].rank_score, 0);
    assert.deepEqual(out.ranked[0].reached_via, []);
  });
});

describe("rankVulnsByReach — reached_via", () => {
  it("reached_via is the sorted distinct satisfying reachable module paths", () => {
    const out = rank({
      vulnerabilities: [
        { id: "V", package: "pkg", severity: "low", vulnerable_exports: ["x"] },
      ],
      modules: [
        {
          path: "z.ts",
          imports: [
            { package: "pkg", names: ["x"] },
            { package: "pkg", names: ["x"] },
          ],
        },
        { path: "a.ts", imports: [{ package: "pkg", names: ["x"] }] },
        { path: "m.ts", imports: [{ package: "pkg", names: ["nope"] }] },
        { path: "dead.ts", imports: [{ package: "pkg", names: ["x"] }] },
      ],
      entry_points: ["z.ts", "a.ts", "m.ts"],
    });
    assert.deepEqual(out.ranked[0].reached_via, ["a.ts", "z.ts"]);
  });

  it("reached_via is [] for imported_unreachable and not_imported findings", () => {
    const out = rank({
      vulnerabilities: [
        { id: "A", package: "only-dead", severity: "low" },
        { id: "B", package: "nowhere", severity: "low" },
      ],
      modules: [
        { path: "entry", imports: [] },
        { path: "dead", imports: [{ package: "only-dead", names: [] }] },
      ],
      entry_points: ["entry"],
    });
    for (const r of out.ranked) assert.deepEqual(r.reached_via, []);
  });
});

describe("rankVulnsByReach — ordering and counts", () => {
  it("orders by rank score descending", () => {
    const out = rank({
      vulnerabilities: [
        { id: "low-reach", package: "a", severity: "low" },
        { id: "crit-dead", package: "b", severity: "critical" },
        { id: "crit-none", package: "c", severity: "critical" },
      ],
      modules: [
        { path: "entry", imports: [{ package: "a", names: [] }] },
        { path: "dead", imports: [{ package: "b", names: [] }] },
      ],
      entry_points: ["entry"],
    });
    // crit-dead: 40x1=40, low-reach: 10x3=30, crit-none: 0.
    assert.deepEqual(
      out.ranked.map((r) => r.id),
      ["crit-dead", "low-reach", "crit-none"],
    );
    assert.deepEqual(out.counts, { reachable: 1, imported_unreachable: 1, not_imported: 1 });
  });

  it("same score breaks by severity weight descending", () => {
    const out = rank({
      vulnerabilities: [
        { id: "low-reach", package: "a", severity: "low" },
        { id: "high-dead", package: "b", severity: "high" },
      ],
      modules: [
        { path: "entry", imports: [{ package: "a", names: [] }] },
        { path: "dead", imports: [{ package: "b", names: [] }] },
      ],
      entry_points: ["entry"],
    });
    // Both score 30; high (30) outweighs low (10).
    assert.deepEqual(
      out.ranked.map((r) => r.id),
      ["high-dead", "low-reach"],
    );
  });

  it("same score and same weight break by id ascending", () => {
    const out = rank({
      vulnerabilities: [
        { id: "CVE-B", package: "a", severity: "critical" },
        { id: "CVE-A", package: "b", severity: "critical" },
      ],
      modules: [{ path: "entry", imports: [{ package: "a", names: [] }, { package: "b", names: [] }] }],
      entry_points: ["entry"],
    });
    assert.deepEqual(
      out.ranked.map((r) => r.id),
      ["CVE-A", "CVE-B"],
    );
  });

  it("not_imported findings all score 0 and order by weight then id", () => {
    const out = rank({
      vulnerabilities: [
        { id: "z-low", package: "x", severity: "low" },
        { id: "a-crit", package: "y", severity: "critical" },
        { id: "b-crit", package: "z", severity: "critical" },
      ],
      modules: [],
      entry_points: [],
    });
    assert.deepEqual(
      out.ranked.map((r) => r.id),
      ["a-crit", "b-crit", "z-low"],
    );
    assert.deepEqual(out.counts, { reachable: 0, imported_unreachable: 0, not_imported: 3 });
  });

  it("counts tally each class across a mixed set", () => {
    const out = rank({
      vulnerabilities: [
        { id: "1", package: "r", severity: "low" },
        { id: "2", package: "r2", severity: "low" },
        { id: "3", package: "u", severity: "low" },
        { id: "4", package: "n", severity: "low" },
        { id: "5", package: "n2", severity: "low" },
      ],
      modules: [
        {
          path: "entry",
          imports: [
            { package: "r", names: [] },
            { package: "r2", names: [] },
          ],
        },
        { path: "dead", imports: [{ package: "u", names: [] }] },
      ],
      entry_points: ["entry"],
    });
    assert.deepEqual(out.counts, { reachable: 2, imported_unreachable: 1, not_imported: 2 });
  });
});

describe("rankVulnsByReach — empty inputs", () => {
  it("empty vulnerabilities yields an empty ranked list and zero counts", () => {
    const out = rank({ vulnerabilities: [], modules: [], entry_points: [] });
    assert.deepEqual(out, {
      ranked: [],
      counts: { reachable: 0, imported_unreachable: 0, not_imported: 0 },
    });
  });

  it("empty modules makes every finding not_imported", () => {
    const out = rank({
      vulnerabilities: [{ id: "V", package: "p", severity: "high" }],
      modules: [],
      entry_points: [],
    });
    assert.equal(out.ranked[0].reachability, "not_imported");
  });

  it("empty entry_points means nothing is reachable, even when imported", () => {
    const out = rank({
      vulnerabilities: [{ id: "V", package: "p", severity: "high" }],
      modules: [{ path: "m", imports: [{ package: "p", names: [] }] }],
      entry_points: [],
    });
    assert.equal(out.ranked[0].reachability, "imported_unreachable");
    assert.equal(out.ranked[0].rank_score, 30);
  });
});

describe("rankVulnsByReach — validation", () => {
  const throws = (args: unknown, message: string) =>
    assert.throws(() => rank(args), { message });

  const ok = { vulnerabilities: [], modules: [], entry_points: [] };

  it("vulnerabilities missing or not an array names vulnerabilities", () => {
    throws({}, "vulnerabilities must be an array");
    throws({ modules: [], entry_points: [] }, "vulnerabilities must be an array");
    throws({ ...ok, vulnerabilities: "x" }, "vulnerabilities must be an array");
    throws(null, "vulnerabilities must be an array");
    throws([], "vulnerabilities must be an array");
    throws("nope", "vulnerabilities must be an array");
  });

  it("a vulnerability entry that is not an object names its index", () => {
    throws({ ...ok, vulnerabilities: ["x"] }, "vulnerabilities[0] must be an object");
    throws({ ...ok, vulnerabilities: [null] }, "vulnerabilities[0] must be an object");
  });

  it("vulnerability id missing, empty, or non-string names id", () => {
    const msg = "vulnerabilities[0].id must be a non-empty string";
    throws({ ...ok, vulnerabilities: [{ package: "p", severity: "low" }] }, msg);
    throws({ ...ok, vulnerabilities: [{ id: "", package: "p", severity: "low" }] }, msg);
    throws({ ...ok, vulnerabilities: [{ id: 1, package: "p", severity: "low" }] }, msg);
  });

  it("a duplicate vulnerability id names the duplicate path", () => {
    throws(
      {
        ...ok,
        vulnerabilities: [
          { id: "A", package: "p", severity: "low" },
          { id: "B", package: "p", severity: "low" },
          { id: "A", package: "q", severity: "low" },
        ],
      },
      "vulnerabilities[2].id is a duplicate",
    );
  });

  it("vulnerability package missing, empty, or non-string names package", () => {
    const msg = "vulnerabilities[0].package must be a non-empty string";
    throws({ ...ok, vulnerabilities: [{ id: "A", severity: "low" }] }, msg);
    throws({ ...ok, vulnerabilities: [{ id: "A", package: "", severity: "low" }] }, msg);
    throws({ ...ok, vulnerabilities: [{ id: "A", package: 2, severity: "low" }] }, msg);
  });

  it("severity missing or outside the enum names severity with the enum", () => {
    const msg =
      'vulnerabilities[0].severity must be one of "critical", "high", "medium", "low"';
    throws({ ...ok, vulnerabilities: [{ id: "A", package: "p" }] }, msg);
    throws({ ...ok, vulnerabilities: [{ id: "A", package: "p", severity: "severe" }] }, msg);
    throws({ ...ok, vulnerabilities: [{ id: "A", package: "p", severity: "HIGH" }] }, msg);
    throws({ ...ok, vulnerabilities: [{ id: "A", package: "p", severity: 1 }] }, msg);
  });

  it("every severity enum value is accepted", () => {
    for (const severity of ["critical", "high", "medium", "low"]) {
      const out = rank({ ...ok, vulnerabilities: [{ id: "A", package: "p", severity }] });
      assert.equal(out.ranked[0].severity, severity);
    }
  });

  it("vulnerable_exports badly typed names its path", () => {
    throws(
      { ...ok, vulnerabilities: [{ id: "A", package: "p", severity: "low", vulnerable_exports: "x" }] },
      "vulnerabilities[0].vulnerable_exports must be an array",
    );
    throws(
      { ...ok, vulnerabilities: [{ id: "A", package: "p", severity: "low", vulnerable_exports: [""] }] },
      "vulnerabilities[0].vulnerable_exports[0] must be a non-empty string",
    );
    throws(
      { ...ok, vulnerabilities: [{ id: "A", package: "p", severity: "low", vulnerable_exports: ["ok", 3] }] },
      "vulnerabilities[0].vulnerable_exports[1] must be a non-empty string",
    );
  });

  it("modules missing or not an array names modules", () => {
    throws({ vulnerabilities: [] }, "modules must be an array");
    throws({ ...ok, modules: {} }, "modules must be an array");
  });

  it("a module entry that is not an object names its index", () => {
    throws({ ...ok, modules: [42] }, "modules[0] must be an object");
  });

  it("module path missing, empty, or non-string names path", () => {
    const msg = "modules[0].path must be a non-empty string";
    throws({ ...ok, modules: [{ imports: [] }] }, msg);
    throws({ ...ok, modules: [{ path: "", imports: [] }] }, msg);
    throws({ ...ok, modules: [{ path: 1, imports: [] }] }, msg);
  });

  it("a duplicate module path names the duplicate path", () => {
    throws(
      {
        ...ok,
        modules: [
          { path: "m", imports: [] },
          { path: "m", imports: [] },
        ],
      },
      "modules[1].path is a duplicate",
    );
  });

  it("module imports missing or not an array names imports", () => {
    throws({ ...ok, modules: [{ path: "m" }] }, "modules[0].imports must be an array");
    throws({ ...ok, modules: [{ path: "m", imports: "x" }] }, "modules[0].imports must be an array");
  });

  it("an import that is not an object names its path", () => {
    throws(
      { ...ok, modules: [{ path: "m", imports: ["x"] }] },
      "modules[0].imports[0] must be an object",
    );
  });

  it("import package missing, empty, or non-string names its path", () => {
    const msg = "modules[0].imports[0].package must be a non-empty string";
    throws({ ...ok, modules: [{ path: "m", imports: [{ names: [] }] }] }, msg);
    throws({ ...ok, modules: [{ path: "m", imports: [{ package: "", names: [] }] }] }, msg);
    throws({ ...ok, modules: [{ path: "m", imports: [{ package: 1, names: [] }] }] }, msg);
  });

  it("import names missing, not an array, or badly typed names its path", () => {
    throws(
      { ...ok, modules: [{ path: "m", imports: [{ package: "p" }] }] },
      "modules[0].imports[0].names must be an array",
    );
    throws(
      { ...ok, modules: [{ path: "m", imports: [{ package: "p", names: "x" }] }] },
      "modules[0].imports[0].names must be an array",
    );
    throws(
      { ...ok, modules: [{ path: "m", imports: [{ package: "p", names: ["ok", null] }] }] },
      "modules[0].imports[0].names[1] must be a string",
    );
  });

  it("entry_points missing or not an array names entry_points", () => {
    throws({ vulnerabilities: [], modules: [] }, "entry_points must be an array");
    throws({ ...ok, entry_points: "m" }, "entry_points must be an array");
  });

  it("an entry point that is empty or non-string names its index", () => {
    const msg = "entry_points[0] must be a non-empty string";
    throws({ ...ok, entry_points: [""] }, msg);
    throws({ ...ok, entry_points: [1] }, msg);
    throws({ ...ok, entry_points: [null] }, msg);
  });

  it("an entry point that is not a module path names its index", () => {
    throws(
      {
        vulnerabilities: [],
        modules: [{ path: "m", imports: [] }],
        entry_points: ["nope"],
      },
      "entry_points[0] is not a module path",
    );
    throws(
      {
        vulnerabilities: [],
        modules: [{ path: "m", imports: [] }],
        entry_points: ["m", "ghost"],
      },
      "entry_points[1] is not a module path",
    );
  });

  it("unknown extra fields are ignored at every level (pinned judgement call)", () => {
    const out = rank({
      vulnerabilities: [{ id: "A", package: "p", severity: "low", extra: 1 }],
      modules: [{ path: "m", imports: [{ package: "p", names: [], extra: 2 }], extra: 3 }],
      entry_points: ["m"],
      extra: 4,
    });
    assert.equal(out.ranked[0].reachability, "reachable");
  });

  it("no partial result is produced on invalid input", () => {
    assert.throws(() =>
      rank({
        vulnerabilities: [{ id: "A", package: "p", severity: "low" }],
        modules: [{ path: "m", imports: [] }],
        entry_points: ["ghost"],
      }),
    );
  });
});
