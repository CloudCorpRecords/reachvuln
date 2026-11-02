/**
 * reachvuln core: rank vulnerability findings by whether
 * the vulnerable package and exports are reachable from
 * entry points through the supplied import graph.
 *
 *   rankVulnsByReach(args) -> { ranked, counts }
 *
 * Local edges (pinned): an import whose `package` equals
 * another module's `path` is a local edge to that module;
 * any other `package` is an external package import.
 *
 * Reachable modules (pinned): the entry points, plus every
 * module reachable from them by following local edges
 * breadth-first; cycles are safe.
 *
 * Reachability of a finding (pinned):
 *   - "reachable" — some reachable module imports the
 *     finding's package AND (`vulnerable_exports` is empty
 *     OR that import's `names` share at least one entry
 *     with `vulnerable_exports`).
 *   - "imported_unreachable" — not reachable, but at least
 *     one module imports the package at all (any names).
 *   - "not_imported" — no module imports the package.
 *
 * `reached_via` (pinned): for a reachable finding, the
 * sorted distinct paths of the reachable modules whose
 * imports satisfy the reachable condition; otherwise [].
 *
 * Rank score (pinned): severity weight — critical 40,
 * high 30, medium 20, low 10 — multiplied by 3 when
 * reachable, by 1 when imported_unreachable, by 0 when
 * not_imported. Ordering: rank score descending, then
 * severity weight descending, then `id` ascending.
 *
 * Validation is strict and path-naming: any malformed
 * input throws an Error naming the offending path and no
 * partial result is produced. Unknown extra fields are
 * ignored; a non-object top-level argument is treated
 * as {}.
 */
import type {
  ModuleImport,
  ModuleInfo,
  Reachability,
  ReachVulnResult,
  Severity,
  Vulnerability,
} from "./types.js";

export const VERSION = "0.1.0";

const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low"];

const WEIGHTS: Record<Severity, number> = {
  critical: 40,
  high: 30,
  medium: 20,
  low: 10,
};

const MULTIPLIERS: Record<Reachability, number> = {
  reachable: 3,
  imported_unreachable: 1,
  not_imported: 0,
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function validateArgs(args: unknown): {
  vulnerabilities: Vulnerability[];
  modules: ModuleInfo[];
  entryPoints: string[];
} {
  const raw: Record<string, unknown> = isRecord(args) ? args : {};

  // ---- vulnerabilities ----
  if (!Array.isArray(raw.vulnerabilities)) {
    throw new Error("vulnerabilities must be an array");
  }
  const vulnerabilities: Vulnerability[] = [];
  const seenIds = new Set<string>();
  raw.vulnerabilities.forEach((entry, i) => {
    const p = `vulnerabilities[${i}]`;
    if (!isRecord(entry)) throw new Error(`${p} must be an object`);
    if (typeof entry.id !== "string" || entry.id.length === 0) {
      throw new Error(`${p}.id must be a non-empty string`);
    }
    if (seenIds.has(entry.id)) {
      throw new Error(`${p}.id is a duplicate`);
    }
    seenIds.add(entry.id);
    if (typeof entry.package !== "string" || entry.package.length === 0) {
      throw new Error(`${p}.package must be a non-empty string`);
    }
    if (
      typeof entry.severity !== "string" ||
      !SEVERITIES.includes(entry.severity as Severity)
    ) {
      throw new Error(
        `${p}.severity must be one of ${SEVERITIES.map((s) => `"${s}"`).join(", ")}`,
      );
    }
    let vulnerableExports: string[] = [];
    if (entry.vulnerable_exports !== undefined) {
      if (!Array.isArray(entry.vulnerable_exports)) {
        throw new Error(`${p}.vulnerable_exports must be an array`);
      }
      entry.vulnerable_exports.forEach((name, j) => {
        if (typeof name !== "string" || name.length === 0) {
          throw new Error(
            `${p}.vulnerable_exports[${j}] must be a non-empty string`,
          );
        }
      });
      vulnerableExports = entry.vulnerable_exports as string[];
    }
    vulnerabilities.push({
      id: entry.id,
      package: entry.package,
      severity: entry.severity as Severity,
      vulnerable_exports: vulnerableExports,
    });
  });

  // ---- modules ----
  if (!Array.isArray(raw.modules)) {
    throw new Error("modules must be an array");
  }
  const modules: ModuleInfo[] = [];
  const seenPaths = new Set<string>();
  raw.modules.forEach((entry, i) => {
    const p = `modules[${i}]`;
    if (!isRecord(entry)) throw new Error(`${p} must be an object`);
    if (typeof entry.path !== "string" || entry.path.length === 0) {
      throw new Error(`${p}.path must be a non-empty string`);
    }
    if (seenPaths.has(entry.path)) {
      throw new Error(`${p}.path is a duplicate`);
    }
    seenPaths.add(entry.path);
    if (!Array.isArray(entry.imports)) {
      throw new Error(`${p}.imports must be an array`);
    }
    const imports: ModuleImport[] = [];
    entry.imports.forEach((imp, j) => {
      const ip = `${p}.imports[${j}]`;
      if (!isRecord(imp)) throw new Error(`${ip} must be an object`);
      if (typeof imp.package !== "string" || imp.package.length === 0) {
        throw new Error(`${ip}.package must be a non-empty string`);
      }
      if (!Array.isArray(imp.names)) {
        throw new Error(`${ip}.names must be an array`);
      }
      imp.names.forEach((name, k) => {
        if (typeof name !== "string") {
          throw new Error(`${ip}.names[${k}] must be a string`);
        }
      });
      imports.push({ package: imp.package, names: imp.names as string[] });
    });
    modules.push({ path: entry.path, imports });
  });

  // ---- entry_points ----
  if (!Array.isArray(raw.entry_points)) {
    throw new Error("entry_points must be an array");
  }
  const entryPoints: string[] = [];
  raw.entry_points.forEach((entry, i) => {
    if (typeof entry !== "string" || entry.length === 0) {
      throw new Error(`entry_points[${i}] must be a non-empty string`);
    }
    if (!seenPaths.has(entry)) {
      throw new Error(`entry_points[${i}] is not a module path`);
    }
    entryPoints.push(entry);
  });

  return { vulnerabilities, modules, entryPoints };
}

/** Rank vulnerability findings by code reachability. */
export function rankVulnsByReach(args: unknown): ReachVulnResult {
  const { vulnerabilities, modules, entryPoints } = validateArgs(args);

  const byPath = new Map<string, ModuleInfo>();
  for (const m of modules) byPath.set(m.path, m);

  // BFS from entry points over local edges, cycle-safe.
  const reachable = new Set<string>();
  const queue: string[] = [];
  for (const ep of entryPoints) {
    if (!reachable.has(ep)) {
      reachable.add(ep);
      queue.push(ep);
    }
  }
  let head = 0;
  while (head < queue.length) {
    const current = queue[head++];
    const mod = byPath.get(current);
    if (!mod) continue;
    for (const imp of mod.imports) {
      if (byPath.has(imp.package) && !reachable.has(imp.package)) {
        reachable.add(imp.package);
        queue.push(imp.package);
      }
    }
  }

  const ranked = vulnerabilities.map((vuln) => {
    const reachedViaSet = new Set<string>();
    let anyImport = false;
    for (const mod of modules) {
      for (const imp of mod.imports) {
        if (imp.package !== vuln.package) continue;
        anyImport = true;
        if (!reachable.has(mod.path)) continue;
        if (
          vuln.vulnerable_exports.length === 0 ||
          imp.names.some((n) => vuln.vulnerable_exports.includes(n))
        ) {
          reachedViaSet.add(mod.path);
        }
      }
    }
    const reached_via = [...reachedViaSet].sort();
    const reachability: Reachability =
      reached_via.length > 0
        ? "reachable"
        : anyImport
          ? "imported_unreachable"
          : "not_imported";
    const rank_score = WEIGHTS[vuln.severity] * MULTIPLIERS[reachability];
    return {
      id: vuln.id,
      package: vuln.package,
      severity: vuln.severity,
      reachability,
      rank_score,
      reached_via,
    };
  });

  ranked.sort((a, b) => {
    if (b.rank_score !== a.rank_score) return b.rank_score - a.rank_score;
    if (WEIGHTS[b.severity] !== WEIGHTS[a.severity]) {
      return WEIGHTS[b.severity] - WEIGHTS[a.severity];
    }
    return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
  });

  const counts = { reachable: 0, imported_unreachable: 0, not_imported: 0 };
  for (const r of ranked) counts[r.reachability]++;

  return { ranked, counts };
}

/** Render a payload as the JSON text block MCP clients show. */
export function formatPayload(payload: unknown): string {
  return typeof payload === "string" ? payload : JSON.stringify(payload, null, 2);
}
