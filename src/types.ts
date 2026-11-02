/**
 * reachvuln types.
 *
 * reachvuln ranks vulnerability findings by code
 * reachability. The caller supplies findings, a set of
 * modules with their imports, and the entry-point module
 * paths. From that data alone, as pure local computation,
 * reachvuln reports for each finding whether it is
 * reachable, imported but unreachable, or not imported,
 * together with a rank score and the paths it is reached
 * via.
 */

/** Severity levels a finding may carry. */
export type Severity = "critical" | "high" | "medium" | "low";

/** Reachability classification of a finding. */
export type Reachability = "reachable" | "imported_unreachable" | "not_imported";

/** A single vulnerability finding, after validation. */
export interface Vulnerability {
  id: string;
  package: string;
  severity: Severity;
  vulnerable_exports: string[];
}

/** A single import made by a module, after validation. */
export interface ModuleImport {
  package: string;
  names: string[];
}

/** A module and its imports, after validation. */
export interface ModuleInfo {
  path: string;
  imports: ModuleImport[];
}

/** A ranked finding. */
export interface RankedFinding {
  id: string;
  package: string;
  severity: Severity;
  reachability: Reachability;
  rank_score: number;
  reached_via: string[];
}

/** Counts by reachability classification. */
export interface ReachCounts {
  reachable: number;
  imported_unreachable: number;
  not_imported: number;
}

/** The result of ranking findings by reachability. */
export interface ReachVulnResult {
  ranked: RankedFinding[];
  counts: ReachCounts;
}
