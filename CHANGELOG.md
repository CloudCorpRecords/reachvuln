# Changelog

## 0.1.0 (2026-10-27)

- Initial release: `rank_vulns_by_reach` MCP tool and
  `rank` CLI command ranking vulnerability findings by
  whether the vulnerable package and exports are reachable
  from entry points through the supplied import graph.
- Pinned reachability: an import whose package equals a
  module path is a local edge; reachable modules are the
  entry points plus everything reached from them by
  breadth-first traversal of local edges, cycle-safe.
- Pinned condition: a finding is reachable when a reachable
  module imports its package and either its
  `vulnerable_exports` is empty or that import's `names`
  intersect `vulnerable_exports`; otherwise it is
  `imported_unreachable` when any module imports the
  package, and `not_imported` when none does.
- Pinned rank score: severity weight (critical 40, high
  30, medium 20, low 10) multiplied by 3, 1, or 0 for
  reachable, imported-unreachable, or not-imported
  findings; ordering by score descending, severity weight
  descending, then id ascending.
- Path-naming validation for malformed input, including
  duplicate vulnerability ids, duplicate module paths,
  and entry points that are not module paths.
