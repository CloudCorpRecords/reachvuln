# reachvuln

A scanner report with two hundred findings is not a work
list. Most of those packages may never be loaded by your
code at all, and of the ones that are, the vulnerable export
may never be the one you import. reachvuln reorders the
report around that question: given the findings, your
modules and their imports, and your entry points, which
findings can actually be reached?

Reachability is computed over the import graph you supply.
An import whose `package` equals another module's `path`
is a local edge; anything else is an external package
import. The reachable modules are the entry points plus
everything reached from them by following local edges —
breadth-first, and safe around cycles, so a circular import
chain neither loops forever nor hides what sits behind it.

A finding is **reachable** when some reachable module
imports its package and either the finding lists no
`vulnerable_exports` (any import of the package counts) or
that import's `names` share at least one entry with
`vulnerable_exports`. It is **imported_unreachable** when
some module imports the package but the reachable condition
does not hold — the package is in the tree, yet no reachable
module imports it in a way that touches the vulnerable
exports. It is **not_imported** when no module imports the
package at all. For a reachable finding, `reached_via`
lists the sorted distinct paths of the reachable modules
whose imports satisfy the condition; otherwise it is empty.

Ranking is pinned arithmetic, not a heuristic: severity
weighs critical 40, high 30, medium 20, and low 10, and the
weight is multiplied by 3 for reachable findings, by 1 for
imported-but-unreachable ones, and by 0 for not-imported
ones. Findings order by rank score descending, then
severity weight descending, then `id` ascending, and the
result also carries counts for the three classes.

Validation is strict and names the offending path: a
missing or badly typed `vulnerabilities`, `modules`, or
`entry_points`; a finding with a missing, empty, or
duplicate `id`, a missing or empty `package`, a `severity`
outside its enum, or a badly typed `vulnerable_exports`; a
module with a missing, empty, or duplicate `path`, a
missing `imports`, or an import with a bad `package` or
`names`; and an entry point that is not one of the module
paths. Note that entries in an import's `names` may be
empty strings — they simply never match a vulnerable
export, which is itself required to be non-empty. Unknown
extra fields are ignored, and no partial result is produced
on invalid input. The computation is pure and local: no
network, no configuration, and no repository is read.

## CLI

```bash
npx @reneturcios/reachvuln rank --input args.json
npx @reneturcios/reachvuln --version
```

`args.json` contains the full arguments object:

```json
{
  "vulnerabilities": [
    {
      "id": "CVE-1",
      "package": "lodash",
      "severity": "high",
      "vulnerable_exports": ["merge"]
    }
  ],
  "modules": [
    {
      "path": "src/app.ts",
      "imports": [{ "package": "lodash", "names": ["merge"] }]
    }
  ],
  "entry_points": ["src/app.ts"]
}
```

The result is printed as JSON:

```json
{
  "ranked": [
    {
      "id": "CVE-1",
      "package": "lodash",
      "severity": "high",
      "reachability": "reachable",
      "rank_score": 90,
      "reached_via": ["src/app.ts"]
    }
  ],
  "counts": {
    "reachable": 1,
    "imported_unreachable": 0,
    "not_imported": 0
  }
}
```

Exit codes: `0` on success, `1` on a runtime error (including
an unreadable or invalid input file, or invalid input), `2`
on a usage error.

## MCP server

```bash
npx -y @reneturcios/reachvuln mcp
```

MCP client config:

```json
{
  "mcpServers": {
    "reachvuln": {
      "command": "npx",
      "args": ["-y", "@reneturcios/reachvuln", "mcp"]
    }
  }
}
```

### Tools

- `rank_vulns_by_reach` — Rank vulnerability findings by
  whether the vulnerable package and exports are reachable
  from your entry points.
  - `vulnerabilities` (array, required, may be empty) —
    findings, each `{id, package, severity,
    vulnerable_exports}`; `id` is a non-empty unique string,
    `package` a non-empty string, `severity` one of
    `critical`, `high`, `medium`, `low`, and
    `vulnerable_exports` an optional array of non-empty
    strings (default `[]`)
  - `modules` (array, required, may be empty) — modules,
    each `{path, imports}`; `path` is a non-empty unique
    string and `imports` an array of `{package, names}`,
    where `package` is a non-empty string and `names` a
    required array of strings (entries may be empty)
  - `entry_points` (array, required, may be empty) —
    module paths that are entry points; every entry must
    equal some module's `path`

  Returns `{ranked, counts}`, where each ranked entry is
  `{id, package, severity, reachability, rank_score,
  reached_via}` in the pinned order and `counts` is
  `{reachable, imported_unreachable, not_imported}`.

## Docker

```bash
docker run -i ghcr.io/cloudcorprecords/reachvuln
docker run --rm -v "$PWD:/w" ghcr.io/cloudcorprecords/reachvuln rank --input /w/args.json
```

## Development

```bash
npm install
npm run build   # tsc -> dist/
npm test        # tsx --test test/*.test.ts (pure local, no network)
npm run dev     # run the CLI from source
```

## License

MIT — Copyright (c) 2026 Rene Turcios
