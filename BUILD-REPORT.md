# reachvuln — Build Report

MCP Rebuild 1000, Batch 17. Original program build from the
packages-100 plan (cluster F #67), built from the spec in
`~/workspace/mcp-rebuild-100/specs-batch17/reachvuln.md`
(read first). There is no external original; the tool surface
is the program's defined spec. Local build only — nothing
pushed or published.

Identity: repo `reachvuln`, npm `@reneturcios/reachvuln`,
MCP name `io.github.CloudCorpRecords/reachvuln`, version
`0.1.0`, bin `reachvuln` → `dist/cli.js`.

## Files created (19/19 per TEMPLATE.md checklist)

- `package.json`, `server.json` (description "Rank
  vulnerabilities by whether the vulnerable code path is
  reachable in your code." — 83 chars, verified by count;
  npm entry carries `version: 0.1.0`; OCI entry
  `ghcr.io/cloudcorprecords/reachvuln:0.1.0` carries **no**
  `version` field), `Dockerfile` (node:20-alpine two-stage,
  label
  `io.modelcontextprotocol.server.name="io.github.CloudCorpRecords/reachvuln"`),
  `tsconfig.json`, `.gitignore`, `LICENSE` (MIT, Copyright
  (c) 2026 Rene Turcios), `README.md` (fresh text),
  `CHANGELOG.md` (single 0.1.0 entry, 2026-10-27),
  `package-lock.json` (Route 3, see below)
- `src/index.ts`, `src/cli.ts` (`rank --input <args.json>`
  where the file holds the full arguments object, `mcp`,
  `--version`; exit 2 usage / 1 runtime error, argument
  validation before any file read), `src/mcp.ts`,
  `src/types.ts`, `src/reachvuln.ts` (core,
  `VERSION = "0.1.0"`)
- `test/reachvuln.test.ts`
- `.github/workflows/{ci,publish,publish-container,registry-publish}.yml`
  (publish-container `IMAGE = ghcr.io/cloudcorprecords/reachvuln`,
  smoke-test server-name assertion `reachvuln`)

Plus the parity fixture at
`harness/fixtures/reachvuln-tools-original.json`, labelled
as a program spec from the packages-100 plan cluster F #67.

## Tools implemented (1)

- `rank_vulns_by_reach` — arguments: `vulnerabilities`
  (array, required, may be empty; entries `{id, package,
  severity, vulnerable_exports}` with `id`/`package`
  non-empty strings, `id` unique, `severity` enum
  ["critical", "high", "medium", "low"],
  `vulnerable_exports` optional array of non-empty strings,
  default []), `modules` (array, required, may be empty;
  entries `{path, imports}` with `path` a non-empty unique
  string and `imports` a required array of `{package,
  names}`, `package` non-empty and `names` a required array
  of strings whose entries may be empty), and
  `entry_points` (array of strings, required, may be empty;
  every entry must equal some module's `path`). The schema
  literal carries the severity enum exactly and no
  `minLength` anywhere the spec does not state one.

  Reachability is pinned: an import whose `package` equals
  a module's `path` is a local edge; reachable modules are
  the entry points plus everything reached from them by
  breadth-first traversal of local edges, cycle-safe. A
  finding is "reachable" when some reachable module imports
  its package AND (`vulnerable_exports` is empty OR that
  import's `names` intersect `vulnerable_exports`);
  "imported_unreachable" when at least one module imports
  the package but the reachable condition fails;
  "not_imported" otherwise. `reached_via` is the sorted
  distinct paths of the reachable modules whose imports
  satisfy the reachable condition, else []. Rank score is
  the severity weight (critical 40, high 30, medium 20,
  low 10) multiplied by 3 / 1 / 0 for the three classes;
  ordering is score descending, severity weight
  descending, then `id` ascending. Returns `{ranked,
  counts}` with counts `{reachable, imported_unreachable,
  not_imported}`.

  The fixture literal
  (`harness/fixtures/reachvuln-tools-original.json`) and
  the `src/mcp.ts` literal are identical, with no `$schema`
  and no `additionalProperties` — confirmed by the parity
  run below.

## Implementation notes

- `src/mcp.ts` uses the SDK's low-level `Server` with an
  explicit inputSchema literal exactly matching the
  fixture, per the standing fleet rule (no McpServer/zod
  schema conversion). Every `tools/call` is validated by
  the core itself, so the MCP and CLI paths share one
  validation implementation; the core takes the full
  arguments object (`{vulnerabilities, modules,
  entry_points}`).
- Validation is path-naming and total: missing or
  non-array top-level fields; non-object entries; missing,
  empty, or non-string `id` / `package` / `path` /
  import `package`; out-of-enum `severity`; badly typed
  `vulnerable_exports` (non-array, or an empty or
  non-string entry); duplicate vulnerability ids and
  duplicate module paths; missing or non-array `imports`;
  missing, non-array, or badly typed import `names`
  (entries must be strings but may be empty); and entry
  points that are empty, non-string, or not a module path
  all throw an Error naming the offending path (for
  example `vulnerabilities[2].id is a duplicate`,
  `entry_points[0] is not a module path`) and produce no
  partial result (MCP: `isError`; CLI: exit 1).

## Verification (foreground, this session)

- `npm test` (`tsx --test test/*.test.ts`): **46 tests,
  46 pass, 0 fail** — direct reachability with an exact
  result object and the four severity weights; transitive
  reachability through local edges; a module behind no
  local edge not making a finding reachable; cycles and a
  self-import terminating; names-intersection hit, miss,
  and empty-names miss; empty or omitted
  `vulnerable_exports` counting any import; a names hit
  only in an unreachable module not satisfying the
  condition; an empty-string import name accepted but
  never matching; imported-only-by-unreachable and
  never-imported findings with their scores;
  `reached_via` sorted, distinct, excluding non-satisfying
  and unreachable modules, and empty for the other classes;
  ordering by score descending including a reachable low
  outscored by an imported critical, the score tie broken
  by severity weight, the score-and-weight tie broken by
  id ascending, and all-zero not-imported ordering by
  weight then id; counts across mixed classes; empty
  vulnerabilities / modules / entry_points (empty entry
  points = nothing reachable); and every validation path
  (top-level fields, entry objects, id/package/severity/
  vulnerable_exports, duplicate ids, module paths and
  their duplicates, imports and import package/names,
  entry-point type and unknown-module-path errors,
  unknown extras ignored, non-object top level treated as
  {}, and no partial result on invalid input).
- `npx tsc --noEmit` → exit 0; `npm run build` produced
  `dist/` with all 15 outputs.
- `dist/cli.js --version` → `0.1.0`; unknown command exits
  2 with usage; `rank` with no `--input` exits 2;
  `rank --input <missing file>` exits 1 naming the file;
  `rank --input <valid file>` exits 0 and prints the
  hand-checked result (CVE-1 / lodash / high, reachable,
  rank_score 90, reached_via ["src/app.ts"]) for the
  README example input; `rank --input <invalid file>`
  (unknown entry point) exits 1 with
  `entry_points[0] is not a module path`.
- Parity: `harness/parity.py` vs
  `harness/fixtures/reachvuln-tools-original.json` →
  **PASS, parity 100.0, identical_tools 1/1** (run with
  the rebuild path as an absolute path; the harness does
  not expand a `~` inside the quoted stdio command
  string). Report saved under `parity-out/`.

## Lockfile status

`package-lock.json` generated clean via Route 3 (in the
build directory with no `node_modules` present, offline
`npm install --package-lock-only --ignore-scripts
--offline`), verified: parses, name
`@reneturcios/reachvuln`, **128 package entries**. The
subsequent offline `npm install --ignore-scripts
--offline`, build, tests, and parity all ran against this
lockfile's tree.

## Gaps / honest notes

- **Pinned judgement calls** (each with a dedicated test
  where applicable): (1) unknown extra fields are ignored
  rather than rejected, at every level; (2) a non-object
  top-level arguments value is treated as an empty object,
  so it fails as `vulnerabilities must be an array`;
  (3) import `names` entries may be empty strings (the
  deadpath precedent in the spec) — they are accepted and
  simply never match a vulnerable export, which is itself
  required to be non-empty; (4) a finding's package that
  happens to equal a module path is treated by the same
  import-matching rule as any other package string (the
  spec's ordinary case is external package names, which
  never equal module paths); (5) error-message wording
  other than the spec's example paths follows the fleet's
  path-naming pattern (e.g. `modules[1].path is a
  duplicate`). No other spec ambiguity was found in the
  core behaviour.
- Container build not exercised locally; the
  publish-container workflow smoke-tests the image at
  publish time.
- Nothing pushed or published; this is a local build only.
