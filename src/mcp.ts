/**
 * reachvuln MCP server. Tools: rank_vulns_by_reach.
 *
 * Why the low-level Server instead of McpServer: the high-level
 * helper converts zod schemas to JSON Schema and injects keys
 * not in this tool's defined spec ("$schema" and
 * "additionalProperties"), which breaks exact tool-list/schema
 * parity with the spec. This file serves tools/list with the
 * spec's exact input schema as an explicit literal, and every
 * tools/call is validated by the core, which names the
 * offending path on invalid input.
 *
 * The computation is pure and local: no upstream API, no
 * authentication, no configuration, and no repository is
 * touched — the tool only ranks findings.
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import { formatPayload, rankVulnsByReach, VERSION } from "./reachvuln.js";

const TOOLS = [
  {
    name: "rank_vulns_by_reach",
    description:
      "Rank vulnerability findings by whether the vulnerable package and exports are reachable from your entry points through the supplied import graph — not by raw CVE count. Reachable findings outrank imported but unreachable ones.",
    inputSchema: {
      type: "object" as const,
      properties: {
        vulnerabilities: {
          type: "array",
          description: "Findings: {id, package, severity, vulnerable_exports}",
          items: {
            type: "object",
            properties: {
              id: {
                type: "string",
                description: "Finding id (unique across the array)",
              },
              package: {
                type: "string",
                description: "Vulnerable package name",
              },
              severity: {
                type: "string",
                description: "Severity of the finding",
                enum: ["critical", "high", "medium", "low"],
              },
              vulnerable_exports: {
                type: "array",
                description: "Vulnerable exported names (optional, default [])",
                items: { type: "string" },
              },
            },
            required: ["id", "package", "severity"],
          },
        },
        modules: {
          type: "array",
          description: "Modules and their imports: {path, imports}",
          items: {
            type: "object",
            properties: {
              path: {
                type: "string",
                description: "Module path (unique across the array)",
              },
              imports: {
                type: "array",
                description: "Imports this module makes",
                items: {
                  type: "object",
                  properties: {
                    package: {
                      type: "string",
                      description:
                        "Package or module path imported; a value equal to a module path is a local edge",
                    },
                    names: {
                      type: "array",
                      description: "Names imported from that package",
                      items: { type: "string" },
                    },
                  },
                  required: ["package", "names"],
                },
              },
            },
            required: ["path", "imports"],
          },
        },
        entry_points: {
          type: "array",
          description: "Module paths that are entry points",
          items: { type: "string" },
        },
      },
      required: ["vulnerabilities", "modules", "entry_points"],
    },
  },
];

function textResult(value: unknown) {
  return {
    content: [
      {
        type: "text" as const,
        text: typeof value === "string" ? value : JSON.stringify(value, null, 2),
      },
    ],
  };
}

function errorResult(err: unknown) {
  return {
    content: [
      { type: "text" as const, text: err instanceof Error ? err.message : String(err) },
    ],
    isError: true,
  };
}

const server = new Server(
  { name: "reachvuln", version: VERSION },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  try {
    let out: unknown;
    if (name === "rank_vulns_by_reach") {
      out = rankVulnsByReach(args ?? {});
    } else {
      throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
    }
    return textResult(formatPayload(out));
  } catch (err) {
    if (err instanceof McpError) throw err;
    return errorResult(err);
  }
});

async function main(): Promise<void> {
  await server.connect(new StdioServerTransport());
}

void main();
