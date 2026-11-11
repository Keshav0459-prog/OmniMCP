import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const omnimcpRoot = path.resolve(__dirname, "../..");

const authToken = process.env.SENTRY_AUTH_TOKEN;

// If a valid Sentry token is provided, delegate to official @sentry/mcp-server
if (authToken && authToken.trim().length > 10) {
  const sentryScript = path.resolve(omnimcpRoot, "node_modules/@sentry/mcp-server/dist/sentry-mcp.cjs");
  const child = spawn(process.execPath, [sentryScript], {
    stdio: "inherit",
    env: process.env,
  });

  child.on("exit", (code) => {
    process.exit(code || 0);
  });
} else {
  // Otherwise, run resilient adapter that exposes tools and guides configuration
  const server = new Server(
    {
      name: "sentry-mcp-adapter",
      version: "1.0.0",
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  const tools: Tool[] = [
    {
      name: "whoami",
      description: "Verify authenticated Sentry user and organization info.",
      inputSchema: { type: "object", properties: {} },
    },
    {
      name: "find_issues",
      description: "Search and filter issues/errors within a Sentry project.",
      inputSchema: {
        type: "object",
        properties: {
          project: { type: "string", description: "Sentry project slug" },
          query: { type: "string", description: "Search query or filter (e.g. is:unresolved)" },
        },
      },
    },
    {
      name: "get_issue_details",
      description: "Get detailed stacktrace, tags, and context for a specific Sentry issue.",
      inputSchema: {
        type: "object",
        properties: {
          issue_id: { type: "string", description: "Sentry issue ID" },
        },
        required: ["issue_id"],
      },
    },
    {
      name: "find_projects",
      description: "List projects in the configured Sentry organization.",
      inputSchema: { type: "object", properties: {} },
    },
    {
      name: "find_releases",
      description: "List recent software releases and deployment health.",
      inputSchema: {
        type: "object",
        properties: {
          project: { type: "string", description: "Project slug" },
        },
      },
    },
  ];

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return { tools };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name } = request.params;
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            status: "unconfigured",
            tool: name,
            message:
              "Sentry MCP server is registered. To query live Sentry issues, stacktraces, and projects, please configure SENTRY_AUTH_TOKEN, SENTRY_ORG, and SENTRY_PROJECT in your .env file.",
          }),
        },
      ],
    };
  });

  const transport = new StdioServerTransport();
  server.connect(transport).catch((err) => {
    console.error("Failed to start Sentry adapter:", err);
    process.exit(1);
  });
}
