import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
  Tool,
  ErrorCode,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import { serverRegistry } from "./registry.js";
import { clientManager } from "./client-manager.js";
import { discoveryEngine } from "./discovery.js";
import { executionEngine } from "./executor.js";
import { executionHistory } from "./history.js";
import { healthMonitor } from "./health.js";
import { dbManager } from "./db.js";
import { ProjectContext } from "./types.js";
import { createChildLogger } from "./logger.js";

const log = createChildLogger("gateway-server");

export class OmniMCPGatewayServer {
  private server: Server;
  private version = "1.0.0";

  constructor() {
    this.server = new Server(
      {
        name: "omnimcp-gateway",
        version: this.version,
      },
      {
        capabilities: {
          tools: {},
          logging: {},
        },
      }
    );

    this.registerHandlers();
  }

  public getServer(): Server {
    return this.server;
  }

  private registerHandlers(): void {
    // 1. Advertise the 10 Central Gateway Tools
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      const tools: Tool[] = [
        {
          name: "search_servers",
          description:
            "Search and query registered downstream MCP servers by keyword, category (e.g. core, development, database, browser, observability) or status.",
          inputSchema: {
            type: "object",
            properties: {
              query: { type: "string", description: "Search query for server name or description" },
              category: {
                type: "string",
                description: "Filter by category: core, development, browser, database, observability",
              },
              status: {
                type: "string",
                enum: ["connected", "disconnected", "error", "all"],
                description: "Filter by connection status",
              },
            },
          },
        },
        {
          name: "list_connected_servers",
          description:
            "Lists all currently active connected downstream MCP servers, including uptime, tool counts, and latency.",
          inputSchema: {
            type: "object",
            properties: {},
          },
        },
        {
          name: "get_server_status",
          description: "Get detailed health, latency, tool count, and configuration status for a specific server.",
          inputSchema: {
            type: "object",
            properties: {
              server_id: { type: "string", description: "ID of the registered server (e.g. filesystem, github, context7)" },
            },
            required: ["server_id"],
          },
        },
        {
          name: "search_tools",
          description:
            "Discover and search tools across connected downstream MCP servers using semantic keywords or server filters. Returns namespaced tool IDs (e.g. filesystem:read_file).",
          inputSchema: {
            type: "object",
            properties: {
              query: { type: "string", description: "Search query matching tool name, tags or capabilities" },
              server_id: { type: "string", description: "Optional filter by server ID (e.g. filesystem, github, context7)" },
              permission_level: {
                type: "string",
                enum: ["READ_ONLY", "WRITE_PROTECTED", "DESTRUCTIVE_ADMIN"],
                description: "Optional filter by permission level",
              },
            },
            required: ["query"],
          },
        },
        {
          name: "get_tool_details",
          description:
            "Inspect full JSON input schema, argument types, descriptions, and required permissions for a specific namespaced tool.",
          inputSchema: {
            type: "object",
            properties: {
              tool_id: {
                type: "string",
                description: "Namespaced tool ID (e.g. 'filesystem:read_file' or 'github:create_issue')",
              },
            },
            required: ["tool_id"],
          },
        },
        {
          name: "connect_server",
          description:
            "Dynamically connect to a registered MCP server and index its tools into OmniMCP's discovery catalog.",
          inputSchema: {
            type: "object",
            properties: {
              server_id: { type: "string", description: "ID of the registered server to connect" },
            },
            required: ["server_id"],
          },
        },
        {
          name: "disconnect_server",
          description: "Gracefully disconnect a downstream MCP server and evict its tools from active catalog.",
          inputSchema: {
            type: "object",
            properties: {
              server_id: { type: "string", description: "ID of the server to disconnect" },
            },
            required: ["server_id"],
          },
        },
        {
          name: "call_tool",
          description:
            "Execute a tool on a downstream MCP server. Validates permissions, enforces timeouts, redacts secrets, and logs execution audit trails.",
          inputSchema: {
            type: "object",
            properties: {
              tool_id: {
                type: "string",
                description: "Namespaced tool ID (e.g. 'filesystem:read_file', 'github:search_repositories', 'context7:query-docs')",
              },
              parameters: {
                type: "object",
                description: "Arguments dictionary to pass to the target tool",
                additionalProperties: true,
              },
              confirm_sensitive: {
                type: "boolean",
                description:
                  "Set to true if executing a tool classified as WRITE_PROTECTED or DESTRUCTIVE_ADMIN to authorize action.",
              },
              approval_token: {
                type: "string",
                description:
                  "One-time parameter-bound approval token issued for sensitive/destructive operations.",
              },
            },
            required: ["tool_id"],
          },
        },
        {
          name: "get_execution_history",
          description:
            "Retrieve audit history of recent tool calls, execution statuses, latencies, and sanitized parameters.",
          inputSchema: {
            type: "object",
            properties: {
              limit: { type: "number", description: "Max records to return (default 20, max 100)" },
              server_id: { type: "string", description: "Filter executions by server ID" },
              status: {
                type: "string",
                enum: ["success", "error", "denied"],
                description: "Filter by execution status",
              },
            },
          },
        },
        {
          name: "get_project_context",
          description:
            "Returns high-level project and gateway context: active servers, discovered capabilities, and security posture.",
          inputSchema: {
            type: "object",
            properties: {
              cwd: { type: "string", description: "Current working directory context" },
            },
          },
        },
      ];

      return { tools };
    });

    // 2. Dispatch Tool Executions
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: rawArgs } = request.params;
      const args = (rawArgs || {}) as Record<string, unknown>;

      log.info({ tool: name, args }, "Gateway tool invocation received");

      try {
        switch (name) {
          case "search_servers": {
            const query = typeof args.query === "string" ? args.query : undefined;
            const category = typeof args.category === "string" ? args.category : undefined;
            const status = typeof args.status === "string" ? args.status : undefined;
            const servers = serverRegistry.searchServers(query, category, status);
            return {
              content: [
                {
                  type: "text",
                  text: JSON.stringify(servers, null, 2),
                },
              ],
            };
          }

          case "list_connected_servers": {
            const connected = serverRegistry.getConnectedServers();
            return {
              content: [
                {
                  type: "text",
                  text: JSON.stringify(connected, null, 2),
                },
              ],
            };
          }

          case "get_server_status": {
            const serverId = String(args.server_id || "");
            const s = serverRegistry.getServer(serverId);
            if (!s) {
              throw new McpError(ErrorCode.InvalidParams, `Server '${serverId}' not found in registry`);
            }
            const health = await healthMonitor.checkServer(serverId).catch(() => null);
            const recentMetrics = dbManager.getRecentMetrics(serverId, 10);
            return {
              content: [
                {
                  type: "text",
                  text: JSON.stringify(
                    {
                      ...s,
                      health,
                      recentMetrics,
                    },
                    null,
                    2
                  ),
                },
              ],
            };
          }

          case "search_tools": {
            const query = String(args.query || "");
            const serverId = typeof args.server_id === "string" ? args.server_id : undefined;
            const perm = typeof args.permission_level === "string" ? (args.permission_level as any) : undefined;
            const tools = discoveryEngine.searchTools(query, serverId, perm);
            return {
              content: [
                {
                  type: "text",
                  text: JSON.stringify(tools, null, 2),
                },
              ],
            };
          }

          case "get_tool_details": {
            const toolId = String(args.tool_id || "");
            const tool = discoveryEngine.getTool(toolId);
            if (!tool) {
              throw new McpError(ErrorCode.InvalidParams, `Tool '${toolId}' not found. Try 'search_tools' first.`);
            }
            return {
              content: [
                {
                  type: "text",
                  text: JSON.stringify(tool, null, 2),
                },
              ],
            };
          }

          case "connect_server": {
            const serverId = String(args.server_id || "");
            const serverConfig = serverRegistry.getServer(serverId);
            if (!serverConfig) {
              throw new McpError(ErrorCode.InvalidParams, `Server '${serverId}' not found in registry`);
            }
            await clientManager.connectServer(serverConfig);
            const discovered = await discoveryEngine.discoverServerTools(serverId);
            return {
              content: [
                {
                  type: "text",
                  text: JSON.stringify(
                    {
                      status: "connected",
                      serverId,
                      toolsDiscovered: discovered.length,
                      tools: discovered.map((t) => t.id),
                    },
                    null,
                    2
                  ),
                },
              ],
            };
          }

          case "disconnect_server": {
            const serverId = String(args.server_id || "");
            await clientManager.disconnectServer(serverId);
            discoveryEngine.unregisterServerTools(serverId);
            return {
              content: [
                {
                  type: "text",
                  text: JSON.stringify({ status: "disconnected", serverId }, null, 2),
                },
              ],
            };
          }

          case "call_tool": {
            const toolId = String(args.tool_id || "");
            const parameters = (args.parameters || {}) as Record<string, unknown>;
            const confirmSensitive = Boolean(args.confirm_sensitive);
            const approvalToken = typeof args.approval_token === "string" ? args.approval_token : undefined;

            const result = await executionEngine.executeTool(toolId, parameters, {
              confirmSensitive,
              approvalToken,
            });

            return {
              content: [
                {
                  type: "text",
                  text: JSON.stringify(result, null, 2),
                },
              ],
            };
          }

          case "get_execution_history": {
            const limit = typeof args.limit === "number" ? args.limit : 20;
            const serverId = typeof args.server_id === "string" ? args.server_id : undefined;
            const status = typeof args.status === "string" ? args.status : undefined;
            const history = executionHistory.getHistory(limit, serverId, status);
            return {
              content: [
                {
                  type: "text",
                  text: JSON.stringify(history, null, 2),
                },
              ],
            };
          }

          case "get_project_context": {
            const activeServers = serverRegistry.getConnectedServers().map((s) => ({
              id: s.id,
              name: s.name,
              status: s.status,
              toolCount: s.toolCount,
              latencyMs: s.latencyMs,
            }));

            const allTools = discoveryEngine.getAllTools();
            const toolsByServer: Record<string, string[]> = {};
            for (const t of allTools) {
              if (!toolsByServer[t.serverId]) {
                toolsByServer[t.serverId] = [];
              }
              toolsByServer[t.serverId].push(t.originalName);
            }

            const context: ProjectContext = {
              gatewayVersion: this.version,
              activeServers,
              totalDiscoveredTools: allTools.length,
              toolsByServer,
              securityPolicy: {
                leastPrivilegeEnforced: true,
                encryptedVaultActive: true,
                requireDestructiveApproval: true,
              },
            };

            return {
              content: [
                {
                  type: "text",
                  text: JSON.stringify(context, null, 2),
                },
              ],
            };
          }

          default:
            throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
        }
      } catch (err: unknown) {
        if (err instanceof McpError) {
          throw err;
        }
        const message = err instanceof Error ? err.message : String(err);
        log.error({ tool: name, error: message }, "Tool execution threw unhandled exception");
        throw new McpError(ErrorCode.InternalError, message);
      }
    });
  }

  /**
   * Initializes default auto-connect servers and starts tool discovery.
   */
  public async initializeDefaultServers(options?: { remoteOnly?: boolean }): Promise<void> {
    const isRemoteOnly = options?.remoteOnly ?? false;
    log.info({ isRemoteOnly }, "Auto-connecting initial servers...");
    const servers = serverRegistry
      .getAllServers()
      .filter((s) => s.enabled && s.autoConnect && (isRemoteOnly ? (s.transport === "http" || s.transport === "sse") : true));

    for (const server of servers) {
      try {
        await clientManager.connectServer(server);
        await discoveryEngine.discoverServerTools(server.id);
      } catch (err) {
        log.warn({ serverId: server.id, error: err }, "Auto-connect skipped or encountered error during startup");
      }
    }

    log.info(
      {
        connected: serverRegistry.getConnectedServers().length,
        totalTools: discoveryEngine.getAllTools().length,
      },
      "Gateway default servers initialized"
    );

    // Start background health checking
    healthMonitor.start(30000);
  }
}

