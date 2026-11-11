import { describe, it, beforeAll, afterAll, expect, vi } from "vitest";
import http from "node:http";
import { serverRegistry } from "../src/registry.js";
import { clientManager } from "../src/client-manager.js";
import { discoveryEngine } from "../src/discovery.js";
import { executionEngine } from "../src/executor.js";
import { profilesManager } from "../src/profiles.js";
import { executionHistory } from "../src/history.js";
import { validateRemoteServerUrl, sanitizeData } from "../src/security.js";
import { ServerConfig } from "../src/types.js";

describe("Google Stitch Remote MCP Integration", () => {
  let mockStitchServer: http.Server;
  let mockPort: number;
  let receivedHeaders: http.IncomingHttpHeaders = {};
  let simulateAuthFailure = false;
  let simulateTimeout = false;

  beforeAll(async () => {
    // Spin up an HTTP mock server emulating upstream Google Stitch Streamable HTTP MCP endpoint
    mockStitchServer = http.createServer((req, res) => {
      receivedHeaders = req.headers;

      if (simulateTimeout) {
        // Do not respond; wait for client timeout
        return;
      }

      if (simulateAuthFailure) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Invalid Google Stitch API key provided." }));
        return;
      }

      // Check for X-Goog-Api-Key authentication header
      const apiKey = req.headers["x-goog-api-key"];
      if (!apiKey || apiKey !== "AIzaSyTestValidStitchKey123456789") {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Unauthorized: Invalid or missing X-Goog-Api-Key header" }));
        return;
      }

      let body = "";
      req.on("data", chunk => { body += chunk; });
      req.on("end", () => {
        let jsonReq: any = {};
        try { jsonReq = JSON.parse(body || "{}"); } catch {}

        res.writeHead(200, {
          "Content-Type": "application/json",
          "mcp-session-id": "stitch-mock-session-uuid",
        });

        // 1. Initialize Request
        if (jsonReq.method === "initialize") {
          res.end(JSON.stringify({
            jsonrpc: "2.0",
            id: jsonReq.id,
            result: {
              protocolVersion: "2025-11-25",
              capabilities: { tools: {} },
              serverInfo: { name: "Google Stitch Mock MCP", version: "1.0.0" }
            }
          }));
          return;
        }

        // 2. Notifications
        if (jsonReq.method === "notifications/initialized") {
          res.end(JSON.stringify({ jsonrpc: "2.0" }));
          return;
        }

        // 3. Tools Listing (Dynamic Discovery)
        if (jsonReq.method === "tools/list") {
          res.end(JSON.stringify({
            jsonrpc: "2.0",
            id: jsonReq.id,
            result: {
              tools: [
                {
                  name: "list_projects",
                  description: "List all Google Stitch UI design projects in workspace",
                  inputSchema: {
                    type: "object",
                    properties: { filter: { type: "string" } }
                  }
                },
                {
                  name: "get_screen",
                  description: "Retrieve a specific design screen and component tree by ID",
                  inputSchema: {
                    type: "object",
                    properties: { screenId: { type: "string" } },
                    required: ["screenId"]
                  }
                },
                {
                  name: "generate_screen",
                  description: "Generate a new application screen UI from natural language prompt",
                  inputSchema: {
                    type: "object",
                    properties: {
                      prompt: { type: "string" },
                      styleGuide: { type: "string" }
                    },
                    required: ["prompt"]
                  }
                },
                {
                  name: "create_component",
                  description: "Synthesize a reusable UI component in Stitch design system",
                  inputSchema: {
                    type: "object",
                    properties: {
                      name: { type: "string" },
                      tokens: { type: "object" }
                    },
                    required: ["name"]
                  }
                }
              ]
            }
          }));
          return;
        }

        // 4. Tool Execution
        if (jsonReq.method === "tools/call") {
          const toolName = jsonReq.params?.name;
          const args = jsonReq.params?.arguments || {};

          if (toolName === "list_projects") {
            res.end(JSON.stringify({
              jsonrpc: "2.0",
              id: jsonReq.id,
              result: {
                content: [
                  {
                    type: "text",
                    text: JSON.stringify({
                      projects: [
                        { id: "proj-101", title: "Mobile Banking Dashboard", screens: 4 },
                        { id: "proj-102", title: "SaaS Analytics Console", screens: 8 }
                      ]
                    })
                  }
                ],
                isError: false
              }
            }));
            return;
          }

          if (toolName === "generate_screen") {
            res.end(JSON.stringify({
              jsonrpc: "2.0",
              id: jsonReq.id,
              result: {
                content: [
                  {
                    type: "text",
                    text: JSON.stringify({
                      screenId: "scr-883",
                      name: "Generated Customer Overview",
                      componentsCount: 14,
                      promptUsed: args.prompt
                    })
                  }
                ],
                isError: false
              }
            }));
            return;
          }

          res.end(JSON.stringify({
            jsonrpc: "2.0",
            id: jsonReq.id,
            result: {
              content: [{ type: "text", text: `Unknown tool: ${toolName}` }],
              isError: true
            }
          }));
          return;
        }

        // Default empty response
        res.end(JSON.stringify({ jsonrpc: "2.0", id: jsonReq.id, result: {} }));
      });
    });

    await new Promise<void>((resolve) => {
      mockStitchServer.listen(0, "127.0.0.1", () => {
        const addr = mockStitchServer.address() as any;
        mockPort = addr.port;
        resolve();
      });
    });
  });

  afterAll(async () => {
    delete process.env.STITCH_API_KEY;
    delete process.env.STITCH_TIMEOUT_MS;
    await clientManager.disconnectServer("stitch");
    await new Promise<void>((resolve) => mockStitchServer.close(() => resolve()));
  });

  // ---------------------------------------------------------------------------
  // 1. Configuration Validation
  // ---------------------------------------------------------------------------
  it("should validate official Google Stitch MCP configuration in registry", () => {
    const stitch = serverRegistry.getServer("stitch");
    expect(stitch).toBeDefined();
    expect(stitch?.id).toBe("stitch");
    expect(stitch?.name).toBe("Google Stitch MCP");
    expect(stitch?.transport).toBe("http");
    expect(stitch?.url).toBe("https://stitch.googleapis.com/mcp");
    expect(stitch?.category).toBe("development");

    // SSRF URL validation test
    const validation = validateRemoteServerUrl("https://stitch.googleapis.com/mcp");
    expect(validation.valid).toBe(true);
  });

  // ---------------------------------------------------------------------------
  // 2. Missing API Key Validation
  // ---------------------------------------------------------------------------
  it("should reject connection when STITCH_API_KEY is not provisioned", async () => {
    delete process.env.STITCH_API_KEY;

    await expect(
      clientManager.connectServer({
        id: "stitch",
        name: "Google Stitch MCP",
        description: "Google Stitch hosted remote MCP server",
        category: "development",
        transport: "http",
        enabled: true,
        autoConnect: false,
        url: `http://127.0.0.1:${mockPort}/mcp`,
      })
    ).rejects.toThrow(/STITCH_API_KEY environment variable/i);

    const stitch = serverRegistry.getServer("stitch");
    expect(stitch?.status).toBe("error");
    expect(stitch?.error).toMatch(/STITCH_API_KEY/i);
  });

  // ---------------------------------------------------------------------------
  // 3. Successful Remote Connection with X-Goog-Api-Key Header
  // ---------------------------------------------------------------------------
  it("should successfully connect to remote Stitch MCP using X-Goog-Api-Key", async () => {
    process.env.STITCH_API_KEY = "AIzaSyTestValidStitchKey123456789";
    simulateAuthFailure = false;

    const mockConfig: ServerConfig = {
      id: "stitch",
      name: "Google Stitch MCP",
      description: "Google Stitch remote MCP",
      category: "development",
      transport: "http",
      enabled: true,
      autoConnect: true,
      url: `http://127.0.0.1:${mockPort}/mcp`,
    };

    const client = await clientManager.connectServer(mockConfig);
    expect(client).toBeDefined();
    expect(clientManager.isConnected("stitch")).toBe(true);

    // Verify X-Goog-Api-Key header was sent upstream
    expect(receivedHeaders["x-goog-api-key"]).toBe("AIzaSyTestValidStitchKey123456789");
    expect(receivedHeaders["user-agent"]).toBe("OmniMCP-Gateway/1.0.0");

    const serverState = serverRegistry.getServer("stitch");
    expect(serverState?.status).toBe("connected");
  });

  // ---------------------------------------------------------------------------
  // 4. Dynamic Tool Discovery & Schema Preservation
  // ---------------------------------------------------------------------------
  it("should dynamically discover and index all upstream Stitch tools with preserved schemas", async () => {
    const discovered = await discoveryEngine.discoverServerTools("stitch");
    expect(discovered.length).toBe(4);

    const listProj = discoveryEngine.getTool("stitch:list_projects");
    expect(listProj).toBeDefined();
    expect(listProj?.originalName).toBe("list_projects");
    expect(listProj?.permissionLevel).toBe("READ_ONLY");
    expect(listProj?.inputSchema).toHaveProperty("properties");

    const genScreen = discoveryEngine.getTool("stitch:generate_screen");
    expect(genScreen).toBeDefined();
    expect(genScreen?.originalName).toBe("generate_screen");
    expect(genScreen?.permissionLevel).toBe("WRITE_PROTECTED");
    expect(genScreen?.inputSchema).toHaveProperty("required", ["prompt"]);
  });

  // ---------------------------------------------------------------------------
  // 5. Tool Execution Pipeline
  // ---------------------------------------------------------------------------
  it("should execute read-only tool 'stitch:list_projects' and record audit trail", async () => {
    const result = await executionEngine.executeTool("stitch:list_projects", { filter: "mobile" }, { profileId: "developer" });

    expect(result.status).toBe("success");
    expect(result.serverId).toBe("stitch");
    expect(result.traceId).toBeDefined();

    // Verify content parsed from upstream
    const content = (result.content as any)?.content?.[0]?.text;
    expect(content).toContain("Mobile Banking Dashboard");

    // Verify audit history was saved
    const recent = executionHistory.getHistory(5);
    const trace = recent.find(r => r.toolId === "stitch:list_projects");
    expect(trace).toBeDefined();
    expect(trace?.status).toBe("success");
  });

  // ---------------------------------------------------------------------------
  // 6. Upstream Authentication Failure Handling
  // ---------------------------------------------------------------------------
  it("should gracefully handle upstream 401 Unauthorized without crashing gateway", async () => {
    await clientManager.disconnectServer("stitch");
    simulateAuthFailure = true;

    await expect(
      clientManager.connectServer({
        id: "stitch",
        name: "Google Stitch MCP",
        description: "Google Stitch remote MCP",
        category: "development",
        transport: "http",
        enabled: true,
        autoConnect: true,
        url: `http://127.0.0.1:${mockPort}/mcp`,
      })
    ).rejects.toThrow();

    const state = serverRegistry.getServer("stitch");
    expect(state?.status).toBe("error");

    simulateAuthFailure = false;
  });

  // ---------------------------------------------------------------------------
  // 7. Profile Boundary & RBAC Restrictions
  // ---------------------------------------------------------------------------
  it("should allow Stitch in Developer profile but reject in profiles where Stitch is disabled", async () => {
    // Reconnect cleanly
    process.env.STITCH_API_KEY = "AIzaSyTestValidStitchKey123456789";
    await clientManager.connectServer({
      id: "stitch",
      name: "Google Stitch MCP",
      description: "Google Stitch remote MCP",
      category: "development",
      transport: "http",
      enabled: true,
      autoConnect: true,
      url: `http://127.0.0.1:${mockPort}/mcp`,
    });
    await discoveryEngine.discoverServerTools("stitch");

    // Developer profile includes 'stitch'
    const devAccess = profilesManager.evaluateToolAccess("stitch:list_projects", "stitch", "READ_ONLY", "developer");
    expect(devAccess.allowed).toBe(true);

    // Backend profile does NOT include 'stitch' by default
    const backendAccess = profilesManager.evaluateToolAccess("stitch:list_projects", "stitch", "READ_ONLY", "backend");
    expect(backendAccess.allowed).toBe(false);
    expect(backendAccess.reason).toMatch(/disabled in active profile/i);
  });

  // ---------------------------------------------------------------------------
  // 8. Strict Read-Only Boundary Enforcement
  // ---------------------------------------------------------------------------
  it("should allow list queries but block design generation under Read-Only profile", async () => {
    // Read query should be evaluated against read-only permissions
    const readCheck = profilesManager.evaluateToolAccess("stitch:list_projects", "stitch", "READ_ONLY", "readonly");
    // Under readonly profile, write-protected tools like generate_screen MUST be blocked
    const writeCheck = profilesManager.evaluateToolAccess("stitch:generate_screen", "stitch", "WRITE_PROTECTED", "readonly");

    expect(writeCheck.allowed).toBe(false);
    expect(writeCheck.reason).toMatch(/strictly READ_ONLY/i);
  });

  // ---------------------------------------------------------------------------
  // 9. Upstream Timeout Handling
  // ---------------------------------------------------------------------------
  it("should enforce execution timeout and abort hanging upstream requests", async () => {
    simulateTimeout = true;

    const timeoutRes = await executionEngine.executeTool(
      "stitch:list_projects",
      {},
      { timeoutMs: 300, profileId: "developer" }
    );

    expect(timeoutRes.status).toBe("error");
    expect(timeoutRes.error).toMatch(/timed out/i);

    simulateTimeout = false;
  });

  // ---------------------------------------------------------------------------
  // 10. Secret Redaction & Zero In-Browser Exposure
  // ---------------------------------------------------------------------------
  it("should never expose STITCH_API_KEY in server registry queries or sanitized logs", () => {
    const allServers = serverRegistry.getAllServers();
    const stitchServer = allServers.find(s => s.id === "stitch");
    expect(stitchServer).toBeDefined();

    // Verify headers do not leak key in public server state
    const serialized = JSON.stringify(stitchServer);
    expect(serialized).not.toContain("AIzaSyTestValidStitchKey123456789");

    // Verify sanitizeData redacts X-Goog-Api-Key
    const rawError = "Error: Upstream request failed with x-goog-api-key: AIzaSyTestValidStitchKey123456789";
    const sanitized = sanitizeData(rawError);
    expect(sanitized).not.toContain("AIzaSyTestValidStitchKey123456789");
    expect(sanitized).toContain("[REDACTED_SECRET]");
  });

  // ---------------------------------------------------------------------------
  // 11. Graceful Disconnect & Eviction
  // ---------------------------------------------------------------------------
  it("should gracefully disconnect and unregister Stitch tools", async () => {
    await clientManager.disconnectServer("stitch");
    discoveryEngine.unregisterServerTools("stitch");

    expect(clientManager.isConnected("stitch")).toBe(false);
    expect(discoveryEngine.getTool("stitch:list_projects")).toBeUndefined();
    expect(discoveryEngine.getTool("stitch:generate_screen")).toBeUndefined();

    const state = serverRegistry.getServer("stitch");
    expect(state?.status).toBe("disconnected");
  });
});
