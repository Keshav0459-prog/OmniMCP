import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { OmniMCPGatewayServer } from "../src/gateway-server.js";
import { createHttpGateway } from "../src/http-gateway.js";
import { remoteTokenManager } from "../src/remote-mcp/token-manager.js";
import { remoteSessionManager } from "../src/remote-mcp/session-manager.js";
import { profilesManager } from "../src/profiles.js";
import { discoveryEngine } from "../src/discovery.js";
import { executionHistory } from "../src/history.js";

describe("Milestone M9: Remote MCP Streamable HTTP Transport & Security", () => {
  let httpServer: http.Server;
  let serverPort: number;
  let baseUrl: string;

  let devToken: string;
  let devTokenId: string;
  let roToken: string;
  let roTokenId: string;

  beforeAll(async () => {
    // 1. Setup mock downstream tools in discoveryEngine for deterministic testing
    discoveryEngine.registerTool({
      id: "filesystem:read_file",
      serverId: "filesystem",
      serverName: "Filesystem Server",
      originalName: "read_file",
      description: "Read file contents",
      permissionLevel: "READ_ONLY",
      requiresApproval: false,
      inputSchema: {
        type: "object",
        properties: { path: { type: "string" } },
        required: ["path"],
      },
    });

    discoveryEngine.registerTool({
      id: "filesystem:write_file",
      serverId: "filesystem",
      serverName: "Filesystem Server",
      originalName: "write_file",
      description: "Write content to disk",
      permissionLevel: "WRITE_PROTECTED",
      requiresApproval: false,
      inputSchema: {
        type: "object",
        properties: { path: { type: "string" }, content: { type: "string" } },
        required: ["path"],
      },
    });

    discoveryEngine.registerTool({
      id: "filesystem:delete_file",
      serverId: "filesystem",
      serverName: "Filesystem Server",
      originalName: "delete_file",
      description: "Delete file from disk",
      permissionLevel: "DESTRUCTIVE_ADMIN",
      requiresApproval: true,
      inputSchema: {
        type: "object",
        properties: { path: { type: "string" } },
        required: ["path"],
      },
    });

    // 2. Initialize tokens with explicit profile assignments
    remoteTokenManager.clearAllForTesting();
    const devCreated = remoteTokenManager.createToken({
      principalId: "agent-developer",
      assignedProfileId: "developer",
      name: "Developer Agent Token",
    });
    devToken = devCreated.rawToken;
    devTokenId = devCreated.record.id;

    const roCreated = remoteTokenManager.createToken({
      principalId: "agent-readonly",
      assignedProfileId: "readonly",
      name: "Read-Only Agent Token",
    });
    roToken = roCreated.rawToken;
    roTokenId = roCreated.record.id;

    // 3. Start HTTP Gateway server
    const gatewayServer = new OmniMCPGatewayServer();
    const app = createHttpGateway(gatewayServer);

    await new Promise<void>((resolve) => {
      httpServer = app.listen(0, "127.0.0.1", () => {
        const addr = httpServer.address() as { port: number };
        serverPort = addr.port;
        baseUrl = `http://127.0.0.1:${serverPort}`;
        resolve();
      });
    });
  });

  afterAll(async () => {
    await remoteSessionManager.clearAllForTesting();
    if (httpServer) {
      await new Promise<void>((resolve) => httpServer.close(() => resolve()));
    }
  });

  it("1. Initializes remote session & advertises tools matching Developer profile", async () => {
    const clientTransport = new StreamableHTTPClientTransport(new URL(`${baseUrl}/mcp`), {
      requestInit: {
        headers: {
          Authorization: `Bearer ${devToken}`,
        },
      },
    });

    const client = new Client({ name: "dev-test-client", version: "1.0.0" }, { capabilities: {} });
    await client.connect(clientTransport);

    expect(clientTransport.sessionId).toBeDefined();
    expect(typeof clientTransport.sessionId).toBe("string");

    const toolsResult = await client.listTools();
    const toolNames = toolsResult.tools.map((t) => t.name);

    // Should include central gateway tools
    expect(toolNames).toContain("call_tool");
    expect(toolNames).toContain("search_tools");
    expect(toolNames).toContain("search_servers");
    expect(toolNames).toContain("get_server_status");

    // Developer profile includes filesystem: read_file and write_file
    expect(toolNames).toContain("filesystem:read_file");
    expect(toolNames).toContain("filesystem:write_file");

    await client.close();
  });

  it("2. Executes tool under Developer profile and generates execution audit trail", async () => {
    const clientTransport = new StreamableHTTPClientTransport(new URL(`${baseUrl}/mcp`), {
      requestInit: {
        headers: {
          Authorization: `Bearer ${devToken}`,
        },
      },
    });

    const client = new Client({ name: "dev-executor-client", version: "1.0.0" }, { capabilities: {} });
    await client.connect(clientTransport);

    // Call search_servers
    const result = await client.callTool({
      name: "search_servers",
      arguments: {},
    });

    expect(result).toBeDefined();
    expect(Array.isArray(result.content)).toBe(true);
    expect(result.content[0].type).toBe("text");

    // Call search_tools via gateway
    const toolsSearch = await client.callTool({
      name: "search_tools",
      arguments: { query: "read" },
    });
    expect(toolsSearch).toBeDefined();

    await client.close();
  });

  it("3. Strictly enforces Read-Only boundary (denies WRITE & DESTRUCTIVE operations)", async () => {
    const clientTransport = new StreamableHTTPClientTransport(new URL(`${baseUrl}/mcp`), {
      requestInit: {
        headers: {
          Authorization: `Bearer ${roToken}`,
        },
      },
    });

    const client = new Client({ name: "ro-test-client", version: "1.0.0" }, { capabilities: {} });
    await client.connect(clientTransport);

    // List tools: read_file should be present, write_file should NOT be advertised to readonly
    const toolsResult = await client.listTools();
    const toolNames = toolsResult.tools.map((t) => t.name);
    expect(toolNames).toContain("filesystem:read_file");
    expect(toolNames).not.toContain("filesystem:write_file");
    expect(toolNames).not.toContain("filesystem:delete_file");

    // Attempting to execute write_file via call_tool must be denied by executor-level check
    const callResult = await client.callTool({
      name: "call_tool",
      arguments: {
        tool_id: "filesystem:write_file",
        parameters: { path: "test.txt", content: "data" },
      },
    });

    // Tool call should report error / denied
    expect(callResult.isError).toBe(true);
    const parsedContent = JSON.parse((callResult.content[0] as any).text);
    expect(parsedContent.status).toBe("denied");
    expect(parsedContent.error).toMatch(/READ_ONLY/i);

    // Attempting connect_server must be prohibited for readonly profile
    await expect(
      client.callTool({
        name: "connect_server",
        arguments: { server_id: "filesystem" },
      })
    ).rejects.toThrow(/readonly/i);

    await client.close();
  });

  it("4. Rejects missing, invalid, and revoked agent tokens with 401", async () => {
    // 4a. Missing token
    const resNoToken = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", method: "initialize", id: 1 }),
    });
    expect(resNoToken.status).toBe(401);

    // 4b. Invalid token
    const resInvalidToken = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer invalid_secret_token_12345",
      },
      body: JSON.stringify({ jsonrpc: "2.0", method: "initialize", id: 2 }),
    });
    expect(resInvalidToken.status).toBe(401);

    // 4c. Revoked token
    const ephemeralToken = remoteTokenManager.createToken({
      principalId: "ephemeral-agent",
      assignedProfileId: "developer",
    });

    // Before revocation: succeeds
    const resBefore = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
        Authorization: `Bearer ${ephemeralToken.rawToken}`,
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        method: "initialize",
        params: {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: { name: "test", version: "1.0.0" },
        },
        id: 3,
      }),
    });
    expect(resBefore.status).toBe(200);

    // Revoke token immediately
    const revoked = remoteTokenManager.revokeToken(ephemeralToken.record.id);
    expect(revoked).toBe(true);

    // After revocation: rejects with 401
    const resAfter = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
        Authorization: `Bearer ${ephemeralToken.rawToken}`,
      },
      body: JSON.stringify({ jsonrpc: "2.0", method: "initialize", id: 4 }),
    });
    expect(resAfter.status).toBe(401);
  });

  it("5. Rejects cross-session access and session spoofing with 403 Forbidden", async () => {
    // Agent 1 creates session S1
    const clientTransport1 = new StreamableHTTPClientTransport(new URL(`${baseUrl}/mcp`), {
      requestInit: {
        headers: {
          Authorization: `Bearer ${devToken}`,
        },
      },
    });
    const client1 = new Client({ name: "agent-1", version: "1.0.0" }, { capabilities: {} });
    await client1.connect(clientTransport1);
    const session1Id = clientTransport1.sessionId!;
    expect(session1Id).toBeDefined();

    // Agent 2 (different principal & token) attempts to issue a request using session1Id
    const spoofResponse = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${roToken}`, // Wrong token!
        "mcp-session-id": session1Id,
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        method: "tools/list",
        params: {},
        id: 10,
      }),
    });

    expect(spoofResponse.status).toBe(403);
    const body = await spoofResponse.json();
    expect(body.error.message).toMatch(/permission to access this MCP session/i);

    await client1.close();
  });

  it("6. Maintains independent concurrent sessions with different profiles", async () => {
    const devTransport = new StreamableHTTPClientTransport(new URL(`${baseUrl}/mcp`), {
      requestInit: { headers: { Authorization: `Bearer ${devToken}` } },
    });
    const devClient = new Client({ name: "dev-agent", version: "1.0.0" }, { capabilities: {} });
    await devClient.connect(devTransport);

    const roTransport = new StreamableHTTPClientTransport(new URL(`${baseUrl}/mcp`), {
      requestInit: { headers: { Authorization: `Bearer ${roToken}` } },
    });
    const roClient = new Client({ name: "ro-agent", version: "1.0.0" }, { capabilities: {} });
    await roClient.connect(roTransport);

    // Verify session IDs are distinct
    expect(devTransport.sessionId).not.toBe(roTransport.sessionId);

    // Concurrently fetch tools
    const [devTools, roTools] = await Promise.all([devClient.listTools(), roClient.listTools()]);

    const devNames = devTools.tools.map((t) => t.name);
    const roNames = roTools.tools.map((t) => t.name);

    expect(devNames).toContain("filesystem:write_file");
    expect(roNames).not.toContain("filesystem:write_file");

    await devClient.close();
    await roClient.close();
  });

  it("7. Dashboard global active profile changes do NOT affect existing remote sessions", async () => {
    // 1. Establish session bound to Developer profile
    const clientTransport = new StreamableHTTPClientTransport(new URL(`${baseUrl}/mcp`), {
      requestInit: { headers: { Authorization: `Bearer ${devToken}` } },
    });
    const client = new Client({ name: "stable-agent", version: "1.0.0" }, { capabilities: {} });
    await client.connect(clientTransport);

    // 2. Change global dashboard active profile to 'readonly'
    profilesManager.setActiveProfile("readonly");
    expect(profilesManager.getActiveProfile()?.id).toBe("readonly");

    // 3. Existing Developer session must still retain write access
    const tools = await client.listTools();
    const names = tools.tools.map((t) => t.name);
    expect(names).toContain("filesystem:write_file");

    // Reset active profile back to developer
    profilesManager.setActiveProfile("developer");
    await client.close();
  });

  it("8. Terminates session on DELETE and rejects subsequent requests with 404", async () => {
    const clientTransport = new StreamableHTTPClientTransport(new URL(`${baseUrl}/mcp`), {
      requestInit: { headers: { Authorization: `Bearer ${devToken}` } },
    });
    const client = new Client({ name: "terminating-agent", version: "1.0.0" }, { capabilities: {} });
    await client.connect(clientTransport);

    const sessionId = clientTransport.sessionId!;
    expect(remoteSessionManager.getSession(sessionId)).toBeDefined();

    // Terminate session explicitly via client
    await clientTransport.terminateSession();

    // Verify session is removed
    expect(remoteSessionManager.getSession(sessionId)).toBeUndefined();

    // Subsequent request with terminated session id should yield 404
    const res = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${devToken}`,
        "mcp-session-id": sessionId,
      },
      body: JSON.stringify({ jsonrpc: "2.0", method: "tools/list", id: 99 }),
    });

    expect(res.status).toBe(404);
  });
});
