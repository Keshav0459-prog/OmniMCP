import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { OmniMCPGatewayServer } from "../src/gateway-server.js";
import { clientManager } from "../src/client-manager.js";
import { healthMonitor } from "../src/health.js";

describe("OmniMCPGatewayServer (Antigravity Integration Contract)", () => {
  let gateway: OmniMCPGatewayServer;
  let client: Client;
  let clientTransport: any;
  let serverTransport: any;

  beforeAll(async () => {
    gateway = new OmniMCPGatewayServer();
    const server = gateway.getServer();

    [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

    client = new Client(
      {
        name: "antigravity-test-host",
        version: "1.0.0",
      },
      {
        capabilities: {},
      }
    );

    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);

    // Initialize initial servers (Filesystem, Context7)
    await gateway.initializeDefaultServers();
  }, 25000);

  afterAll(async () => {
    healthMonitor.stop();
    await clientManager.disconnectAll();
    await client.close();
    await gateway.getServer().close();
  });

  it("should advertise exactly the 10 Gateway Tools to Antigravity", async () => {
    const response = await client.listTools();
    const toolNames = response.tools.map((t) => t.name);

    expect(toolNames).toContain("search_servers");
    expect(toolNames).toContain("list_connected_servers");
    expect(toolNames).toContain("get_server_status");
    expect(toolNames).toContain("search_tools");
    expect(toolNames).toContain("get_tool_details");
    expect(toolNames).toContain("connect_server");
    expect(toolNames).toContain("disconnect_server");
    expect(toolNames).toContain("call_tool");
    expect(toolNames).toContain("get_execution_history");
    expect(toolNames).toContain("get_project_context");
    expect(toolNames.length).toBe(10);
  });

  it("Tool 1: search_servers should return registered servers", async () => {
    const res = await client.callTool({
      name: "search_servers",
      arguments: { category: "core" },
    });

    const parsed = JSON.parse((res.content as any)[0].text);
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed.length).toBe(1);
    expect(parsed[0].id).toBe("filesystem");
  });

  it("Tool 2: list_connected_servers should list active child servers", async () => {
    const res = await client.callTool({
      name: "list_connected_servers",
      arguments: {},
    });

    const parsed = JSON.parse((res.content as any)[0].text);
    expect(Array.isArray(parsed)).toBe(true);
    const ids = parsed.map((s: any) => s.id);
    expect(ids).toContain("filesystem");
    expect(ids).toContain("context7");
  });

  it("Tool 3: get_server_status should return server health and latency", async () => {
    const res = await client.callTool({
      name: "get_server_status",
      arguments: { server_id: "filesystem" },
    });

    const parsed = JSON.parse((res.content as any)[0].text);
    expect(parsed.id).toBe("filesystem");
    expect(parsed.status).toBe("connected");
    expect(parsed.toolCount).toBeGreaterThanOrEqual(10);
  });

  it("Tool 4: search_tools should discover tools across connected servers", async () => {
    const res = await client.callTool({
      name: "search_tools",
      arguments: { query: "read" },
    });

    const parsed = JSON.parse((res.content as any)[0].text);
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed.length).toBeGreaterThanOrEqual(1);

    const hasReadFile = parsed.some((t: any) => t.id === "filesystem:read_file" || t.id.includes("read"));
    expect(hasReadFile).toBe(true);
  });

  it("Tool 5: get_tool_details should return full JSON schema", async () => {
    const res = await client.callTool({
      name: "get_tool_details",
      arguments: { tool_id: "filesystem:read_file" },
    });

    const parsed = JSON.parse((res.content as any)[0].text);
    expect(parsed.id).toBe("filesystem:read_file");
    expect(parsed.originalName).toBe("read_file");
    expect(parsed.inputSchema).toBeDefined();
    expect(parsed.permissionLevel).toBe("READ_ONLY");
  });

  it("Tool 6: call_tool should execute child tool and record execution history", async () => {
    const res = await client.callTool({
      name: "call_tool",
      arguments: {
        tool_id: "filesystem:list_allowed_directories",
        parameters: {},
      },
    });

    const parsed = JSON.parse((res.content as any)[0].text);
    expect(parsed.status).toBe("success");
    expect(parsed.toolId).toBe("filesystem:list_allowed_directories");
    expect(parsed.traceId).toBeDefined();
  });

  it("Tool 7: get_execution_history should return recent sanitized audit logs", async () => {
    const res = await client.callTool({
      name: "get_execution_history",
      arguments: { limit: 5 },
    });

    const parsed = JSON.parse((res.content as any)[0].text);
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed.length).toBeGreaterThanOrEqual(1);
    expect(parsed[0].status).toBe("success");
  });

  it("Tool 8: get_project_context should summarize active capabilities and security posture", async () => {
    const res = await client.callTool({
      name: "get_project_context",
      arguments: {},
    });

    const parsed = JSON.parse((res.content as any)[0].text);
    expect(parsed.gatewayVersion).toBe("1.0.0");
    expect(parsed.totalDiscoveredTools).toBeGreaterThanOrEqual(15);
    expect(parsed.securityPolicy.leastPrivilegeEnforced).toBe(true);
  });
});

