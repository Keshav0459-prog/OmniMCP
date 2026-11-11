import { describe, it, expect } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import path from "node:path";

describe("OmniMCP STDIO Gateway (Subprocess Antigravity Emulation)", () => {
  it("should communicate with OmniMCP over STDIO process boundaries", async () => {
    const entrypoint = path.resolve("dist/index.js");

    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [entrypoint],
      env: {
        ...process.env,
        LOG_LEVEL: "silent",
      },
      cwd: process.cwd(),
    });

    const client = new Client(
      {
        name: "antigravity-stdio-client",
        version: "1.0.0",
      },
      {
        capabilities: {},
      }
    );

    try {
      await client.connect(transport);

      // 1. Verify Tool Listing over STDIO
      const tools = await client.listTools();
      expect(tools.tools.length).toBe(10);
      expect(tools.tools.map((t) => t.name)).toContain("call_tool");
      expect(tools.tools.map((t) => t.name)).toContain("search_tools");

      // 2. Call get_project_context over STDIO (with short retry if still indexing)
      let contextData: any;
      for (let attempt = 0; attempt < 10; attempt++) {
        const contextRes = await client.callTool({
          name: "get_project_context",
          arguments: {},
        });
        contextData = JSON.parse((contextRes.content as any)[0].text);
        if (contextData && contextData.totalDiscoveredTools >= 16) break;
        await new Promise((resolve) => setTimeout(resolve, 300));
      }
      expect(contextData.gatewayVersion).toBe("1.0.0");
      expect(contextData.totalDiscoveredTools).toBeGreaterThanOrEqual(16);

      // 3. Search and Call a tool via Gateway over STDIO
      const callRes = await client.callTool({
        name: "call_tool",
        arguments: {
          tool_id: "filesystem:list_allowed_directories",
          parameters: {},
        },
      });
      const callData = JSON.parse((callRes.content as any)[0].text);
      expect(callData.status).toBe("success");
      expect(callData.serverId).toBe("filesystem");
    } finally {
      await client.close();
      await transport.close();
    }
  }, 25000);
});

