import { describe, it, expect, afterAll } from "vitest";
import { clientManager } from "../src/client-manager.js";
import { serverRegistry } from "../src/registry.js";
import { discoveryEngine } from "../src/discovery.js";

describe("7 Downstream MCP Integrations Verification", () => {
  afterAll(async () => {
    await clientManager.disconnectAll();
  });

  it("1. Filesystem MCP should connect and list filesystem tools", async () => {
    const s = serverRegistry.getServer("filesystem")!;
    await clientManager.connectServer(s);
    const tools = await discoveryEngine.discoverServerTools("filesystem");
    expect(tools.length).toBeGreaterThanOrEqual(10);
    expect(tools.some((t) => t.id === "filesystem:read_file")).toBe(true);
  });

  it("2. Context7 MCP should connect and list documentation query tools", async () => {
    const s = serverRegistry.getServer("context7")!;
    await clientManager.connectServer(s);
    const tools = await discoveryEngine.discoverServerTools("context7");
    expect(tools.length).toBe(2);
    expect(tools.some((t) => t.id === "context7:query-docs")).toBe(true);
  });

  it("3. Playwright MCP should connect and list browser automation tools", async () => {
    const s = serverRegistry.getServer("playwright")!;
    await clientManager.connectServer(s);
    const tools = await discoveryEngine.discoverServerTools("playwright");
    expect(tools.length).toBeGreaterThanOrEqual(15);
    expect(tools.some((t) => t.id === "playwright:browser_close")).toBe(true);
  });

  it("4. shadcn/ui MCP should connect and list component inspection tools", async () => {
    const s = serverRegistry.getServer("shadcn")!;
    await clientManager.connectServer(s);
    const tools = await discoveryEngine.discoverServerTools("shadcn");
    expect(tools.length).toBe(4);
    expect(tools.some((t) => t.id === "shadcn:list_components")).toBe(true);
  });

  it("5. Sentry MCP should connect and list observability tools", async () => {
    const s = serverRegistry.getServer("sentry")!;
    await clientManager.connectServer(s);
    const tools = await discoveryEngine.discoverServerTools("sentry");
    expect(tools.length).toBeGreaterThanOrEqual(5);
    expect(tools.some((t) => t.id === "sentry:whoami")).toBe(true);
  });

  it("6. Supabase MCP should connect and expose Postgres/Auth tools", async () => {
    const s = serverRegistry.getServer("supabase")!;
    await clientManager.connectServer(s);
    const tools = await discoveryEngine.discoverServerTools("supabase");
    expect(tools.length).toBe(7);
    expect(tools.some((t) => t.id === "supabase:supabase_query_table")).toBe(true);
  });
});
