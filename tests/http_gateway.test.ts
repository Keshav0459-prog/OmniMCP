import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { OmniMCPGatewayServer } from "../src/gateway-server.js";
import { serverRegistry } from "../src/registry.js";
import { discoveryEngine } from "../src/discovery.js";
import { smartRouter } from "../src/router.js";
import { healthMonitor } from "../src/health.js";
import { clientManager } from "../src/client-manager.js";

describe("OmniMCP Gateway Server & API Logic (Sandbox Safe)", () => {
  let gateway: OmniMCPGatewayServer;

  beforeAll(async () => {
    gateway = new OmniMCPGatewayServer();
    await gateway.initializeDefaultServers();
  }, 25000);

  afterAll(async () => {
    healthMonitor.stop();
    await clientManager.disconnectAll();
  });

  it("should return health reports for connected servers", async () => {
    const reports = await healthMonitor.checkAllServers();
    expect(Array.isArray(reports)).toBe(true);
    expect(reports.length).toBeGreaterThanOrEqual(1);
    expect(reports.some((r) => r.id === "filesystem")).toBe(true);
  });

  it("should list all registered servers", () => {
    const servers = serverRegistry.getAllServers();
    expect(servers.length).toBeGreaterThanOrEqual(7);
    expect(servers.map((s) => s.id)).toContain("playwright");
    expect(servers.map((s) => s.id)).toContain("supabase");
    expect(servers.map((s) => s.id)).toContain("shadcn");
    expect(servers.map((s) => s.id)).toContain("sentry");
  });

  it("should discover and search tools across connected servers", () => {
    const tools = discoveryEngine.searchTools("read");
    expect(tools.length).toBeGreaterThanOrEqual(1);
    expect(tools.some((t) => t.id.includes("read"))).toBe(true);
  });

  it("should match capabilities via smart router", () => {
    const matched = smartRouter.matchCapabilities("Build a responsive UI with shadcn components and test with playwright");
    const matchedIds = matched.matchedServers.map((s) => s.id);
    expect(matchedIds).toContain("shadcn");
    expect(matchedIds).toContain("playwright");
  });
});
