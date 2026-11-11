import "dotenv/config";
import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";

if (!process.env.OMNIMCP_OPERATOR_TOKEN) {
  process.env.OMNIMCP_OPERATOR_TOKEN = "omnimcp_operator_2026";
}
if (!process.env.OMNIMCP_AGENT_TOKEN) {
  process.env.OMNIMCP_AGENT_TOKEN = "test_agent_token_secret_123456789";
}
import request from "supertest";
import { createHttpGateway } from "../src/http-gateway.js";
import { OmniMCPGatewayServer } from "../src/gateway-server.js";
import { profilesManager } from "../src/profiles.js";
import { executionEngine } from "../src/executor.js";
import { discoveryEngine } from "../src/discovery.js";
import { serverRegistry } from "../src/registry.js";
import { executionHistory } from "../src/history.js";
import { DiscoveredTool } from "../src/types.js";

describe("Profiles Engine & REST API (Milestone 2)", () => {
  const gateway = new OmniMCPGatewayServer();
  const app = createHttpGateway(gateway);
  const operatorToken = process.env.OMNIMCP_OPERATOR_TOKEN || "omnimcp_operator_2026";
  const agentToken = process.env.OMNIMCP_AGENT_TOKEN || process.env.OMNIMCP_AUTH_TOKEN || "test_token";

  beforeEach(() => {
    // Reset active profile to developer before each test
    profilesManager.setActiveProfile("developer");
  });

  describe("Profile Boundary & Tool Access Evaluation", () => {
    it("should allow tools matching enabled integrations in active profile", () => {
      profilesManager.setActiveProfile("developer");
      const devProfile = profilesManager.getActiveProfile();
      assert.equal(devProfile?.id, "developer");

      // Developer has filesystem and playwright
      const fsCheck = profilesManager.evaluateToolAccess("filesystem:read_file", "filesystem", "READ_ONLY");
      assert.equal(fsCheck.allowed, true);

      const pwCheck = profilesManager.evaluateToolAccess("playwright:navigate", "playwright", "WRITE_PROTECTED");
      assert.equal(pwCheck.allowed, true);
    });

    it("should allow write operations under Developer profile", () => {
      profilesManager.setActiveProfile("developer");
      const writeCheck = profilesManager.evaluateToolAccess("filesystem:write_file", "filesystem", "WRITE_PROTECTED");
      assert.equal(writeCheck.allowed, true);
    });

    it("should deny tools from integrations excluded by active profile", () => {
      // Backend profile has supabase, github, context7, sentry (NO playwright)
      profilesManager.setActiveProfile("backend");
      const backendProfile = profilesManager.getActiveProfile();
      assert.equal(backendProfile?.id, "backend");

      const pwCheck = profilesManager.evaluateToolAccess("playwright:navigate", "playwright");
      assert.equal(pwCheck.allowed, false);
      assert.match(pwCheck.reason || "", /disabled in active profile/i);

      // But Supabase is permitted in backend profile
      const supaCheck = profilesManager.evaluateToolAccess("supabase:execute_sql", "supabase");
      assert.equal(supaCheck.allowed, true);
    });

    it("should deny write and admin operations when active profile is Read Only", () => {
      profilesManager.setActiveProfile("readonly");
      const roProfile = profilesManager.getActiveProfile();
      assert.equal(roProfile?.id, "readonly");

      // Read operation is allowed
      const readCheck = profilesManager.evaluateToolAccess("filesystem:read_file", "filesystem", "READ_ONLY");
      assert.equal(readCheck.allowed, true);

      // Write operation is strictly denied
      const writeCheck = profilesManager.evaluateToolAccess("filesystem:write_file", "filesystem", "WRITE_PROTECTED");
      assert.equal(writeCheck.allowed, false);
      assert.match(writeCheck.reason || "", /strictly READ_ONLY/i);

      // Admin operation is strictly denied
      const adminCheck = profilesManager.evaluateToolAccess("filesystem:delete_file", "filesystem", "DESTRUCTIVE_ADMIN");
      assert.equal(adminCheck.allowed, false);
      assert.match(adminCheck.reason || "", /strictly READ_ONLY/i);
    });

    it("should immediately revoke write permissions upon switching to Read Only profile", () => {
      // 1. In developer profile, write is permitted
      profilesManager.setActiveProfile("developer");
      assert.equal(profilesManager.evaluateToolAccess("filesystem:write_file", "filesystem", "WRITE_PROTECTED").allowed, true);

      // 2. Switch to readonly
      profilesManager.setActiveProfile("readonly");
      const roCheck = profilesManager.evaluateToolAccess("filesystem:write_file", "filesystem", "WRITE_PROTECTED");
      assert.equal(roCheck.allowed, false);
      assert.match(roCheck.reason || "", /strictly READ_ONLY/i);

      // 3. Switch back to developer
      profilesManager.setActiveProfile("developer");
      assert.equal(profilesManager.evaluateToolAccess("filesystem:write_file", "filesystem", "WRITE_PROTECTED").allowed, true);
    });

    it("should record unauthorized profile tool execution in audit history as status: 'denied'", async () => {
      // Set to backend profile where playwright is disabled
      profilesManager.setActiveProfile("backend");

      const mockToolId = "playwright:browser_action_mock";
      const mockServerId = "playwright";

      const mockTool: DiscoveredTool = {
        id: mockToolId,
        serverId: mockServerId,
        originalName: "browser_action_mock",
        serverName: "Playwright",
        description: "Mock playwright action",
        inputSchema: { type: "object", properties: {} },
        permissionLevel: "WRITE_PROTECTED",
        requiresApproval: false,
      };

      const originalGetTool = discoveryEngine.getTool.bind(discoveryEngine);
      discoveryEngine.getTool = (id: string) => (id === mockToolId ? mockTool : originalGetTool(id));

      try {
        const result = await executionEngine.executeTool(mockToolId, { url: "https://example.com" });
        assert.equal(result.status, "denied");
        assert.match(result.error || "", /disabled in active profile/i);

        // Verify denial is logged in audit history
        const recent = executionHistory.getHistory(5);
        const record = recent.find(r => r.toolId === mockToolId);
        assert.ok(record, "Execution record must exist in audit log");
        assert.equal(record.status, "denied");
        assert.match(record.error || "", /disabled in active profile/i);
      } finally {
        discoveryEngine.getTool = originalGetTool;
      }
    });
  });

  describe("Profiles HTTP REST API Endpoints", () => {
    it("GET /api/profiles should return all profiles and activeProfileId", async () => {
      const res = await request(app)
        .get("/api/profiles")
        .set("Authorization", `Bearer ${operatorToken}`);

      assert.equal(res.status, 200);
      assert.ok(Array.isArray(res.body.profiles));
      assert.ok(res.body.profiles.length >= 4);
      assert.equal(res.body.activeProfileId, "developer");
    });

    it("GET /api/profiles/active should return current active profile", async () => {
      const res = await request(app)
        .get("/api/profiles/active")
        .set("Authorization", `Bearer ${operatorToken}`);

      assert.equal(res.status, 200);
      assert.equal(res.body.id, "developer");
      assert.ok(res.body.integrations.includes("filesystem"));
    });

    it("POST /api/profiles/:id/activate should switch active profile", async () => {
      const res = await request(app)
        .post("/api/profiles/qa/activate")
        .set("Authorization", `Bearer ${operatorToken}`);

      assert.equal(res.status, 200);
      assert.equal(res.body.status, "activated");
      assert.equal(res.body.profile.id, "qa");
      assert.equal(res.body.profile.isActive, true);

      // Verify active profile changed
      const active = profilesManager.getActiveProfile();
      assert.equal(active?.id, "qa");
    });

    it("POST /api/profiles should create a custom profile (OPERATOR ONLY)", async () => {
      const res = await request(app)
        .post("/api/profiles")
        .set("Authorization", `Bearer ${operatorToken}`)
        .send({
          name: "DevOps Sentry",
          description: "Monitoring and error tracking profile",
          integrations: ["sentry", "github"],
        });

      assert.equal(res.status, 201);
      assert.equal(res.body.name, "DevOps Sentry");
      assert.deepEqual(res.body.integrations, ["sentry", "github"]);

      // Cleanup
      profilesManager.deleteProfile(res.body.id);
    });

    it("POST /api/profiles should reject creation without operator token (RBAC protection)", async () => {
      const res = await request(app)
        .post("/api/profiles")
        .set("Authorization", `Bearer ${agentToken}`) // Agent role
        .send({
          name: "Escalated Profile",
          integrations: ["filesystem"],
        });

      // Agents cannot create or modify system profiles
      assert.equal(res.status, 403);
    });

    it("POST /api/profiles/:id/duplicate should duplicate existing profile", async () => {
      const res = await request(app)
        .post("/api/profiles/developer/duplicate")
        .set("Authorization", `Bearer ${operatorToken}`)
        .send({ name: "Developer Staging" });

      assert.equal(res.status, 201);
      assert.equal(res.body.name, "Developer Staging");
      assert.ok(res.body.integrations.includes("filesystem"));

      // Cleanup
      profilesManager.deleteProfile(res.body.id);
    });

    it("DELETE /api/profiles/:id should reject deleting default profile", async () => {
      const res = await request(app)
        .delete("/api/profiles/developer")
        .set("Authorization", `Bearer ${operatorToken}`);

      assert.equal(res.status, 400);
      assert.match(res.body.error, /Cannot delete profile/i);
    });
  });
});
