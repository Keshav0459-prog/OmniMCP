import { describe, it, expect } from "vitest";
import { PermissionManager } from "../src/permissions.js";

describe("PermissionManager Rate Limiting & Overrides", () => {
  it("should enforce rate limits when max calls exceeded", () => {
    const pm = new PermissionManager();
    const toolId = "test:fast_tool";

    // Set limit of 3 calls per minute
    pm.setPolicyOverride(toolId, { rateLimitPerMinute: 3 });

    expect(pm.checkRateLimit(toolId).allowed).toBe(true);
    expect(pm.checkRateLimit(toolId).allowed).toBe(true);
    expect(pm.checkRateLimit(toolId).allowed).toBe(true);

    const fourth = pm.checkRateLimit(toolId);
    expect(fourth.allowed).toBe(false);
    expect(fourth.retryAfterSeconds).toBeGreaterThan(0);
  });

  it("should honor policy overrides for tool permission level", () => {
    const pm = new PermissionManager();
    const toolId = "custom:risky_action";

    // Default is WRITE_PROTECTED with approval required for unknown tools (safe default-deny)
    expect(pm.classifyTool(toolId).level).toBe("WRITE_PROTECTED");

    // Override to destructive admin
    pm.setPolicyOverride(toolId, { permissionLevel: "DESTRUCTIVE_ADMIN", requiresApproval: true });
    expect(pm.classifyTool(toolId).level).toBe("DESTRUCTIVE_ADMIN");
    expect(pm.classifyTool(toolId).requiresApproval).toBe(true);
  });
});

