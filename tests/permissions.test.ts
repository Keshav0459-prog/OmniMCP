import { describe, it, expect } from "vitest";
import { PermissionManager } from "../src/permissions.js";
import { DiscoveredTool, ServerConfig } from "../src/types.js";

describe("PermissionManager", () => {
  const pm = new PermissionManager();

  it("should classify tools accurately by intent", () => {
    expect(pm.classifyTool("read_file").level).toBe("READ_ONLY");
    expect(pm.classifyTool("list_directory").level).toBe("READ_ONLY");
    expect(pm.classifyTool("write_file").level).toBe("WRITE_PROTECTED");
    expect(pm.classifyTool("create_branch").level).toBe("WRITE_PROTECTED");
    expect(pm.classifyTool("delete_file").level).toBe("DESTRUCTIVE_ADMIN");
    expect(pm.classifyTool("delete_file").requiresApproval).toBe(true);
    expect(pm.classifyTool("drop_table").level).toBe("DESTRUCTIVE_ADMIN");
  });

  it("should permit read-only execution without sensitive confirmation", () => {
    const tool: DiscoveredTool = {
      id: "fs:read_file",
      originalName: "read_file",
      serverId: "fs",
      serverName: "Filesystem",
      description: "Read file",
      inputSchema: {},
      permissionLevel: "READ_ONLY",
      requiresApproval: false,
    };

    const server: ServerConfig = {
      id: "fs",
      name: "Filesystem",
      description: "FS",
      category: "core",
      transport: "stdio",
      enabled: true,
      autoConnect: true,
      allowedPermissions: ["READ_ONLY", "WRITE_PROTECTED"],
    };

    const check = pm.checkExecutionAllowed(tool, server, false);
    expect(check.allowed).toBe(true);
  });

  it("should strictly block destructive operations without human approval, even if confirm_sensitive is true", () => {
    const tool: DiscoveredTool = {
      id: "fs:delete_file",
      originalName: "delete_file",
      serverId: "fs",
      serverName: "Filesystem",
      description: "Delete file",
      inputSchema: {},
      permissionLevel: "DESTRUCTIVE_ADMIN",
      requiresApproval: true,
    };

    const server: ServerConfig = {
      id: "fs",
      name: "Filesystem",
      description: "FS",
      category: "core",
      transport: "stdio",
      enabled: true,
      autoConnect: true,
      allowedPermissions: ["READ_ONLY", "WRITE_PROTECTED", "DESTRUCTIVE_ADMIN"],
      requiresApprovalForDestructive: true,
    };

    // confirm_sensitive: false -> blocked
    const blockedFalse = pm.checkExecutionAllowed(tool, server, false);
    expect(blockedFalse.allowed).toBe(false);
    expect(blockedFalse.requiresHumanApproval).toBe(true);

    // confirm_sensitive: true WITHOUT human approval token -> MUST STILL BE BLOCKED!
    // An AI caller passing confirm_sensitive: true cannot authorize its own destructive operation.
    const blockedTrue = pm.checkExecutionAllowed(tool, server, true);
    expect(blockedTrue.allowed).toBe(false);
    expect(blockedTrue.requiresHumanApproval).toBe(true);
    expect(blockedTrue.reason).toContain("confirm_sensitive");
  });

  it("should enforce recursive canonical parameter hashing regardless of key ordering", () => {
    // 1. Deeply nested objects with different key order must produce identical hashes
    const payload1 = {
      action: "delete",
      filter: { status: "inactive", olderThanDays: 30, tags: ["temp", "cache"] },
      metadata: { author: { name: "admin", id: 42 }, priority: 1 },
    };

    const payload2 = {
      metadata: { priority: 1, author: { id: 42, name: "admin" } },
      action: "delete",
      filter: { tags: ["temp", "cache"], olderThanDays: 30, status: "inactive" },
    };

    const hash1 = pm.computeParamsHash(payload1);
    const hash2 = pm.computeParamsHash(payload2);
    expect(hash1).toBe(hash2);

    // 2. Array ordering must be preserved: [a, b] !== [b, a]
    const arrayPayload1 = { items: ["alpha", "beta"] };
    const arrayPayload2 = { items: ["beta", "alpha"] };
    expect(pm.computeParamsHash(arrayPayload1)).not.toBe(pm.computeParamsHash(arrayPayload2));

    // 3. Objects inside array elements must be recursively canonicalized
    const arrayWithObj1 = { items: [{ y: 2, x: 1 }] };
    const arrayWithObj2 = { items: [{ x: 1, y: 2 }] };
    expect(pm.computeParamsHash(arrayWithObj1)).toBe(pm.computeParamsHash(arrayWithObj2));

    // 4. Null values must be preserved
    const nullPayload1 = { opt: null, valid: true };
    const nullPayload2 = { valid: true, opt: null };
    expect(pm.computeParamsHash(nullPayload1)).toBe(pm.computeParamsHash(nullPayload2));

    // 5. Any parameter tampering must produce a different hash
    const tamperedPayload = {
      action: "delete",
      filter: { status: "active", olderThanDays: 30, tags: ["temp", "cache"] },
      metadata: { author: { name: "admin", id: 42 }, priority: 1 },
    };
    expect(pm.computeParamsHash(tamperedPayload)).not.toBe(hash1);
  });

  it("should reject non-JSON and circular structures in canonical hashing", () => {
    // Functions must be rejected
    expect(() => {
      pm.computeParamsHash({ fn: () => {} } as any);
    }).toThrow(/Unsupported non-JSON/i);

    // Circular reference must be rejected
    const circular: any = { name: "loop" };
    circular.self = circular;
    expect(() => {
      pm.computeParamsHash(circular);
    }).toThrow(/Circular reference/i);
  });

  it("should execute the complete human approval lifecycle and prevent self-authorization", () => {
    const tool: DiscoveredTool = {
      id: "fs:delete_file",
      originalName: "delete_file",
      serverId: "fs",
      serverName: "Filesystem",
      description: "Delete file",
      inputSchema: {},
      permissionLevel: "DESTRUCTIVE_ADMIN",
      requiresApproval: true,
    };

    const server: ServerConfig = {
      id: "fs",
      name: "Filesystem",
      description: "FS",
      category: "core",
      transport: "stdio",
      enabled: true,
      autoConnect: true,
      allowedPermissions: ["READ_ONLY", "WRITE_PROTECTED", "DESTRUCTIVE_ADMIN"],
      requiresApprovalForDestructive: true,
    };

    const targetParams = { path: "/data/archive.tar.gz", recursive: true };

    // Step 1: Register approval request (status: pending, NO token issued yet)
    const req = pm.requestApproval(tool.id, server.id, targetParams);
    expect(req.status).toBe("pending");
    expect(req.token).toBeUndefined();

    // Step 2: Confirm it appears in pending approvals
    const pendingList = pm.getPendingApprovals();
    expect(pendingList.some((p) => p.id === req.id)).toBe(true);

    // Step 3: Human reviews and explicitly approves request
    const { token, request: approvedReq } = pm.approveRequest(req.id, "security_officer_alice");
    expect(approvedReq.status).toBe("approved");
    expect(approvedReq.approvedBy).toBe("security_officer_alice");
    expect(token).toBeDefined();

    // Step 4: Execution with valid token and exact parameters succeeds
    const executionResult = pm.checkExecutionAllowed(tool, server, false, token, targetParams);
    expect(executionResult.allowed).toBe(true);

    // Step 5: Single-use check — token is consumed and cannot be replayed
    const replayResult = pm.checkExecutionAllowed(tool, server, false, token, targetParams);
    expect(replayResult.allowed).toBe(false);
    expect(replayResult.reason).toContain("already consumed");
  });

  it("should reject execution if human explicitly rejects the approval request", () => {
    const tool: DiscoveredTool = {
      id: "db:drop_table",
      originalName: "drop_table",
      serverId: "db",
      serverName: "Database",
      description: "Drop table",
      inputSchema: {},
      permissionLevel: "DESTRUCTIVE_ADMIN",
      requiresApproval: true,
    };

    const server: ServerConfig = {
      id: "db",
      name: "Database",
      description: "DB",
      category: "database",
      transport: "stdio",
      enabled: true,
      autoConnect: true,
      allowedPermissions: ["DESTRUCTIVE_ADMIN"],
    };

    const params = { table: "users" };
    const req = pm.requestApproval(tool.id, server.id, params);

    // Human operator rejects the request
    pm.rejectRequest(req.id, "admin", "Dropping production tables is strictly forbidden");

    // Cannot approve an already-rejected request
    expect(() => {
      pm.approveRequest(req.id, "attacker");
    }).toThrow(/already rejected/i);

    // Execution without valid token is denied
    const denied = pm.checkExecutionAllowed(tool, server, false, undefined, params);
    expect(denied.allowed).toBe(false);
  });

  it("should enforce parameter-bound approval tokens and reject parameter tampering", () => {
    const originalParams = { path: "/workspace/config.json", force: true };
    const tamperedParams = { path: "/etc/shadow", force: true };

    const token = pm.issueApprovalToken("fs:delete_file", originalParams, 60);
    expect(token).toBeDefined();

    // Verification with tampered parameters must fail
    const tamperedCheck = pm.consumeApprovalToken(token, "fs:delete_file", tamperedParams);
    expect(tamperedCheck.valid).toBe(false);

    // Single-use check: even original parameters fail after a failed or consumed token attempt
    const replayCheck = pm.consumeApprovalToken(token, "fs:delete_file", originalParams);
    expect(replayCheck.valid).toBe(false);

    // Fresh valid token with exact parameters succeeds
    const freshToken = pm.issueApprovalToken("fs:delete_file", originalParams, 60);
    const validCheck = pm.consumeApprovalToken(freshToken, "fs:delete_file", originalParams);
    expect(validCheck.valid).toBe(true);
  });

  it("should authorize execution with a valid parameter-bound approval token", () => {
    const tool: DiscoveredTool = {
      id: "fs:delete_file",
      originalName: "delete_file",
      serverId: "fs",
      serverName: "Filesystem",
      description: "Delete file",
      inputSchema: {},
      permissionLevel: "DESTRUCTIVE_ADMIN",
      requiresApproval: true,
    };

    const server: ServerConfig = {
      id: "fs",
      name: "Filesystem",
      description: "FS",
      category: "core",
      transport: "stdio",
      enabled: true,
      autoConnect: true,
      allowedPermissions: ["READ_ONLY", "WRITE_PROTECTED", "DESTRUCTIVE_ADMIN"],
      requiresApprovalForDestructive: true,
    };

    const params = { target: "temp.log" };
    const validToken = pm.issueApprovalToken(tool.id, params);

    // Execute with valid token and exact params
    const allowed = pm.checkExecutionAllowed(tool, server, false, validToken, params);
    expect(allowed.allowed).toBe(true);
  });
});

