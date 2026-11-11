import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { DatabaseManager } from "../src/db.js";
import { ServerConfig, ExecutionRecord } from "../src/types.js";
import fs from "node:fs";

describe("DatabaseManager (SQLite Persistence)", () => {
  let db: DatabaseManager;

  beforeEach(() => {
    db = new DatabaseManager(":memory:");
  });

  afterEach(() => {
    db.close();
  });

  it("should persist and retrieve servers across instances", () => {
    const config: ServerConfig = {
      id: "custom-server",
      name: "Custom Integration",
      description: "Custom downstream MCP server",
      category: "custom",
      transport: "stdio",
      enabled: true,
      autoConnect: false,
      command: "node",
      args: ["test.js"],
      allowedPermissions: ["READ_ONLY"],
      requiresApprovalForDestructive: true,
    };

    db.upsertServer(config);

    const servers = db.getPersistedServers();
    expect(servers.length).toBe(1);
    expect(servers[0].id).toBe("custom-server");
    expect(servers[0].name).toBe("Custom Integration");
    expect(servers[0].allowedPermissions).toContain("READ_ONLY");
  });

  it("should insert and query audit logs", () => {
    const record: ExecutionRecord = {
      id: "rec-1",
      traceId: "trace-123",
      toolId: "filesystem:read_file",
      serverId: "filesystem",
      originalToolName: "read_file",
      inputParameters: { path: "package.json" },
      outputResult: { content: "test" },
      status: "success",
      durationMs: 15,
      timestamp: new Date().toISOString(),
    };

    db.insertAuditLog(record);

    const logs = db.queryAuditLogs(10);
    expect(logs.length).toBe(1);
    expect(logs[0].toolId).toBe("filesystem:read_file");
    expect(logs[0].status).toBe("success");
    expect(logs[0].durationMs).toBe(15);
  });

  it("should record and retrieve server metrics", () => {
    db.recordMetric("filesystem", "connected", 12);
    db.recordMetric("filesystem", "connected", 14);

    const metrics = db.getRecentMetrics("filesystem");
    expect(metrics.length).toBe(2);
    expect(metrics[0].latencyMs).toBe(12);
    expect(metrics[1].latencyMs).toBe(14);
  });
});
