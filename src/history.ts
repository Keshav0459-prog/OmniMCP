import crypto from "node:crypto";
import { ExecutionRecord } from "./types.js";
import { sanitizeData } from "./security.js";
import { dbManager } from "./db.js";
import { createChildLogger } from "./logger.js";
import { telemetryManager } from "./telemetry.js";

const log = createChildLogger("history");

export class ExecutionHistoryManager {
  private records: ExecutionRecord[] = [];
  private maxRecords = 500;

  public recordExecution(
    toolId: string,
    serverId: string,
    originalToolName: string,
    rawParams: Record<string, unknown>,
    rawOutput: unknown,
    status: "success" | "error" | "denied",
    durationMs: number,
    error?: string
  ): ExecutionRecord {
    const record: ExecutionRecord = {
      id: crypto.randomUUID(),
      traceId: crypto.randomBytes(8).toString("hex"),
      toolId,
      serverId,
      originalToolName,
      inputParameters: sanitizeData(rawParams) as Record<string, unknown>,
      outputResult: sanitizeData(rawOutput),
      status,
      durationMs,
      timestamp: new Date().toISOString(),
      error: error ? (sanitizeData(error) as string) : undefined,
    };

    this.records.unshift(record);
    if (this.records.length > this.maxRecords) {
      this.records.pop();
    }

    // Persist to SQLite
    dbManager.insertAuditLog(record);

    // Ingest into real-time telemetry pipeline (in-memory O(1))
    telemetryManager.recordExecution(record);

    log.debug(
      { traceId: record.traceId, toolId, status, durationMs },
      "Recorded tool execution"
    );

    return record;
  }

  public getHistory(limit = 20, serverId?: string, status?: string, traceId?: string, offset = 0): ExecutionRecord[] {
    // Attempt to load from database for persistence across reboots
    const dbLogs = dbManager.queryAuditLogs(limit, serverId, status, traceId, offset);
    if (dbLogs.length > 0) {
      return dbLogs;
    }

    let filtered = this.records;
    if (serverId) {
      filtered = filtered.filter((r) => r.serverId === serverId);
    }
    if (status) {
      filtered = filtered.filter((r) => r.status === status);
    }
    if (traceId) {
      filtered = filtered.filter((r) => r.traceId === traceId);
    }
    return filtered.slice(offset, offset + Math.min(limit, 100));
  }

  public countHistory(serverId?: string, status?: string, traceId?: string): number {
    const dbCount = dbManager.countAuditLogs(serverId, status, traceId);
    if (dbCount > 0 || this.records.length === 0) {
      return dbCount;
    }

    let filtered = this.records;
    if (serverId) {
      filtered = filtered.filter((r) => r.serverId === serverId);
    }
    if (status) {
      filtered = filtered.filter((r) => r.status === status);
    }
    if (traceId) {
      filtered = filtered.filter((r) => r.traceId === traceId);
    }
    return filtered.length;
  }

  public getByTraceId(traceId: string): ExecutionRecord | undefined {
    const dbRecord = dbManager.getAuditLogByTraceId(traceId);
    if (dbRecord) return dbRecord;
    return this.records.find((r) => r.traceId === traceId);
  }

  public clearHistory(): void {
    this.records = [];
  }
}

export const executionHistory = new ExecutionHistoryManager();
