import { ExecutionRecord } from "./types.js";
import { dbManager } from "./db.js";
import { createChildLogger } from "./logger.js";

const log = createChildLogger("telemetry");

export interface TimelineBucket {
  timestamp: number; // Unix epoch ms
  timeLabel: string; // Formatted HH:mm
  total: number;
  success: number;
  error: number;
  denied: number;
  latencies: number[];
  avgLatencyMs: number;
  p95LatencyMs: number;
  maxLatencyMs: number;
}

export interface HistogramBucket {
  label: string;
  min: number;
  max: number;
  count: number;
  percentage: number;
}

export interface ServerTelemetry {
  serverId: string;
  total: number;
  success: number;
  error: number;
  denied: number;
  totalLatencyMs: number;
  avgLatencyMs: number;
  lastError?: {
    toolId: string;
    message: string;
    timestamp: string;
  };
  lastActivity?: string;
}

export interface RecentErrorItem {
  traceId: string;
  serverId: string;
  toolId: string;
  error: string;
  durationMs: number;
  timestamp: string;
}

export class TelemetryManager {
  private activeInFlight = 0;
  private readonly maxRecentErrors = 50;
  private recentErrors: RecentErrorItem[] = [];

  // In-memory ring buffer of recent raw executions (last 500)
  private readonly maxRecentRecords = 500;
  private recentRecords: ExecutionRecord[] = [];

  // Server-level aggregates
  private serverAggregates = new Map<string, ServerTelemetry>();

  private initialized = false;

  constructor() {}

  /**
   * Increment active in-flight executions counter
   */
  public incrementInFlight(): void {
    this.activeInFlight++;
  }

  /**
   * Decrement active in-flight executions counter
   */
  public decrementInFlight(): void {
    this.activeInFlight = Math.max(0, this.activeInFlight - 1);
  }

  public getActiveInFlight(): number {
    return this.activeInFlight;
  }

  /**
   * Seed telemetry from SQLite audit logs on startup so graphs show past data immediately
   */
  public initFromDatabase(): void {
    if (this.initialized) return;
    this.initialized = true;

    try {
      const pastLogs = dbManager.queryAuditLogs(200);
      if (Array.isArray(pastLogs) && pastLogs.length > 0) {
        // Query returns newest first, so reverse to chronological order for replay
        const chronological = [...pastLogs].reverse();
        for (const record of chronological) {
          this.ingestRecord(record, false);
        }
        log.info({ count: chronological.length }, "Seeded in-memory telemetry from persistent database");
      }
    } catch (err) {
      log.warn({ err }, "Could not seed telemetry from database");
    }
  }

  /**
   * Record a new execution into the telemetry pipeline
   */
  public recordExecution(record: ExecutionRecord): void {
    this.ingestRecord(record, true);
  }

  private ingestRecord(record: ExecutionRecord, isLive: boolean): void {
    // 1. Maintain recent execution ring buffer
    this.recentRecords.unshift(record);
    if (this.recentRecords.length > this.maxRecentRecords) {
      this.recentRecords.pop();
    }

    // 2. Track server aggregates
    const sId = record.serverId || "unknown";
    let sAgg = this.serverAggregates.get(sId);
    if (!sAgg) {
      sAgg = {
        serverId: sId,
        total: 0,
        success: 0,
        error: 0,
        denied: 0,
        totalLatencyMs: 0,
        avgLatencyMs: 0,
      };
      this.serverAggregates.set(sId, sAgg);
    }

    sAgg.total++;
    sAgg.totalLatencyMs += record.durationMs;
    sAgg.avgLatencyMs = Math.round(sAgg.totalLatencyMs / sAgg.total);
    sAgg.lastActivity = record.timestamp;

    if (record.status === "success") {
      sAgg.success++;
    } else if (record.status === "error") {
      sAgg.error++;
      if (record.error) {
        sAgg.lastError = {
          toolId: record.toolId,
          message: record.error,
          timestamp: record.timestamp,
        };
      }
    } else if (record.status === "denied") {
      sAgg.denied++;
    }

    // 3. Track recent errors ring buffer
    if (record.status === "error" && record.error) {
      this.recentErrors.unshift({
        traceId: record.traceId,
        serverId: record.serverId,
        toolId: record.toolId,
        error: record.error,
        durationMs: record.durationMs,
        timestamp: record.timestamp,
      });
      if (this.recentErrors.length > this.maxRecentErrors) {
        this.recentErrors.pop();
      }
    }

    if (isLive) {
      log.debug(
        { toolId: record.toolId, status: record.status, durationMs: record.durationMs },
        "Ingested telemetry record"
      );
    }
  }

  /**
   * Get dynamic timeline buckets for a specified duration ('15m', '1h', '6h', '24h')
   */
  public getTimeline(range: "15m" | "1h" | "6h" | "24h" = "1h"): {
    range: string;
    timeline: Array<{
      timestamp: number;
      timeLabel: string;
      total: number;
      success: number;
      error: number;
      denied: number;
      avgLatencyMs: number;
      p95LatencyMs: number;
      maxLatencyMs: number;
    }>;
    histogram: {
      buckets: HistogramBucket[];
      p50: number;
      p90: number;
      p95: number;
      p99: number;
      max: number;
    };
    servers: Record<string, ServerTelemetry>;
    recentErrors: RecentErrorItem[];
    activeInFlight: number;
    summary: {
      total: number;
      success: number;
      error: number;
      denied: number;
      successRate: number;
      avgLatencyMs: number;
      p95LatencyMs: number;
      budgetComplianceRate: number; // Percentage under 500ms
    };
  } {
    const now = Date.now();
    let windowMs: number;
    let bucketCount: number;

    switch (range) {
      case "15m":
        windowMs = 15 * 60 * 1000;
        bucketCount = 15; // 1-minute buckets
        break;
      case "6h":
        windowMs = 6 * 60 * 60 * 1000;
        bucketCount = 24; // 15-minute buckets
        break;
      case "24h":
        windowMs = 24 * 60 * 60 * 1000;
        bucketCount = 24; // 1-hour buckets
        break;
      case "1h":
      default:
        windowMs = 60 * 60 * 1000;
        bucketCount = 20; // 3-minute buckets
        break;
    }

    const bucketSizeMs = windowMs / bucketCount;
    const windowStart = now - windowMs;

    // Initialize empty chronological buckets
    const buckets: TimelineBucket[] = [];
    for (let i = 0; i < bucketCount; i++) {
      const bTime = windowStart + i * bucketSizeMs;
      const d = new Date(bTime);
      const hours = String(d.getHours()).padStart(2, "0");
      const mins = String(d.getMinutes()).padStart(2, "0");
      buckets.push({
        timestamp: bTime,
        timeLabel: `${hours}:${mins}`,
        total: 0,
        success: 0,
        error: 0,
        denied: 0,
        latencies: [],
        avgLatencyMs: 0,
        p95LatencyMs: 0,
        maxLatencyMs: 0,
      });
    }

    // Filter recent records in range
    const inRangeRecords: ExecutionRecord[] = [];
    const allLatencies: number[] = [];

    for (const rec of this.recentRecords) {
      const recTime = new Date(rec.timestamp).getTime();
      if (recTime >= windowStart && recTime <= now) {
        inRangeRecords.push(rec);
        allLatencies.push(rec.durationMs);

        // Assign to bucket
        const idx = Math.min(
          bucketCount - 1,
          Math.max(0, Math.floor((recTime - windowStart) / bucketSizeMs))
        );
        const b = buckets[idx];
        b.total++;
        b.latencies.push(rec.durationMs);
        if (rec.status === "success") b.success++;
        else if (rec.status === "error") b.error++;
        else if (rec.status === "denied") b.denied++;
      }
    }

    // Calculate per-bucket aggregates
    for (const b of buckets) {
      if (b.latencies.length > 0) {
        const sum = b.latencies.reduce((acc, v) => acc + v, 0);
        b.avgLatencyMs = Math.round(sum / b.latencies.length);
        b.maxLatencyMs = Math.max(...b.latencies);
        const sorted = [...b.latencies].sort((a, b) => a - b);
        const p95Idx = Math.min(sorted.length - 1, Math.floor(sorted.length * 0.95));
        b.p95LatencyMs = sorted[p95Idx];
      }
    }

    // Calculate histogram buckets across all recent executions (or inRange if sufficient)
    const recordsForHistogram = inRangeRecords.length >= 5 ? inRangeRecords : this.recentRecords;
    const histogram = this.calculateHistogram(recordsForHistogram);

    // Calculate overall summary metrics
    const totalRuns = inRangeRecords.length > 0 ? inRangeRecords.length : this.recentRecords.length;
    const successRuns = (inRangeRecords.length > 0 ? inRangeRecords : this.recentRecords).filter(
      (r) => r.status === "success"
    ).length;
    const errorRuns = (inRangeRecords.length > 0 ? inRangeRecords : this.recentRecords).filter(
      (r) => r.status === "error"
    ).length;
    const deniedRuns = (inRangeRecords.length > 0 ? inRangeRecords : this.recentRecords).filter(
      (r) => r.status === "denied"
    ).length;

    const latList = recordsForHistogram.map((r) => r.durationMs).sort((a, b) => a - b);
    const avgLatency =
      latList.length > 0 ? Math.round(latList.reduce((a, b) => a + b, 0) / latList.length) : 0;
    const p95Latency = latList.length > 0 ? latList[Math.floor(latList.length * 0.95)] : 0;
    const underBudgetCount = latList.filter((l) => l <= 500).length;
    const budgetComplianceRate =
      latList.length > 0 ? Math.round((underBudgetCount / latList.length) * 1000) / 10 : 100;

    // Convert server aggregates to plain object
    const serversObj: Record<string, ServerTelemetry> = {};
    for (const [k, v] of this.serverAggregates.entries()) {
      serversObj[k] = { ...v };
    }

    return {
      range,
      timeline: buckets.map((b) => ({
        timestamp: b.timestamp,
        timeLabel: b.timeLabel,
        total: b.total,
        success: b.success,
        error: b.error,
        denied: b.denied,
        avgLatencyMs: b.avgLatencyMs,
        p95LatencyMs: b.p95LatencyMs,
        maxLatencyMs: b.maxLatencyMs,
      })),
      histogram,
      servers: serversObj,
      recentErrors: this.recentErrors.slice(0, 15),
      activeInFlight: this.activeInFlight,
      summary: {
        total: totalRuns,
        success: successRuns,
        error: errorRuns,
        denied: deniedRuns,
        successRate: totalRuns > 0 ? Math.round((successRuns / totalRuns) * 1000) / 10 : 100,
        avgLatencyMs: avgLatency,
        p95LatencyMs: p95Latency,
        budgetComplianceRate,
      },
    };
  }

  private calculateHistogram(records: ExecutionRecord[]): {
    buckets: HistogramBucket[];
    p50: number;
    p90: number;
    p95: number;
    p99: number;
    max: number;
  } {
    const thresholds = [
      { label: "<10ms", min: 0, max: 10 },
      { label: "10-25ms", min: 10, max: 25 },
      { label: "25-50ms", min: 25, max: 50 },
      { label: "50-100ms", min: 50, max: 100 },
      { label: "100-250ms", min: 100, max: 250 },
      { label: "250-500ms", min: 250, max: 500 },
      { label: "500ms-1s", min: 500, max: 1000 },
      { label: "1s-2s", min: 1000, max: 2000 },
      { label: "2s-5s", min: 2000, max: 5000 },
      { label: ">5s", min: 5000, max: Infinity },
    ];

    const counts = new Array(thresholds.length).fill(0);
    const latencies: number[] = [];

    for (const r of records) {
      const dur = r.durationMs;
      latencies.push(dur);
      for (let i = 0; i < thresholds.length; i++) {
        if (dur >= thresholds[i].min && dur < thresholds[i].max) {
          counts[i]++;
          break;
        }
      }
    }

    const total = latencies.length;
    const buckets: HistogramBucket[] = thresholds.map((t, i) => ({
      label: t.label,
      min: t.min,
      max: t.max,
      count: counts[i],
      percentage: total > 0 ? Math.round((counts[i] / total) * 1000) / 10 : 0,
    }));

    latencies.sort((a, b) => a - b);
    const p50 = total > 0 ? latencies[Math.floor(total * 0.5)] : 0;
    const p90 = total > 0 ? latencies[Math.floor(total * 0.9)] : 0;
    const p95 = total > 0 ? latencies[Math.floor(total * 0.95)] : 0;
    const p99 = total > 0 ? latencies[Math.floor(total * 0.99)] : 0;
    const max = total > 0 ? latencies[latencies.length - 1] : 0;

    return { buckets, p50, p90, p95, p99, max };
  }
}

export const telemetryManager = new TelemetryManager();

