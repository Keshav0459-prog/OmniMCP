import { serverRegistry } from "./registry.js";
import { clientManager } from "./client-manager.js";
import { discoveryEngine } from "./discovery.js";
import { dbManager } from "./db.js";
import { createChildLogger } from "./logger.js";

const log = createChildLogger("health-monitor");

export interface ServerHealthReport {
  id: string;
  name: string;
  status: string;
  latencyMs?: number;
  toolCount: number;
  uptimeSeconds: number;
  lastCheckedAt: string;
  consecutiveFailures: number;
}

export class HealthMonitor {
  private intervalId: NodeJS.Timeout | null = null;
  private consecutiveFailures: Map<string, number> = new Map();
  private checkIntervalMs = 30000;

  public start(intervalMs = 30000): void {
    this.checkIntervalMs = intervalMs;
    if (this.intervalId) return;

    log.info({ intervalMs }, "Starting background health check monitor");
    this.intervalId = setInterval(() => {
      this.checkAllServers().catch((err) => {
        log.error({ error: err }, "Error running health checks");
      });
    }, this.checkIntervalMs);
  }

  public stop(): void {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
      log.info("Stopped background health check monitor");
    }
  }

  public async checkServer(serverId: string): Promise<ServerHealthReport> {
    const s = serverRegistry.getServer(serverId);
    if (!s) {
      throw new Error(`Server '${serverId}' not found`);
    }

    const startTime = Date.now();
    let currentStatus = s.status;
    let latencyMs = s.latencyMs || 0;
    const client = clientManager.getClient(serverId);

    if (s.enabled && client) {
      try {
        if (s.transport === "stdio") {
          // For stdio child processes, liveness is continuously tracked by the transport.onclose lifecycle event.
          // Directly verify client is active and transport is connected (avoids hanging on servers that do not implement optional 'ping' method).
          if (!clientManager.isConnected(serverId)) {
            throw new Error(`Child MCP server '${serverId}' transport is closed`);
          }
          currentStatus = "connected";
          this.consecutiveFailures.set(serverId, 0);
          serverRegistry.updateStatus(serverId, "connected", undefined, s.toolCount, s.latencyMs || 5);
          dbManager.recordMetric(serverId, "connected", s.latencyMs || 5);
        } else {
          // For remote HTTP/SSE endpoints, verify network RPC responsiveness
          const healthTimeoutMs = Number(process.env.MCP_HEALTH_TIMEOUT_MS) || 15000;
          const pingPromise = typeof client.ping === "function" ? client.ping() : client.listTools();
          const timeoutPromise = new Promise<never>((_, reject) =>
            setTimeout(() => reject(new Error(`Health check timeout (${healthTimeoutMs}ms)`)), healthTimeoutMs)
          );

          const res = (await Promise.race([pingPromise, timeoutPromise])) as any;
          latencyMs = Date.now() - startTime;
          currentStatus = "connected";
          this.consecutiveFailures.set(serverId, 0);

          const toolCount = res?.tools ? res.tools.length : s.toolCount;
          serverRegistry.updateStatus(serverId, "connected", undefined, toolCount, latencyMs);
          dbManager.recordMetric(serverId, "connected", latencyMs);
        }
      } catch (err: any) {
        latencyMs = Date.now() - startTime;
        currentStatus = "error";
        const failures = (this.consecutiveFailures.get(serverId) || 0) + 1;
        this.consecutiveFailures.set(serverId, failures);

        serverRegistry.updateStatus(serverId, "error", err.message, undefined, latencyMs);
        dbManager.recordMetric(serverId, "error", latencyMs);

        log.warn({ serverId, failures, error: err.message }, "Server health check failed");

        // Attempt automatic reconnect if autoConnect is enabled
        if (s.autoConnect && failures <= 5) {
          log.info({ serverId, attempt: failures }, "Attempting auto-reconnect for downstream server");
          try {
            await clientManager.disconnectServer(serverId);
            await clientManager.connectServer(s);
            await discoveryEngine.discoverServerTools(serverId);
          } catch (reconnectErr) {
            log.error({ serverId, error: reconnectErr }, "Auto-reconnect attempt failed");
          }
        }
      }
    }

    return {
      id: s.id,
      name: s.name,
      status: currentStatus,
      latencyMs,
      toolCount: s.toolCount,
      uptimeSeconds: s.lastConnectedAt ? Math.floor((Date.now() - new Date(s.lastConnectedAt).getTime()) / 1000) : 0,
      lastCheckedAt: new Date().toISOString(),
      consecutiveFailures: this.consecutiveFailures.get(serverId) || 0,
    };
  }

  public async checkAllServers(): Promise<ServerHealthReport[]> {
    const servers = serverRegistry.getAllServers().filter((s) => s.enabled);
    const reports: ServerHealthReport[] = [];

    for (const s of servers) {
      if (s.status === "connected") {
        const report = await this.checkServer(s.id);
        reports.push(report);
      }
    }

    return reports;
  }
}

export const healthMonitor = new HealthMonitor();

