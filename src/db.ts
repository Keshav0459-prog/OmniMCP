import { DatabaseSync } from "node:sqlite";
import path from "node:path";
import fs from "node:fs";
import crypto from "node:crypto";
import { 
  ServerConfig, 
  ExecutionRecord, 
  ApprovalAuditEvent, 
  ApprovalEventType,
  ProfileWithDetails,
  Project,
  Task,
  TaskStatus,
  TaskPriority,
  type AgentTokenRecord,
} from "./types.js";
import { sanitizeData } from "./security.js";
import { createChildLogger } from "./logger.js";

const log = createChildLogger("database");

export class DatabaseManager {
  private db: DatabaseSync | null = null;
  private isMemory = false;

  constructor(dbPath?: string) {
    this.initDatabase(dbPath);
  }

  private initDatabase(dbPath?: string) {
    try {
      const targetPath = dbPath || process.env.OMNIMCP_DB_PATH || process.env.SQLITE_DB_PATH || "./data/omnimcp.db";
      const resolvedPath = path.resolve(targetPath);
      const dir = path.dirname(resolvedPath);

      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }

      this.db = new DatabaseSync(resolvedPath);
      this.db.exec("PRAGMA journal_mode = WAL;");
      this.db.exec("PRAGMA busy_timeout = 5000;");
      log.info({ path: resolvedPath }, "SQLite database initialized successfully");
    } catch (err) {
      log.warn({ error: err }, "Failed to initialize SQLite on disk. Falling back to in-memory database.");
      this.db = new DatabaseSync(":memory:");
      this.isMemory = true;
    }

    this.migrate();
  }

  private migrate() {
    if (!this.db) return;

    // 1. Servers Table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS servers (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT NOT NULL,
        category TEXT NOT NULL,
        transport TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        auto_connect INTEGER NOT NULL DEFAULT 0,
        command TEXT,
        args_json TEXT,
        env_json TEXT,
        url TEXT,
        headers_json TEXT,
        allowed_permissions_json TEXT,
        requires_approval INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
    `);

    // 2. Audit & Execution Logs Table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id TEXT PRIMARY KEY,
        trace_id TEXT NOT NULL,
        tool_id TEXT NOT NULL,
        server_id TEXT NOT NULL,
        original_tool_name TEXT NOT NULL,
        input_parameters_json TEXT NOT NULL,
        output_result_json TEXT,
        status TEXT NOT NULL,
        duration_ms INTEGER NOT NULL,
        error TEXT,
        timestamp TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
      CREATE INDEX IF NOT EXISTS idx_audit_logs_server_id ON audit_logs(server_id);
      CREATE INDEX IF NOT EXISTS idx_audit_logs_status ON audit_logs(status);
      CREATE INDEX IF NOT EXISTS idx_audit_logs_trace_id ON audit_logs(trace_id);
    `);

    // 3. Health & Latency Metrics Table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS server_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        server_id TEXT NOT NULL,
        status TEXT NOT NULL,
        latency_ms INTEGER NOT NULL,
        timestamp TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_metrics_server_timestamp ON server_metrics(server_id, timestamp);
    `);

    // 4. Permission Overrides Table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS permission_policies (
        id TEXT PRIMARY KEY,
        server_id TEXT NOT NULL,
        tool_id TEXT,
        permission_level TEXT NOT NULL,
        requires_approval INTEGER NOT NULL,
        rate_limit_per_minute INTEGER,
        updated_at TEXT NOT NULL
      );
    `);

    // 5. Approval Audit Logs Table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS approval_audit_logs (
        id TEXT PRIMARY KEY,
        request_id TEXT NOT NULL,
        event_type TEXT NOT NULL,
        tool_id TEXT NOT NULL,
        server_id TEXT NOT NULL,
        params_hash TEXT NOT NULL,
        operator_identity TEXT,
        trace_id TEXT,
        timestamp TEXT NOT NULL,
        status TEXT NOT NULL,
        details_json TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_approval_audit_request_id ON approval_audit_logs(request_id);
      CREATE INDEX IF NOT EXISTS idx_approval_audit_timestamp ON approval_audit_logs(timestamp);
    `);

    // 6. Profiles & Profile Policies Tables
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS profiles (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        description TEXT NOT NULL,
        is_default INTEGER NOT NULL DEFAULT 0,
        is_active INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS profile_integrations (
        id TEXT PRIMARY KEY,
        profile_id TEXT NOT NULL,
        server_id TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        UNIQUE(profile_id, server_id),
        FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS idx_profile_integrations_profile ON profile_integrations(profile_id);

      CREATE TABLE IF NOT EXISTS profile_tool_policies (
        id TEXT PRIMARY KEY,
        profile_id TEXT NOT NULL,
        tool_id TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        requires_approval INTEGER,
        created_at TEXT NOT NULL,
        UNIQUE(profile_id, tool_id),
        FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS idx_profile_tools_profile ON profile_tool_policies(profile_id);
    `);

    // 7. Projects & Tasks (Kanban) Tables
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS projects (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        color TEXT DEFAULT '#7c3aed',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS tasks (
        id TEXT PRIMARY KEY,
        project_id TEXT,
        title TEXT NOT NULL,
        description TEXT,
        status TEXT NOT NULL DEFAULT 'TODO',
        priority TEXT NOT NULL DEFAULT 'MEDIUM',
        assignee TEXT,
        due_date TEXT,
        profile_id TEXT,
        integration_id TEXT,
        labels_json TEXT DEFAULT '[]',
        checklist_json TEXT DEFAULT '[]',
        position INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
      CREATE INDEX IF NOT EXISTS idx_tasks_project ON tasks(project_id);
      CREATE INDEX IF NOT EXISTS idx_tasks_profile ON tasks(profile_id);
    `);

    // 8. Persistent Agent Tokens Table (Milestone M9.2)
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS agent_tokens (
        id TEXT PRIMARY KEY,
        token_hash TEXT NOT NULL UNIQUE,
        token_prefix TEXT NOT NULL,
        principal_id TEXT NOT NULL,
        assigned_profile_id TEXT NOT NULL,
        name TEXT NOT NULL,
        is_revoked INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL,
        expires_at INTEGER,
        last_used_at INTEGER,
        revoked_at INTEGER,
        FOREIGN KEY (assigned_profile_id) REFERENCES profiles(id)
      );
      CREATE INDEX IF NOT EXISTS idx_agent_tokens_hash ON agent_tokens(token_hash);
      CREATE INDEX IF NOT EXISTS idx_agent_tokens_principal ON agent_tokens(principal_id);
      CREATE INDEX IF NOT EXISTS idx_agent_tokens_profile ON agent_tokens(assigned_profile_id);
    `);

    this.seedDefaultProfiles();
  }

  private seedDefaultProfiles() {
    if (!this.db) return;
    try {
      const now = new Date().toISOString();
      const defaultProfiles = [
        {
          id: "admin",
          name: "Admin",
          description: "Full administrative access with fleet server, profile, and token management",
          isDefault: 0,
          isActive: 0,
          integrations: ["filesystem", "github", "playwright", "context7", "shadcn", "stitch", "supabase", "sentry"],
        },
        {
          id: "developer",
          name: "Developer",
          description: "Full-stack development suite with Filesystem, GitHub, Playwright, Context7, shadcn/ui, and Google Stitch",
          isDefault: 1,
          isActive: 1,
          integrations: ["filesystem", "github", "playwright", "context7", "shadcn", "stitch"],
        },
        {
          id: "backend",
          name: "Backend Engineer",
          description: "Backend infrastructure suite with Supabase, GitHub, Context7, and Sentry",
          isDefault: 0,
          isActive: 0,
          integrations: ["supabase", "github", "context7", "sentry"],
        },
        {
          id: "qa",
          name: "QA Engineer",
          description: "Automated browser testing and regression suite with Playwright, GitHub, and Filesystem",
          isDefault: 0,
          isActive: 0,
          integrations: ["playwright", "github", "filesystem"],
        },
        {
          id: "automation",
          name: "Automation",
          description: "Automated workflow and browser execution suite with Playwright, GitHub, and Filesystem",
          isDefault: 0,
          isActive: 0,
          integrations: ["playwright", "github", "filesystem"],
        },
        {
          id: "readonly",
          name: "Read Only",
          description: "Restricted read-only inspection tools across all connected MCP servers",
          isDefault: 0,
          isActive: 0,
          integrations: ["filesystem", "github", "context7", "sentry"],
        },
      ];

      const checkProfile = this.db.prepare(`SELECT id FROM profiles WHERE id = ?`);
      const insertProfile = this.db.prepare(`
        INSERT INTO profiles (id, name, description, is_default, is_active, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `);
      const checkIntegration = this.db.prepare(`
        SELECT COUNT(*) as count FROM profile_integrations WHERE profile_id = ? AND server_id = ?
      `);
      const insertIntegration = this.db.prepare(`
        INSERT INTO profile_integrations (id, profile_id, server_id, enabled, created_at)
        VALUES (?, ?, ?, 1, ?)
      `);

      for (const p of defaultProfiles) {
        const existing = checkProfile.get(p.id);
        if (!existing) {
          insertProfile.run(p.id, p.name, p.description, p.isDefault, p.isActive, now, now);
        }
        for (const s of p.integrations) {
          const row = checkIntegration.get(p.id, s) as { count: number } | undefined;
          if (!row || row.count === 0) {
            insertIntegration.run(crypto.randomUUID(), p.id, s, now);
          }
        }
      }
      log.info("Default MCP operating profiles seeded and verified successfully");
    } catch (err) {
      log.warn({ error: err }, "Failed to seed default profiles");
    }
  }

  // --- Server Methods ---
  public upsertServer(server: ServerConfig): void {
    if (!this.db) return;
    const stmt = this.db.prepare(`
      INSERT INTO servers (
        id, name, description, category, transport, enabled, auto_connect,
        command, args_json, env_json, url, headers_json, allowed_permissions_json,
        requires_approval, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        name = excluded.name,
        description = excluded.description,
        category = excluded.category,
        transport = excluded.transport,
        enabled = excluded.enabled,
        auto_connect = excluded.auto_connect,
        command = excluded.command,
        args_json = excluded.args_json,
        env_json = excluded.env_json,
        url = excluded.url,
        headers_json = excluded.headers_json,
        allowed_permissions_json = excluded.allowed_permissions_json,
        requires_approval = excluded.requires_approval,
        updated_at = excluded.updated_at
    `);

    const now = new Date().toISOString();
    stmt.run(
      server.id,
      server.name,
      server.description,
      server.category,
      server.transport,
      server.enabled ? 1 : 0,
      server.autoConnect ? 1 : 0,
      server.command || null,
      server.args ? JSON.stringify(server.args) : null,
      server.env ? JSON.stringify(server.env) : null,
      server.url || null,
      server.headers ? JSON.stringify(server.headers) : null,
      server.allowedPermissions ? JSON.stringify(server.allowedPermissions) : null,
      server.requiresApprovalForDestructive !== false ? 1 : 0,
      now,
      now
    );
  }

  public getPersistedServers(): ServerConfig[] {
    if (!this.db) return [];
    const stmt = this.db.prepare(`SELECT * FROM servers`);
    const rows = stmt.all() as any[];

    return rows.map((r) => ({
      id: r.id,
      name: r.name,
      description: r.description,
      category: r.category,
      transport: r.transport,
      enabled: Boolean(r.enabled),
      autoConnect: Boolean(r.auto_connect),
      command: r.command || undefined,
      args: r.args_json ? JSON.parse(r.args_json) : undefined,
      env: r.env_json ? JSON.parse(r.env_json) : undefined,
      url: r.url || undefined,
      headers: r.headers_json ? JSON.parse(r.headers_json) : undefined,
      allowedPermissions: r.allowed_permissions_json ? JSON.parse(r.allowed_permissions_json) : undefined,
      requiresApprovalForDestructive: Boolean(r.requires_approval),
    }));
  }

  public deleteServer(id: string): void {
    if (!this.db) return;
    const stmt = this.db.prepare(`DELETE FROM servers WHERE id = ?`);
    stmt.run(id);
  }

  // --- Audit Log Methods ---
  public insertAuditLog(record: ExecutionRecord): void {
    if (!this.db) return;
    try {
      const stmt = this.db.prepare(`
        INSERT INTO audit_logs (
          id, trace_id, tool_id, server_id, original_tool_name,
          input_parameters_json, output_result_json, status, duration_ms, error, timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      const sanitizedParams = sanitizeData(record.inputParameters);
      const sanitizedOutput = record.outputResult !== undefined ? sanitizeData(record.outputResult) : null;
      const sanitizedError = record.error ? (sanitizeData(record.error) as string) : null;

      stmt.run(
        record.id,
        record.traceId,
        record.toolId,
        record.serverId,
        record.originalToolName,
        JSON.stringify(sanitizedParams),
        sanitizedOutput ? JSON.stringify(sanitizedOutput) : null,
        record.status,
        record.durationMs,
        sanitizedError,
        record.timestamp
      );
    } catch (err) {
      log.error({ error: err }, "Failed to write audit log to database");
    }
  }

  public countAuditLogs(serverId?: string, status?: string, traceId?: string): number {
    if (!this.db) return 0;
    let query = `SELECT COUNT(*) as total FROM audit_logs`;
    const params: any[] = [];
    const conditions: string[] = [];

    if (serverId) {
      conditions.push(`server_id = ?`);
      params.push(serverId);
    }

    if (status) {
      conditions.push(`status = ?`);
      params.push(status);
    }

    if (traceId) {
      conditions.push(`trace_id = ?`);
      params.push(traceId);
    }

    if (conditions.length > 0) {
      query += ` WHERE ${conditions.join(" AND ")}`;
    }

    const stmt = this.db.prepare(query);
    const row = stmt.get(...params) as any;
    return Number(row?.total ?? 0);
  }

  public queryAuditLogs(limit = 50, serverId?: string, status?: string, traceId?: string, offset = 0): ExecutionRecord[] {
    if (!this.db) return [];
    let query = `SELECT * FROM audit_logs`;
    const params: any[] = [];
    const conditions: string[] = [];

    if (serverId) {
      conditions.push(`server_id = ?`);
      params.push(serverId);
    }

    if (status) {
      conditions.push(`status = ?`);
      params.push(status);
    }

    if (traceId) {
      conditions.push(`trace_id = ?`);
      params.push(traceId);
    }

    if (conditions.length > 0) {
      query += ` WHERE ${conditions.join(" AND ")}`;
    }

    query += ` ORDER BY timestamp DESC, rowid DESC LIMIT ? OFFSET ?`;
    params.push(Math.min(limit, 100), Math.max(0, offset));

    const stmt = this.db.prepare(query);
    const rows = stmt.all(...params) as any[];

    return rows.map((r) => ({
      id: r.id,
      traceId: r.trace_id,
      toolId: r.tool_id,
      serverId: r.server_id,
      originalToolName: r.original_tool_name,
      inputParameters: JSON.parse(r.input_parameters_json || "{}"),
      outputResult: r.output_result_json ? JSON.parse(r.output_result_json) : undefined,
      status: r.status,
      durationMs: r.duration_ms,
      error: r.error || undefined,
      timestamp: r.timestamp,
    }));
  }

  public getAuditLogByTraceId(traceId: string): ExecutionRecord | undefined {
    if (!this.db) return undefined;
    const stmt = this.db.prepare(`SELECT * FROM audit_logs WHERE trace_id = ? LIMIT 1`);
    const row = stmt.get(traceId) as any;
    if (!row) return undefined;

    return {
      id: row.id,
      traceId: row.trace_id,
      toolId: row.tool_id,
      serverId: row.server_id,
      originalToolName: row.original_tool_name,
      inputParameters: JSON.parse(row.input_parameters_json || "{}"),
      outputResult: row.output_result_json ? JSON.parse(row.output_result_json) : undefined,
      status: row.status,
      durationMs: row.duration_ms,
      error: row.error || undefined,
      timestamp: row.timestamp,
    };
  }

  public getExecutionStats(): {
    totalExecutions: number;
    successfulExecutions: number;
    failedExecutions: number;
    deniedExecutions: number;
    successRate: number;
    avgLatencyMs: number;
  } {
    if (!this.db) {
      return {
        totalExecutions: 0,
        successfulExecutions: 0,
        failedExecutions: 0,
        deniedExecutions: 0,
        successRate: 0,
        avgLatencyMs: 0,
      };
    }

    const stmt = this.db.prepare(`
      SELECT
        COUNT(*) as total,
        COALESCE(SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END), 0) as successes,
        COALESCE(SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END), 0) as errors,
        COALESCE(SUM(CASE WHEN status = 'denied' THEN 1 ELSE 0 END), 0) as denied,
        COALESCE(AVG(duration_ms), 0) as avg_latency
      FROM audit_logs
    `);
    const row = stmt.get() as any;
    const total = Number(row?.total ?? 0);
    const successes = Number(row?.successes ?? 0);
    const errors = Number(row?.errors ?? 0);
    const denied = Number(row?.denied ?? 0);
    const avgLatencyMs = Math.round(Number(row?.avg_latency ?? 0));
    const successRate = total > 0 ? Number(((successes / total) * 100).toFixed(1)) : 0;

    return {
      totalExecutions: total,
      successfulExecutions: successes,
      failedExecutions: errors,
      deniedExecutions: denied,
      successRate,
      avgLatencyMs,
    };
  }

  // --- Metrics Methods ---
  public recordMetric(serverId: string, status: string, latencyMs: number): void {
    if (!this.db) return;
    try {
      const stmt = this.db.prepare(`
        INSERT INTO server_metrics (server_id, status, latency_ms, timestamp)
        VALUES (?, ?, ?, ?)
      `);
      stmt.run(serverId, status, latencyMs, new Date().toISOString());
    } catch (err) {
      log.error({ error: err }, "Failed to record server metric");
    }
  }

  public getRecentMetrics(serverId: string, limit = 30): { timestamp: string; latencyMs: number; status: string }[] {
    if (!this.db) return [];
    const stmt = this.db.prepare(`
      SELECT timestamp, latency_ms, status FROM server_metrics
      WHERE server_id = ?
      ORDER BY timestamp DESC
      LIMIT ?
    `);
    const rows = stmt.all(serverId, limit) as any[];
    return rows.reverse().map((r) => ({
      timestamp: r.timestamp,
      latencyMs: r.latency_ms,
      status: r.status,
    }));
  }

  // --- Approval Audit Logs Methods ---
  public insertApprovalAudit(event: ApprovalAuditEvent): void {
    if (!this.db) return;
    try {
      const stmt = this.db.prepare(`
        INSERT INTO approval_audit_logs (
          id, request_id, event_type, tool_id, server_id,
          params_hash, operator_identity, trace_id, timestamp, status, details_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      stmt.run(
        event.id,
        event.requestId,
        event.eventType,
        event.toolId,
        event.serverId,
        event.paramsHash,
        event.operatorIdentity || null,
        event.traceId || null,
        event.timestamp,
        event.status,
        event.details ? JSON.stringify(event.details) : null
      );
    } catch (err) {
      log.error({ error: err }, "Failed to write approval audit log to database");
    }
  }

  public queryApprovalAudits(requestId?: string, limit = 50): ApprovalAuditEvent[] {
    if (!this.db) return [];
    let query = `SELECT * FROM approval_audit_logs`;
    const params: any[] = [];

    if (requestId) {
      query += ` WHERE request_id = ?`;
      params.push(requestId);
    }

    query += ` ORDER BY timestamp DESC, rowid DESC LIMIT ?`;
    params.push(Math.min(limit, 100));

    const stmt = this.db.prepare(query);
    const rows = stmt.all(...params) as any[];

    return rows.map((r) => ({
      id: r.id,
      requestId: r.request_id,
      eventType: r.event_type as ApprovalEventType,
      toolId: r.tool_id,
      serverId: r.server_id,
      paramsHash: r.params_hash,
      operatorIdentity: r.operator_identity || undefined,
      traceId: r.trace_id || undefined,
      timestamp: r.timestamp,
      status: r.status,
      details: r.details_json ? JSON.parse(r.details_json) : undefined,
    }));
  }

  // --- Profiles Methods ---

  public listProfiles(): ProfileWithDetails[] {
    if (!this.db) return [];
    try {
      const rows = this.db.prepare(`SELECT * FROM profiles ORDER BY is_default DESC, name ASC`).all() as any[];
      return rows.map((r) => this.hydrateProfile(r));
    } catch (err) {
      log.error({ error: err }, "Failed to list profiles");
      return [];
    }
  }

  public getProfile(id: string): ProfileWithDetails | null {
    if (!this.db) return null;
    try {
      const row = this.db.prepare(`SELECT * FROM profiles WHERE id = ?`).get(id) as any;
      if (!row) return null;
      return this.hydrateProfile(row);
    } catch (err) {
      log.error({ error: err }, `Failed to get profile ${id}`);
      return null;
    }
  }

  public getActiveProfile(): ProfileWithDetails | null {
    if (!this.db) return null;
    try {
      const row = this.db.prepare(`SELECT * FROM profiles WHERE is_active = 1 LIMIT 1`).get() as any;
      if (row) return this.hydrateProfile(row);
      // Fallback to default
      const defaultRow = this.db.prepare(`SELECT * FROM profiles WHERE is_default = 1 LIMIT 1`).get() as any;
      if (defaultRow) return this.hydrateProfile(defaultRow);
      return null;
    } catch (err) {
      log.error({ error: err }, "Failed to get active profile");
      return null;
    }
  }

  public setActiveProfile(id: string): ProfileWithDetails | null {
    if (!this.db) return null;
    try {
      const profile = this.getProfile(id);
      if (!profile) return null;

      this.db.exec("BEGIN TRANSACTION;");
      this.db.prepare(`UPDATE profiles SET is_active = 0`).run();
      this.db.prepare(`UPDATE profiles SET is_active = 1, updated_at = ? WHERE id = ?`).run(new Date().toISOString(), id);
      this.db.exec("COMMIT;");

      return this.getProfile(id);
    } catch (err) {
      try { this.db?.exec("ROLLBACK;"); } catch {}
      log.error({ error: err }, `Failed to set active profile ${id}`);
      return null;
    }
  }

  public upsertProfile(input: {
    id: string;
    name: string;
    description: string;
    isDefault?: boolean;
    isActive?: boolean;
    integrations?: string[];
    toolPolicies?: Record<string, { enabled: boolean; requiresApproval?: boolean }>;
  }): ProfileWithDetails {
    if (!this.db) throw new Error("Database not initialized");
    const now = new Date().toISOString();

    this.db.exec("BEGIN TRANSACTION;");
    try {
      if (input.isDefault) {
        this.db.prepare(`UPDATE profiles SET is_default = 0`).run();
      }
      if (input.isActive) {
        this.db.prepare(`UPDATE profiles SET is_active = 0`).run();
      }

      this.db.prepare(`
        INSERT INTO profiles (id, name, description, is_default, is_active, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          name = excluded.name,
          description = excluded.description,
          is_default = excluded.is_default,
          is_active = excluded.is_active,
          updated_at = excluded.updated_at
      `).run(
        input.id,
        input.name,
        input.description,
        input.isDefault ? 1 : 0,
        input.isActive ? 1 : 0,
        now,
        now
      );

      if (input.integrations !== undefined) {
        this.db.prepare(`DELETE FROM profile_integrations WHERE profile_id = ?`).run(input.id);
        const insertIntegration = this.db.prepare(`
          INSERT INTO profile_integrations (id, profile_id, server_id, enabled, created_at)
          VALUES (?, ?, ?, 1, ?)
        `);
        for (const s of input.integrations) {
          insertIntegration.run(crypto.randomUUID(), input.id, s, now);
        }
      }

      if (input.toolPolicies !== undefined) {
        this.db.prepare(`DELETE FROM profile_tool_policies WHERE profile_id = ?`).run(input.id);
        const insertPolicy = this.db.prepare(`
          INSERT INTO profile_tool_policies (id, profile_id, tool_id, enabled, requires_approval, created_at)
          VALUES (?, ?, ?, ?, ?, ?)
        `);
        for (const [toolId, policy] of Object.entries(input.toolPolicies)) {
          insertPolicy.run(
            crypto.randomUUID(),
            input.id,
            toolId,
            policy.enabled ? 1 : 0,
            policy.requiresApproval !== undefined ? (policy.requiresApproval ? 1 : 0) : null,
            now
          );
        }
      }

      this.db.exec("COMMIT;");
      return this.getProfile(input.id)!;
    } catch (err) {
      try { this.db.exec("ROLLBACK;"); } catch {}
      throw err;
    }
  }

  public deleteProfile(id: string): boolean {
    if (!this.db) return false;
    try {
      const profile = this.getProfile(id);
      if (!profile || profile.isDefault) return false; // Default profile cannot be deleted

      this.db.exec("BEGIN TRANSACTION;");
      this.db.prepare(`DELETE FROM profile_integrations WHERE profile_id = ?`).run(id);
      this.db.prepare(`DELETE FROM profile_tool_policies WHERE profile_id = ?`).run(id);
      this.db.prepare(`UPDATE tasks SET profile_id = NULL WHERE profile_id = ?`).run(id);
      this.db.prepare(`DELETE FROM profiles WHERE id = ?`).run(id);
      this.db.exec("COMMIT;");
      return true;
    } catch (err) {
      try { this.db?.exec("ROLLBACK;"); } catch {}
      log.error({ error: err }, `Failed to delete profile ${id}`);
      return false;
    }
  }

  private hydrateProfile(row: any): ProfileWithDetails {
    if (!this.db) throw new Error("Database not initialized");
    const intRows = this.db.prepare(`
      SELECT server_id FROM profile_integrations WHERE profile_id = ? AND enabled = 1
    `).all(row.id) as { server_id: string }[];

    const polRows = this.db.prepare(`
      SELECT tool_id, enabled, requires_approval FROM profile_tool_policies WHERE profile_id = ?
    `).all(row.id) as { tool_id: string; enabled: number; requires_approval: number | null }[];

    const toolPolicies: Record<string, { enabled: boolean; requiresApproval?: boolean }> = {};
    for (const p of polRows) {
      toolPolicies[p.tool_id] = {
        enabled: Boolean(p.enabled),
        requiresApproval: p.requires_approval !== null ? Boolean(p.requires_approval) : undefined,
      };
    }

    return {
      id: row.id,
      name: row.name,
      description: row.description,
      isDefault: Boolean(row.is_default),
      isActive: Boolean(row.is_active),
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      integrations: intRows.map((i) => i.server_id),
      toolPolicies,
    };
  }

  // --- Projects & Tasks (Kanban) Methods ---

  public listProjects(): Project[] {
    if (!this.db) return [];
    try {
      const rows = this.db.prepare(`SELECT * FROM projects ORDER BY name ASC`).all() as any[];
      return rows.map((r) => ({
        id: r.id,
        name: r.name,
        description: r.description || undefined,
        color: r.color || "#7c3aed",
        createdAt: r.created_at,
        updatedAt: r.updated_at,
      }));
    } catch (err) {
      log.error({ error: err }, "Failed to list projects");
      return [];
    }
  }

  public getProject(id: string): Project | null {
    if (!this.db) return null;
    try {
      const r = this.db.prepare(`SELECT * FROM projects WHERE id = ?`).get(id) as any;
      if (!r) return null;
      return {
        id: r.id,
        name: r.name,
        description: r.description || undefined,
        color: r.color || "#7c3aed",
        createdAt: r.created_at,
        updatedAt: r.updated_at,
      };
    } catch (err) {
      log.error({ error: err }, `Failed to get project ${id}`);
      return null;
    }
  }

  public upsertProject(input: { id: string; name: string; description?: string; color?: string }): Project {
    if (!this.db) throw new Error("Database not initialized");
    const now = new Date().toISOString();
    this.db.prepare(`
      INSERT INTO projects (id, name, description, color, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        name = excluded.name,
        description = excluded.description,
        color = excluded.color,
        updated_at = excluded.updated_at
    `).run(input.id, input.name, input.description || null, input.color || "#7c3aed", now, now);

    return this.getProject(input.id)!;
  }

  public deleteProject(id: string): boolean {
    if (!this.db) return false;
    try {
      this.db.prepare(`UPDATE tasks SET project_id = NULL WHERE project_id = ?`).run(id);
      this.db.prepare(`DELETE FROM projects WHERE id = ?`).run(id);
      return true;
    } catch (err) {
      log.error({ error: err }, `Failed to delete project ${id}`);
      return false;
    }
  }

  public listTasks(filter?: {
    projectId?: string;
    status?: TaskStatus;
    profileId?: string;
    integrationId?: string;
  }): Task[] {
    if (!this.db) return [];
    try {
      let query = `SELECT * FROM tasks WHERE 1=1`;
      const params: any[] = [];

      if (filter?.projectId) {
        query += ` AND project_id = ?`;
        params.push(filter.projectId);
      }
      if (filter?.status) {
        query += ` AND status = ?`;
        params.push(filter.status);
      }
      if (filter?.profileId) {
        query += ` AND profile_id = ?`;
        params.push(filter.profileId);
      }
      if (filter?.integrationId) {
        query += ` AND integration_id = ?`;
        params.push(filter.integrationId);
      }

      query += ` ORDER BY position ASC, created_at DESC`;
      const rows = this.db.prepare(query).all(...params) as any[];

      return rows.map((r) => ({
        id: r.id,
        projectId: r.project_id || undefined,
        title: r.title,
        description: r.description || undefined,
        status: r.status as TaskStatus,
        priority: r.priority as TaskPriority,
        assignee: r.assignee || undefined,
        dueDate: r.due_date || undefined,
        profileId: r.profile_id || undefined,
        integrationId: r.integration_id || undefined,
        labels: r.labels_json ? JSON.parse(r.labels_json) : [],
        checklist: r.checklist_json ? JSON.parse(r.checklist_json) : [],
        position: r.position || 0,
        createdAt: r.created_at,
        updatedAt: r.updated_at,
      }));
    } catch (err) {
      log.error({ error: err }, "Failed to list tasks");
      return [];
    }
  }

  public getTask(id: string): Task | null {
    if (!this.db) return null;
    try {
      const r = this.db.prepare(`SELECT * FROM tasks WHERE id = ?`).get(id) as any;
      if (!r) return null;
      return {
        id: r.id,
        projectId: r.project_id || undefined,
        title: r.title,
        description: r.description || undefined,
        status: r.status as TaskStatus,
        priority: r.priority as TaskPriority,
        assignee: r.assignee || undefined,
        dueDate: r.due_date || undefined,
        profileId: r.profile_id || undefined,
        integrationId: r.integration_id || undefined,
        labels: r.labels_json ? JSON.parse(r.labels_json) : [],
        checklist: r.checklist_json ? JSON.parse(r.checklist_json) : [],
        position: r.position || 0,
        createdAt: r.created_at,
        updatedAt: r.updated_at,
      };
    } catch (err) {
      log.error({ error: err }, `Failed to get task ${id}`);
      return null;
    }
  }

  public upsertTask(input: {
    id: string;
    projectId?: string;
    title: string;
    description?: string;
    status?: TaskStatus;
    priority?: TaskPriority;
    assignee?: string;
    dueDate?: string;
    profileId?: string;
    integrationId?: string;
    labels?: string[];
    checklist?: any[];
    position?: number;
  }): Task {
    if (!this.db) throw new Error("Database not initialized");
    const now = new Date().toISOString();
    const status = input.status || "TODO";
    const priority = input.priority || "MEDIUM";
    const labelsJson = JSON.stringify(input.labels || []);
    const checklistJson = JSON.stringify(input.checklist || []);

    this.db.prepare(`
      INSERT INTO tasks (
        id, project_id, title, description, status, priority, assignee,
        due_date, profile_id, integration_id, labels_json, checklist_json, position,
        created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        project_id = excluded.project_id,
        title = excluded.title,
        description = excluded.description,
        status = excluded.status,
        priority = excluded.priority,
        assignee = excluded.assignee,
        due_date = excluded.due_date,
        profile_id = excluded.profile_id,
        integration_id = excluded.integration_id,
        labels_json = excluded.labels_json,
        checklist_json = excluded.checklist_json,
        position = excluded.position,
        updated_at = excluded.updated_at
    `).run(
      input.id,
      input.projectId || null,
      input.title,
      input.description || null,
      status,
      priority,
      input.assignee || null,
      input.dueDate || null,
      input.profileId || null,
      input.integrationId || null,
      labelsJson,
      checklistJson,
      input.position !== undefined ? input.position : 0,
      now,
      now
    );

    return this.getTask(input.id)!;
  }

  public updateTaskStatus(id: string, status: TaskStatus, position?: number): Task | null {
    if (!this.db) return null;
    try {
      const now = new Date().toISOString();
      if (position !== undefined) {
        this.db.prepare(`
          UPDATE tasks SET status = ?, position = ?, updated_at = ? WHERE id = ?
        `).run(status, position, now, id);
      } else {
        this.db.prepare(`
          UPDATE tasks SET status = ?, updated_at = ? WHERE id = ?
        `).run(status, now, id);
      }
      return this.getTask(id);
    } catch (err) {
      log.error({ error: err }, `Failed to update task status ${id}`);
      return null;
    }
  }

  public deleteTask(id: string): boolean {
    if (!this.db) return false;
    try {
      this.db.prepare(`DELETE FROM tasks WHERE id = ?`).run(id);
      return true;
    } catch (err) {
      log.error({ error: err }, `Failed to delete task ${id}`);
      return false;
    }
  }

  // ============================================================================
  // Agent Tokens Persistence (Milestone M9.2)
  // ============================================================================

  public upsertAgentToken(token: AgentTokenRecord): void {
    if (!this.db) return;
    try {
      const stmt = this.db.prepare(`
        INSERT INTO agent_tokens (
          id, token_hash, token_prefix, principal_id, assigned_profile_id,
          name, is_revoked, created_at, expires_at, last_used_at, revoked_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          token_hash = excluded.token_hash,
          token_prefix = excluded.token_prefix,
          principal_id = excluded.principal_id,
          assigned_profile_id = excluded.assigned_profile_id,
          name = excluded.name,
          is_revoked = excluded.is_revoked,
          created_at = excluded.created_at,
          expires_at = excluded.expires_at,
          last_used_at = excluded.last_used_at,
          revoked_at = excluded.revoked_at
      `);
      stmt.run(
        token.id,
        token.tokenHash,
        token.tokenPrefix,
        token.principalId,
        token.assignedProfileId,
        token.name,
        token.isRevoked ? 1 : 0,
        token.createdAt,
        token.expiresAt,
        token.lastUsedAt,
        token.revokedAt
      );
    } catch (err) {
      log.error({ error: err, tokenId: token.id }, "Failed to upsert agent token in SQLite");
      throw err;
    }
  }

  public getAgentTokenByHash(tokenHash: string): AgentTokenRecord | null {
    if (!this.db) return null;
    try {
      const stmt = this.db.prepare(`SELECT * FROM agent_tokens WHERE token_hash = ?`);
      const row = stmt.get(tokenHash) as any;
      if (!row) return null;
      return this.mapAgentTokenRow(row);
    } catch (err) {
      log.error({ error: err }, "Failed to query agent token by hash from SQLite");
      return null;
    }
  }

  public getAgentTokenById(id: string): AgentTokenRecord | null {
    if (!this.db) return null;
    try {
      const stmt = this.db.prepare(`SELECT * FROM agent_tokens WHERE id = ?`);
      const row = stmt.get(id) as any;
      if (!row) return null;
      return this.mapAgentTokenRow(row);
    } catch (err) {
      log.error({ error: err, id }, "Failed to query agent token by ID from SQLite");
      return null;
    }
  }

  public listAgentTokens(): AgentTokenRecord[] {
    if (!this.db) return [];
    try {
      const stmt = this.db.prepare(`SELECT * FROM agent_tokens ORDER BY created_at DESC`);
      const rows = stmt.all() as any[];
      return rows.map((r) => this.mapAgentTokenRow(r));
    } catch (err) {
      log.error({ error: err }, "Failed to list agent tokens from SQLite");
      return [];
    }
  }

  public revokeAgentToken(idOrHash: string, revokedAt = Date.now()): boolean {
    if (!this.db) return false;
    try {
      const stmt = this.db.prepare(`
        UPDATE agent_tokens
        SET is_revoked = 1, revoked_at = ?
        WHERE id = ? OR token_hash = ?
      `);
      const res = stmt.run(revokedAt, idOrHash, idOrHash);
      return res.changes > 0;
    } catch (err) {
      log.error({ error: err, idOrHash }, "Failed to revoke agent token in SQLite");
      return false;
    }
  }

  public updateAgentTokenLastUsed(tokenHash: string, lastUsedAt = Date.now()): void {
    if (!this.db) return;
    try {
      const stmt = this.db.prepare(`
        UPDATE agent_tokens
        SET last_used_at = ?
        WHERE token_hash = ?
      `);
      stmt.run(lastUsedAt, tokenHash);
    } catch (err) {
      log.error({ error: err }, "Failed to update agent token last_used_at in SQLite");
    }
  }

  public deleteAgentToken(id: string): boolean {
    if (!this.db) return false;
    try {
      const stmt = this.db.prepare(`DELETE FROM agent_tokens WHERE id = ?`);
      const res = stmt.run(id);
      return res.changes > 0;
    } catch (err) {
      log.error({ error: err, id }, "Failed to delete agent token in SQLite");
      return false;
    }
  }

  private mapAgentTokenRow(row: any): AgentTokenRecord {
    return {
      id: row.id,
      tokenHash: row.token_hash,
      tokenPrefix: row.token_prefix,
      principalId: row.principal_id,
      assignedProfileId: row.assigned_profile_id,
      name: row.name,
      isRevoked: row.is_revoked === 1,
      createdAt: Number(row.created_at),
      expiresAt: row.expires_at !== null && row.expires_at !== undefined ? Number(row.expires_at) : null,
      lastUsedAt: row.last_used_at !== null && row.last_used_at !== undefined ? Number(row.last_used_at) : null,
      revokedAt: row.revoked_at !== null && row.revoked_at !== undefined ? Number(row.revoked_at) : null,
    };
  }

  public isInMemory(): boolean {
    return this.isMemory;
  }

  public close(): void {
    if (this.db) {
      this.db.close();
      this.db = null;
    }
  }
}

export const dbManager = new DatabaseManager();
