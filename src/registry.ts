import path from "node:path";
import { fileURLToPath } from "node:url";
import fs from "node:fs";
import { ServerConfig, ServerState, ServerStatus } from "./types.js";
import { dbManager } from "./db.js";
import { validateRemoteServerUrl, validateRemoteServerUrlAsync, sanitizeData } from "./security.js";
import { createChildLogger } from "./logger.js";

const log = createChildLogger("registry");

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const omnimcpRoot = path.resolve(__dirname, "..");

export class ServerRegistry {
  private servers: Map<string, ServerState> = new Map();

  constructor() {
    this.initDefaultServers();
    this.loadPersistedServers();
  }

  private initDefaultServers() {
    const cwd = process.env.ALLOWED_DIRECTORIES || process.cwd();
    const nodeExec = process.execPath;

    // 1. Filesystem Server
    const fsScript = path.resolve(omnimcpRoot, "node_modules/@modelcontextprotocol/server-filesystem/dist/index.js");
    this.register({
      id: "filesystem",
      name: "Filesystem MCP",
      description: "Local filesystem operations (read, write, search, directory structure) within workspace",
      category: "core",
      transport: "stdio",
      enabled: true,
      autoConnect: true,
      command: nodeExec,
      args: [fsScript, cwd],
      allowedPermissions: ["READ_ONLY", "WRITE_PROTECTED", "DESTRUCTIVE_ADMIN"],
      requiresApprovalForDestructive: true,
    });

    // 2. GitHub Server
    const ghScript = path.resolve(omnimcpRoot, "node_modules/@modelcontextprotocol/server-github/dist/index.js");
    const ghToken =
      process.env.GITHUB_PERSONAL_ACCESS_TOKEN ||
      process.env.GITHUB_TOKEN ||
      process.env.GH_TOKEN ||
      "";
    this.register({
      id: "github",
      name: "GitHub MCP",
      description: "GitHub API integration for repositories, issues, PRs, branches, and code search",
      category: "development",
      transport: "stdio",
      enabled: true,
      autoConnect: Boolean(ghToken),
      command: nodeExec,
      args: [ghScript],
      cwd: omnimcpRoot,
      env: ghToken ? { GITHUB_PERSONAL_ACCESS_TOKEN: ghToken, GITHUB_TOKEN: ghToken } : {},
      allowedPermissions: ["READ_ONLY", "WRITE_PROTECTED", "DESTRUCTIVE_ADMIN"],
      requiresApprovalForDestructive: true,
    });

    // 3. Context7 MCP
    const ctx7Script = path.resolve(omnimcpRoot, "node_modules/@upstash/context7-mcp/dist/index.js");
    const ctx7ApiKey = process.env.CONTEXT7_API_KEY || "";
    this.register({
      id: "context7",
      name: "Context7 MCP",
      description: "Up-to-date documentation and library query engine by Upstash",
      category: "development",
      transport: "stdio",
      enabled: true,
      autoConnect: true,
      command: nodeExec,
      args: [ctx7Script],
      cwd: omnimcpRoot,
      env: ctx7ApiKey ? { CONTEXT7_API_KEY: ctx7ApiKey } : {},
      allowedPermissions: ["READ_ONLY"],
      requiresApprovalForDestructive: false,
    });

    // 4. Playwright Server (Real local package)
    const pwScript = path.resolve(omnimcpRoot, "node_modules/@playwright/mcp/cli.js");
    this.register({
      id: "playwright",
      name: "Playwright MCP",
      description: "Browser automation, DOM interaction, page screenshots and test validation via Microsoft Playwright",
      category: "browser",
      transport: "stdio",
      enabled: true,
      autoConnect: false, // On-demand by default to avoid opening browsers unless needed
      command: nodeExec,
      args: [pwScript],
      cwd: omnimcpRoot,
      env: {
        PLAYWRIGHT_HEADLESS: process.env.PLAYWRIGHT_HEADLESS || "true",
        PLAYWRIGHT_BROWSER: process.env.PLAYWRIGHT_BROWSER || "chromium",
      },
      allowedPermissions: ["READ_ONLY", "WRITE_PROTECTED", "DESTRUCTIVE_ADMIN"],
      requiresApprovalForDestructive: true,
    });

    // 5. Supabase Server (Built-in standard MCP adapter)
    const supaScript = fs.existsSync(path.resolve(omnimcpRoot, "dist/integrations/supabase-server.js"))
      ? path.resolve(omnimcpRoot, "dist/integrations/supabase-server.js")
      : path.resolve(omnimcpRoot, "src/integrations/supabase-server.ts");

    const isTs = supaScript.endsWith(".ts");
    const npxCmd = process.platform === "win32" ? "npx.cmd" : "npx";
    const supaUrl = process.env.SUPABASE_URL || "";
    const supaKey = process.env.SUPABASE_SERVICE_ROLE_KEY || "";
    this.register({
      id: "supabase",
      name: "Supabase MCP",
      description: "Postgres database queries, migrations, table CRUD, RPC execution, and Auth user administration",
      category: "database",
      transport: "stdio",
      enabled: true,
      autoConnect: Boolean(supaUrl && supaKey),
      command: isTs ? npxCmd : nodeExec,
      args: isTs ? ["-y", "tsx", supaScript] : [supaScript],
      cwd: omnimcpRoot,
      env: {
        SUPABASE_URL: supaUrl,
        SUPABASE_SERVICE_ROLE_KEY: supaKey,
      },
      allowedPermissions: ["READ_ONLY", "WRITE_PROTECTED", "DESTRUCTIVE_ADMIN"],
      requiresApprovalForDestructive: true,
    });

    // 6. shadcn/ui Server (Real local package)
    const shadcnScript = path.resolve(omnimcpRoot, "node_modules/@magnusrodseth/shadcn-mcp-server/dist/index.js");
    this.register({
      id: "shadcn",
      name: "shadcn/ui MCP",
      description: "Component catalog inspection, design tokens, and shadcn component scaffolding",
      category: "development",
      transport: "stdio",
      enabled: true,
      autoConnect: true,
      command: nodeExec,
      args: [shadcnScript],
      cwd: omnimcpRoot,
      allowedPermissions: ["READ_ONLY", "WRITE_PROTECTED"],
      requiresApprovalForDestructive: false,
    });

    // 7. Sentry Server (Official server when token is present, adapter fallback when absent)
    const sentryToken = process.env.SENTRY_AUTH_TOKEN || process.env.SENTRY_TOKEN || "";
    const sentryScript = sentryToken
      ? path.resolve(omnimcpRoot, "node_modules/@sentry/mcp-server/dist/sentry-mcp.cjs")
      : (fs.existsSync(path.resolve(omnimcpRoot, "dist/integrations/sentry-adapter.js"))
          ? path.resolve(omnimcpRoot, "dist/integrations/sentry-adapter.js")
          : path.resolve(omnimcpRoot, "src/integrations/sentry-adapter.ts"));

    const isSentryTs = sentryScript.endsWith(".ts");
    this.register({
      id: "sentry",
      name: "Sentry MCP",
      description: "Application health, error tracking, stacktraces, and performance telemetry via Sentry",
      category: "observability",
      transport: "stdio",
      enabled: true,
      autoConnect: Boolean(sentryToken),
      command: isSentryTs ? npxCmd : nodeExec,
      args: isSentryTs ? ["-y", "tsx", sentryScript] : [sentryScript],
      cwd: omnimcpRoot,
      env: {
        SENTRY_AUTH_TOKEN: sentryToken,
        SENTRY_TOKEN: sentryToken,
        SENTRY_ORG: process.env.SENTRY_ORG || process.env.SENTRY_ORG_SLUG || "",
        SENTRY_PROJECT: process.env.SENTRY_PROJECT || "",
        SENTRY_HOST: process.env.SENTRY_HOST || "https://sentry.io",
        SENTRY_CLI_NO_PERSISTENCE: "true",
      },
      allowedPermissions: ["READ_ONLY"],
      requiresApprovalForDestructive: false,
    });

    // 8. Google Stitch Remote MCP Server (Hosted Streamable HTTP endpoint)
    const stitchApiKey = process.env.STITCH_API_KEY || "";
    this.register({
      id: "stitch",
      name: "Google Stitch MCP",
      description: "Google Stitch hosted remote MCP server for design generation, screen synthesis, and component UI modeling",
      category: "development",
      transport: "http",
      enabled: true,
      autoConnect: Boolean(stitchApiKey),
      url: "https://stitch.googleapis.com/mcp",
      allowedPermissions: ["READ_ONLY", "WRITE_PROTECTED"],
      requiresApprovalForDestructive: false,
    });

    log.info({ registeredCount: this.servers.size }, "Server registry initialized with default servers");
  }

  private loadPersistedServers() {
    try {
      const persisted = dbManager.getPersistedServers();
      for (const p of persisted) {
        if (!this.servers.has(p.id)) {
          this.register(p, false);
        }
      }
      log.info({ persistedCount: persisted.length }, "Loaded persisted servers from database");
    } catch (err) {
      log.warn({ error: err }, "Could not load persisted servers from DB");
    }
  }

  public register(config: ServerConfig, persist = true, allowOverwrite = false): ServerState {
    const existing = this.servers.get(config.id);
    if (existing && !allowOverwrite) {
      throw new Error(
        `Server '${config.id}' is already registered. Direct configuration overwrite is prohibited for security.`
      );
    }

    // SSRF Validation for HTTP servers
    if (config.transport === "http" || config.transport === "sse") {
      if (!config.url) {
        throw new Error(`HTTP/SSE server '${config.id}' requires a valid url`);
      }
      const val = validateRemoteServerUrl(config.url, process.env.NODE_ENV !== "production");
      if (!val.valid) {
        throw new Error(`Invalid server URL for '${config.id}': ${val.reason}`);
      }
    }

    const state: ServerState = {
      ...config,
      status: "disconnected",
      toolCount: 0,
    };
    this.servers.set(config.id, state);

    if (persist) {
      dbManager.upsertServer(config);
    }

    return state;
  }

  /**
   * Safely updates non-sensitive mutable properties of an existing server.
   * Execution parameters (command, args, cwd, env, transport, allowedPermissions) are strictly immutable.
   */
  public updateServerSettings(
    id: string,
    updates: { enabled?: boolean; autoConnect?: boolean; description?: string }
  ): ServerState {
    const server = this.servers.get(id);
    if (!server) {
      throw new Error(`Server '${id}' not found in registry.`);
    }

    if (typeof updates.enabled === "boolean") {
      server.enabled = updates.enabled;
    }
    if (typeof updates.autoConnect === "boolean") {
      server.autoConnect = updates.autoConnect;
    }
    if (typeof updates.description === "string" && updates.description.trim()) {
      server.description = updates.description.trim();
    }

    dbManager.upsertServer(server);
    log.info({ serverId: id, enabled: server.enabled, autoConnect: server.autoConnect }, "Updated server settings");
    return server;
  }

  /**
   * Asynchronously validates remote server URL and resolves DNS records
   * to protect against DNS rebinding and internal network SSRF before connection.
   */
  public async validateRemoteUrl(config: ServerConfig): Promise<void> {
    if (config.transport === "http" || config.transport === "sse") {
      if (!config.url) {
        throw new Error(`HTTP/SSE server '${config.id}' requires a valid url`);
      }
      const asyncCheck = await validateRemoteServerUrlAsync(
        config.url,
        process.env.NODE_ENV !== "production"
      );
      if (!asyncCheck.valid) {
        throw new Error(`DNS validation failed for '${config.id}': ${asyncCheck.reason}`);
      }
    }
  }

  public getServer(id: string): ServerState | undefined {
    return this.servers.get(id);
  }

  public getAllServers(): ServerState[] {
    return Array.from(this.servers.values()).map((s) => ({
      ...s,
      env: s.env ? (sanitizeData(s.env) as Record<string, string>) : undefined,
      headers: s.headers ? (sanitizeData(s.headers) as Record<string, string>) : undefined,
      error: s.error ? String(sanitizeData(s.error)) : undefined,
    }));
  }

  public getConnectedServers(): ServerState[] {
    return this.getAllServers().filter((s) => s.status === "connected");
  }

  public updateStatus(id: string, status: ServerStatus, error?: string, toolCount?: number, latencyMs?: number): void {
    const s = this.servers.get(id);
    if (!s) return;

    s.status = status;
    s.error = error;
    if (status === "connected") {
      s.lastConnectedAt = new Date().toISOString();
    }
    if (toolCount !== undefined) {
      s.toolCount = toolCount;
    }
    if (latencyMs !== undefined) {
      s.latencyMs = latencyMs;
    }
  }

  /**
   * Safe configuration update that strictly prevents modifying execution parameters.
   * Delegates directly to updateServerSettings.
   */
  public updateConfig(
    id: string,
    partial: { enabled?: boolean; autoConnect?: boolean; description?: string }
  ): ServerState {
    const prohibited = ["command", "args", "cwd", "env", "transport", "url", "allowedPermissions"];
    for (const key of Object.keys(partial as Record<string, unknown>)) {
      if (prohibited.includes(key)) {
        throw new Error(`Modifying execution parameter '${key}' via updateConfig is prohibited.`);
      }
    }
    return this.updateServerSettings(id, partial);
  }

  public removeServer(id: string): void {
    this.servers.delete(id);
    dbManager.deleteServer(id);
    log.info({ serverId: id }, "Server removed from registry and database");
  }

  public searchServers(query?: string, category?: string, status?: string): ServerState[] {
    return this.getAllServers().filter((s) => {
      if (category && s.category.toLowerCase() !== category.toLowerCase()) return false;
      if (status && status !== "all" && s.status !== status) return false;
      if (query) {
        const q = query.toLowerCase();
        const matchesName = s.name.toLowerCase().includes(q);
        const matchesDesc = s.description.toLowerCase().includes(q);
        const matchesId = s.id.toLowerCase().includes(q);
        if (!matchesName && !matchesDesc && !matchesId) return false;
      }
      return true;
    });
  }
}

export const serverRegistry = new ServerRegistry();
