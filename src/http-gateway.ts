import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import crypto from "node:crypto";
import { z } from "zod";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { OmniMCPGatewayServer } from "./gateway-server.js";
import { serverRegistry } from "./registry.js";
import { clientManager } from "./client-manager.js";
import { discoveryEngine } from "./discovery.js";
import { executionEngine } from "./executor.js";
import { executionHistory } from "./history.js";
import { smartRouter } from "./router.js";
import { healthMonitor } from "./health.js";
import { permissionManager } from "./permissions.js";
import { dbManager } from "./db.js";
import { profilesManager } from "./profiles.js";
import { 
  CreateProfileSchema, 
  UpdateProfileSchema, 
  CreateTaskSchema, 
  UpdateTaskSchema,
  TaskStatus,
} from "./types.js";
import { createChildLogger } from "./logger.js";
import { PermissionLevel } from "./types.js";
import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import { sanitizeData } from "./security.js";
import { createRemoteMcpRouter } from "./remote-mcp/transport.js";
import { remoteTokenManager } from "./remote-mcp/token-manager.js";
import { remoteSessionManager } from "./remote-mcp/session-manager.js";
import { telemetryManager } from "./telemetry.js";

const log = createChildLogger("http-gateway");

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const publicDir = path.resolve(__dirname, "../public");

// Pre-approved STDIO server registry: only these pre-configured server IDs can be registered
// via the HTTP API. Arbitrary command registration is completely disabled.
// Custom servers must be added directly to registry.ts (code review required).
export const PRE_APPROVED_SERVER_IDS = new Set([
  "filesystem",
  "github",
  "context7",
  "playwright",
  "shadcn",
  "supabase",
  "sentry",
]);

// --------------------------------------------------------------------------
// Role-Separated Authentication, Multi-Agent Identity & Session Management
// --------------------------------------------------------------------------
export const PLACEHOLDER_AGENT_TOKEN = "your_agent_token_here";

export const getAgentToken = (): string | undefined => {
  const token = process.env.OMNIMCP_AGENT_TOKEN || process.env.OMNIMCP_AUTH_TOKEN;
  if (!token || token.trim() === "" || token.trim() === PLACEHOLDER_AGENT_TOKEN) {
    return undefined;
  }
  return token.trim();
};

export const getOperatorToken = (): string | undefined => {
  return process.env.OMNIMCP_OPERATOR_TOKEN;
};

export class SessionQuotaExceededError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SessionQuotaExceededError";
  }
}

export interface AgentSession {
  sessionId: string;
  tokenHash: string; // SHA-256 hash of the raw secret token; raw token is NEVER persisted in memory
  principalId: string;
  createdAt: number;
  expiresAt: number;
}

// In-memory session store: maps SHA-256(sessionToken) -> AgentSession record
const activeAgentSessions = new Map<string, AgentSession>();

// In-memory sliding-window rate limiting for session creation per principal
const sessionCreationWindows = new Map<string, number[]>();

let sessionCleanupInterval: NodeJS.Timeout | null = null;

export function hashSessionToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

export function checkSessionCreationRateLimit(
  principal: string,
  limitPerMinute = 10
): { allowed: boolean; retryAfterSeconds?: number } {
  const now = Date.now();
  const windowStart = now - 60000;
  let timestamps = sessionCreationWindows.get(principal) || [];
  timestamps = timestamps.filter((t) => t > windowStart);
  if (timestamps.length >= limitPerMinute) {
    const oldest = timestamps[0] || now;
    const retryAfterSeconds = Math.max(1, Math.ceil((oldest + 60000 - now) / 1000));
    return { allowed: false, retryAfterSeconds };
  }
  timestamps.push(now);
  sessionCreationWindows.set(principal, timestamps);
  return { allowed: true };
}

export function clearSessionRateLimits(): void {
  sessionCreationWindows.clear();
}

/**
 * Creates a new agent session.
 * - Generates 256 bits of CSPRNG entropy.
 * - Returns raw token only once on issuance.
 * - Stores ONLY the SHA-256 hash in activeAgentSessions.
 * - Enforces per-principal active session quotas (default: 20 max active).
 */
export function createAgentSession(
  principalId?: string,
  ttlSeconds = 86400,
  maxActivePerPrincipal = 20
): { sessionToken: string; principalId: string; expiresAt: number; sessionId: string } {
  const sessionId = crypto.randomUUID();
  const rawToken = "omnimcp_sess_" + crypto.randomBytes(32).toString("hex");
  const tokenHash = hashSessionToken(rawToken);
  const now = Date.now();
  const resolvedPrincipal = principalId || `agent_session_${sessionId}`;

  // Opportunistic cleanup of expired sessions and active quota evaluation
  let activeCountForPrincipal = 0;
  for (const [hash, s] of activeAgentSessions.entries()) {
    if (s.expiresAt <= now) {
      activeAgentSessions.delete(hash);
    } else if (s.principalId === resolvedPrincipal) {
      activeCountForPrincipal++;
    }
  }

  if (activeCountForPrincipal >= maxActivePerPrincipal) {
    throw new SessionQuotaExceededError(
      `Maximum active sessions quota (${maxActivePerPrincipal}) reached for principal '${resolvedPrincipal}'.`
    );
  }

  const session: AgentSession = {
    sessionId,
    tokenHash,
    principalId: resolvedPrincipal,
    createdAt: now,
    expiresAt: now + ttlSeconds * 1000,
  };

  // STORE SHA-256 HASH AS KEY, NEVER RAW TOKEN
  activeAgentSessions.set(tokenHash, session);

  return {
    sessionToken: rawToken,
    principalId: resolvedPrincipal,
    expiresAt: session.expiresAt,
    sessionId: session.sessionId,
  };
}

export function getAgentSession(rawToken: string): AgentSession | undefined {
  if (!rawToken) return undefined;
  const tokenHash = hashSessionToken(rawToken);
  const session = activeAgentSessions.get(tokenHash);
  if (!session) return undefined;
  if (Date.now() > session.expiresAt) {
    activeAgentSessions.delete(tokenHash);
    return undefined;
  }
  return session;
}

export function revokeAgentSession(rawToken: string): boolean {
  if (!rawToken) return false;
  const tokenHash = hashSessionToken(rawToken);
  return activeAgentSessions.delete(tokenHash);
}

export function cleanupExpiredAgentSessions(now = Date.now()): number {
  let cleanedCount = 0;
  for (const [tokenHash, session] of activeAgentSessions.entries()) {
    if (session.expiresAt <= now) {
      activeAgentSessions.delete(tokenHash);
      cleanedCount++;
    }
  }
  return cleanedCount;
}

export function startSessionCleanupTimer(intervalMs = 15 * 60 * 1000): void {
  if (sessionCleanupInterval) {
    clearInterval(sessionCleanupInterval);
    sessionCleanupInterval = null;
  }
  sessionCleanupInterval = setInterval(() => {
    cleanupExpiredAgentSessions();
  }, intervalMs);
  sessionCleanupInterval.unref();
}

export function stopSessionCleanupTimer(): void {
  if (sessionCleanupInterval) {
    clearInterval(sessionCleanupInterval);
    sessionCleanupInterval = null;
  }
}

export function isCleanupTimerActive(): boolean {
  return sessionCleanupInterval !== null;
}

export function clearAllAgentSessions(): void {
  activeAgentSessions.clear();
  sessionCreationWindows.clear();
}

export function getActiveSessionCount(): number {
  return activeAgentSessions.size;
}

export function isRawTokenInSessionMap(rawToken: string): boolean {
  return activeAgentSessions.has(rawToken);
}

export const getPerAgentTokens = (): Map<string, string> => {
  const raw = process.env.OMNIMCP_AGENT_TOKENS;
  const tokenMap = new Map<string, string>(); // token -> principalId
  if (!raw) return tokenMap;
  try {
    if (raw.trim().startsWith("{")) {
      const parsed = JSON.parse(raw);
      for (const [principal, tok] of Object.entries(parsed)) {
        if (typeof tok === "string" && tok.trim() && tok.trim() !== PLACEHOLDER_AGENT_TOKEN) {
          tokenMap.set(tok.trim(), principal.trim());
        }
      }
      return tokenMap;
    }
  } catch (_) {}
  const pairs = raw.split(",");
  for (const pair of pairs) {
    const parts = pair.split(":");
    if (parts.length >= 2) {
      const principal = parts[0].trim();
      const tok = parts.slice(1).join(":").trim();
      if (principal && tok && tok !== PLACEHOLDER_AGENT_TOKEN) {
        tokenMap.set(tok, principal);
      }
    }
  }
  return tokenMap;
};

export function extractClientToken(req: Request): string | undefined {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    return authHeader.substring(7).trim();
  }
  if (typeof req.headers["x-omnimcp-token"] === "string") {
    return req.headers["x-omnimcp-token"].trim();
  }
  // URL query parameter authentication is strictly rejected to prevent credential leaks
  return undefined;
}

export function timingSafeMatch(clientToken: string | undefined, expectedToken: string | undefined): boolean {
  if (!clientToken || !expectedToken) return false;
  const clientBuf = Buffer.from(clientToken);
  const expectedBuf = Buffer.from(expectedToken);
  if (clientBuf.length !== expectedBuf.length) return false;
  return crypto.timingSafeEqual(clientBuf, expectedBuf);
}

/**
 * Resolves an agent token into an authenticated principal.
 * Precedence:
 * 1. Server-issued active session token (omnimcp_sess_...)
 * 2. Configured per-agent tokens (OMNIMCP_AGENT_TOKENS)
 * 3. Default master agent token (OMNIMCP_AGENT_TOKEN / OMNIMCP_AUTH_TOKEN)
 *
 * Client-supplied identification headers (e.g. x-agent-id) are strictly disregarded.
 */
export function resolveAgentPrincipal(clientToken: string | undefined): { valid: boolean; principalId?: string } {
  if (!clientToken || clientToken.trim() === "" || clientToken.trim() === PLACEHOLDER_AGENT_TOKEN) {
    return { valid: false };
  }

  // 1. Check server-issued active session
  const session = getAgentSession(clientToken);
  if (session) {
    return { valid: true, principalId: session.principalId };
  }

  // 2. Check per-agent tokens
  const perAgentTokens = getPerAgentTokens();
  for (const [configuredToken, principal] of perAgentTokens.entries()) {
    if (timingSafeMatch(clientToken, configuredToken)) {
      return { valid: true, principalId: principal };
    }
  }

  // 3. Check shared master agent token
  const masterAgentToken = getAgentToken();
  if (masterAgentToken && timingSafeMatch(clientToken, masterAgentToken)) {
    // Note: When multiple clients share the master agent token without sessions or per-agent keys,
    // they share the "shared_agent_token" principal.
    return { valid: true, principalId: "shared_agent_token" };
  }

  return { valid: false };
}

// Operator-Only Authentication Middleware
export const requireOperatorAuth = (req: Request, res: Response, next: NextFunction): void => {
  const operatorToken = getOperatorToken();
  if (!operatorToken || operatorToken.trim() === "") {
    res.status(500).json({
      error: "Server misconfiguration",
      message: "OMNIMCP_OPERATOR_TOKEN must be configured to access operator approval endpoints.",
    });
    return;
  }

  const clientToken = extractClientToken(req);
  if (!clientToken) {
    res.status(401).json({
      error: "Unauthorized",
      message: "Operator credentials required. Supply 'Authorization: Bearer <operator_token>'.",
    });
    return;
  }

  // Check if client supplied an agent token or session instead
  const agentResolution = resolveAgentPrincipal(clientToken);
  if (agentResolution.valid) {
    res.status(403).json({
      error: "Forbidden",
      message: "Agent credentials cannot access human operator approval endpoints.",
    });
    return;
  }

  if (!timingSafeMatch(clientToken, operatorToken)) {
    res.status(403).json({
      error: "Forbidden",
      message: "Invalid operator credentials.",
    });
    return;
  }

  // Derive operator identity ONLY from verified token; NEVER trust client-supplied headers
  (req as any).operatorIdentity = "authenticated_operator";
  (req as any).role = "operator";
  next();
};

// Agent-Only Authentication Middleware
export const requireAgentAuth = (req: Request, res: Response, next: NextFunction): void => {
  const agentToken = getAgentToken();
  const perAgentTokens = getPerAgentTokens();
  if ((!agentToken || agentToken.trim() === "") && perAgentTokens.size === 0) {
    res.status(500).json({
      error: "Server misconfiguration",
      message: "OMNIMCP_AGENT_TOKEN must be configured to access agent execution endpoints.",
    });
    return;
  }

  const clientToken = extractClientToken(req);
  if (!clientToken) {
    res.status(401).json({
      error: "Unauthorized",
      message: "Agent credentials required. Supply 'Authorization: Bearer <agent_token>'.",
    });
    return;
  }

  // Check if client supplied operator token instead
  const operatorToken = getOperatorToken();
  if (operatorToken && timingSafeMatch(clientToken, operatorToken)) {
    res.status(403).json({
      error: "Forbidden",
      message: "Operator credentials cannot directly invoke agent-only execution endpoints. Agent token required.",
    });
    return;
  }

  const agentResolution = resolveAgentPrincipal(clientToken);
  if (!agentResolution.valid || !agentResolution.principalId) {
    res.status(403).json({
      error: "Forbidden",
      message: "Invalid agent credentials.",
    });
    return;
  }

  (req as any).agentIdentity = "authenticated_agent";
  (req as any).agentPrincipal = agentResolution.principalId;
  (req as any).role = "agent";
  next();
};

// Either Agent OR Operator Middleware (for shared endpoints like tool listing, server catalog, health)
export const requireAgentOrOperatorAuth = (req: Request, res: Response, next: NextFunction): void => {
  const agentToken = getAgentToken();
  const operatorToken = getOperatorToken();
  const perAgentTokens = getPerAgentTokens();

  if (
    (!agentToken || agentToken.trim() === "") &&
    (!operatorToken || operatorToken.trim() === "") &&
    perAgentTokens.size === 0
  ) {
    res.status(500).json({
      error: "Server misconfiguration",
      message: "Authentication tokens must be configured.",
    });
    return;
  }

  const clientToken = extractClientToken(req);
  if (!clientToken) {
    res.status(401).json({
      error: "Unauthorized",
      message: "Authentication credentials required.",
    });
    return;
  }

  const isOperator = operatorToken ? timingSafeMatch(clientToken, operatorToken) : false;
  const agentResolution = resolveAgentPrincipal(clientToken);

  if (!isOperator && !agentResolution.valid) {
    res.status(403).json({
      error: "Forbidden",
      message: "Invalid credentials.",
    });
    return;
  }

  if (isOperator) {
    (req as any).role = "operator";
    (req as any).operatorIdentity = "authenticated_operator";
  } else {
    (req as any).role = "agent";
    (req as any).agentIdentity = "authenticated_agent";
    (req as any).agentPrincipal = agentResolution.principalId;
  }
  next();
};

export const handleGetApprovalRequest = (req: Request, res: Response): void => {
  const id = String(req.params.id);
  const approval = permissionManager.getApprovalRequest(id);
  if (!approval) {
    res.status(404).json({ error: `Approval request '${id}' not found.` });
    return;
  }

  const role = (req as any).role;
  // Operators retain global inspection access to all approval requests
  if (role === "operator") {
    res.json({
      ...approval,
      parameters: sanitizeData(approval.parameters),
      token: undefined, // Never expose raw approval tokens to operator
    });
    return;
  }

  // For Agents: strictly enforce authenticated principal ownership
  const callerPrincipal = (req as any).agentPrincipal;
  if (!callerPrincipal || approval.requesterPrincipal !== callerPrincipal) {
    res.status(403).json({
      error: "Forbidden",
      message: "Access denied: You do not have permission to inspect approval requests created by another agent.",
    });
    return;
  }

  // An agent should ONLY receive the approval token if the request is actively approved and unexpired
  const isExpired = approval.expiresAt <= Date.now();
  const isActivelyApproved = approval.status === "approved" && !isExpired;

  res.json({
    ...approval,
    token: isActivelyApproved ? approval.token : undefined,
  });
};

export const handleGetApprovals = (req: Request, res: Response): void => {
  const status = typeof req.query.status === "string" ? req.query.status.toLowerCase() : "all";
  const approvals = permissionManager.getAllApprovals(status);
  res.json(approvals);
};

export const handleApproveRequest = (req: Request, res: Response): void => {
  try {
    const id = String(req.params.id);
    const verifiedOperator = "authenticated_operator";
    const { request: approvedReq, token } = permissionManager.approveRequest(id, verifiedOperator);
    res.json({
      status: "approved",
      requestId: approvedReq.id,
      toolId: approvedReq.toolId,
      serverId: approvedReq.serverId,
      token,
      expiresAt: approvedReq.expiresAt,
    });
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
};

export const handleRejectRequest = (req: Request, res: Response): void => {
  try {
    const id = String(req.params.id);
    const rawReason = typeof req.body?.reason === "string" ? req.body.reason : "Rejected by operator";
    const reason = sanitizeData(rawReason.trim().slice(0, 500));
    const verifiedOperator = "authenticated_operator";
    const rejected = permissionManager.rejectRequest(id, verifiedOperator, reason);
    res.json({ status: "rejected", requestId: rejected.id, reason: rejected.rejectionReason });
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
};

export const handleGetStats = (_req: Request, res: Response): void => {
  const stats = dbManager.getExecutionStats();
  const pendingApprovals = permissionManager.getPendingApprovals().length;
  res.json({
    ...stats,
    pendingApprovals,
  });
};

export const handleGetTelemetryTimeline = (req: Request, res: Response): void => {
  const rawRange = String(req.query.range || "1h");
  const validRange: "15m" | "1h" | "6h" | "24h" =
    rawRange === "15m" || rawRange === "6h" || rawRange === "24h" ? rawRange : "1h";
  const data = telemetryManager.getTimeline(validRange);
  res.json(data);
};

export const handleGetDashboardSummary = (_req: Request, res: Response): void => {
  const stats = dbManager.getExecutionStats();
  const pendingApprovals = permissionManager.getPendingApprovals().length;
  const health = {
    status: "healthy",
    uptimeSeconds: Math.floor(process.uptime()),
    timestamp: new Date().toISOString(),
    version: "2.1.0",
    memory: process.memoryUsage(),
    nodeVersion: process.version,
    gatewayRole: "operator",
    activeSessions: remoteSessionManager.getActiveSessionsCount(),
  };
  const servers = serverRegistry.getAllServers();
  const tools = discoveryEngine.getAllTools();
  const recentHistory = executionHistory.getHistory(20);
  const telemetry = telemetryManager.getTimeline("1h");
  const profiles = profilesManager.listProfiles();
  const activeProfile = profilesManager.getActiveProfile();
  const tasks = dbManager.listTasks();

  res.json({
    stats: {
      ...stats,
      pendingApprovals,
    },
    health,
    servers,
    toolsCount: tools.length,
    recentHistory,
    telemetry,
    profiles: {
      profiles,
      activeProfileId: activeProfile?.id || null,
    },
    tasks: {
      tasks,
    },
  });
};

export const handleGetHistory = (req: Request, res: Response): void => {
  // Validate limit as finite, positive integer (default 50, clamp [1, 100])
  const rawLimit = Number(req.query.limit);
  const limit = Number.isFinite(rawLimit) && rawLimit > 0
    ? Math.min(Math.floor(rawLimit), 100)
    : 50;

  // Validate offset as finite, non-negative integer (default 0)
  const rawOffset = Number(req.query.offset);
  const offset = Number.isFinite(rawOffset) && rawOffset >= 0
    ? Math.floor(rawOffset)
    : 0;

  const server = typeof req.query.server === "string" && req.query.server.trim() ? req.query.server.trim() : undefined;
  const status = typeof req.query.status === "string" && req.query.status.trim() ? req.query.status.trim() : undefined;
  const traceId = typeof req.query.traceId === "string" && req.query.traceId.trim() ? req.query.traceId.trim() : undefined;

  const history = executionHistory.getHistory(limit, server, status, traceId, offset);
  const totalCount = executionHistory.countHistory(server, status, traceId);

  res.setHeader("X-Total-Count", String(totalCount));
  res.json(history);
};

export const handleGetHistoryByTraceId = (req: Request, res: Response): void => {
  const traceId = String(req.params.traceId);
  const record = executionHistory.getByTraceId(traceId);
  if (!record) {
    res.status(404).json({ error: "Execution trace not found", traceId });
    return;
  }
  res.json(record);
};

export const handleGetAntigravityConfig = (req: Request, res: Response): void => {
  const rawNode = typeof req.query.nodePath === "string" && req.query.nodePath.trim() ? req.query.nodePath.trim() : undefined;
  const rawProject = typeof req.query.projectPath === "string" && req.query.projectPath.trim() ? req.query.projectPath.trim() : undefined;

  let projectRoot: string;
  if (rawProject) {
    if (/^[a-zA-Z]:[/\\]/.test(rawProject) || rawProject.startsWith("/")) {
      projectRoot = rawProject.replace(/\\/g, "/");
    } else {
      projectRoot = path.resolve(rawProject).replace(/\\/g, "/");
    }
  } else {
    projectRoot = path.resolve(__dirname, "..").replace(/\\/g, "/");
  }

  projectRoot = projectRoot.replace(/\/+$/, "");
  const indexPath = `${projectRoot}/dist/index.js`;
  const nodeCommand = (rawNode ? rawNode : process.execPath).replace(/\\/g, "/");

  res.json({
    mcpServers: {
      omnimcp: {
        command: nodeCommand,
        args: [indexPath, "--stdio"],
        cwd: projectRoot,
      },
    },
  });
};

export const handleGetSettings = (_req: Request, res: Response): void => {
  const projectRoot = path.resolve(__dirname, "..").replace(/\\/g, "/");
  const indexPath = path.join(projectRoot, "dist", "index.js").replace(/\\/g, "/");
  const stats = dbManager.getExecutionStats();
  const connectedServers = serverRegistry.getConnectedServers();
  const allServers = serverRegistry.getAllServers();
  const agentToken = getAgentToken();
  const operatorToken = getOperatorToken();
  const perAgentTokens = getPerAgentTokens();

  res.json({
    gateway: {
      status: "active",
      transports: ["stdio", "http", "sse"],
      upstreamTransports: ["stdio", "http", "sse"],
      downstreamTransports: ["stdio"],
      downstreamHttpTransportStatus: "not_implemented",
      version: "1.0.0",
      nodeVersion: process.version,
      platform: process.platform,
      uptimeSeconds: Math.floor(process.uptime()),
      coreToolCount: 10,
      connectedServersCount: connectedServers.length,
      totalServersCount: allServers.length,
      projectRoot,
      distIndexPath: indexPath,
      distExists: fs.existsSync(indexPath),
      defaultAntigravityConfigPath: "~/.gemini/config/mcp_config.json",
    },
    authentication: {
      agentAuthStatus: (agentToken && agentToken.trim().length > 0) || perAgentTokens.size > 0 ? "configured" : "unconfigured",
      agentMasterTokenConfigured: Boolean(agentToken && agentToken.trim().length > 0),
      perAgentTokensCount: perAgentTokens.size,
      operatorAuthStatus: operatorToken && operatorToken.trim().length > 0 ? "configured" : "unconfigured",
      sessionAuthEnabled: true,
      activeSessionsCount: activeAgentSessions.size,
      tokenRotationGuidance: "Update OMNIMCP_AGENT_TOKEN and OMNIMCP_OPERATOR_TOKEN in environment or .env file and restart the process to rotate secrets. Never reuse operator tokens as agent tokens.",
    },
    security: {
      approvalWorkflowStatus: "active",
      pendingApprovalsCount: permissionManager.getPendingApprovals().length,
      approvalQueueType: "session_in_memory",
      approvalTtlSeconds: 300,
      auditLoggingStatus: dbManager.isInMemory() ? "in_memory_fallback" : "sqlite_active",
      auditSanitizationStatus: "test_verified",
      auditDatabasePath: (process.env.SQLITE_DB_PATH || "./data/omnimcp.db").replace(/\\/g, "/"),
      secretRedactionStatus: "enabled",
      downstreamHttpTransport: "not_implemented",
      allowedDirectories: process.env.ALLOWED_DIRECTORIES
        ? [process.env.ALLOWED_DIRECTORIES.replace(/\\/g, "/")]
        : [projectRoot],
      preApprovedServers: ["filesystem", "github", "context7", "playwright", "shadcn", "supabase", "sentry"],
    },
    diagnostics: {
      gatewayHealth: "healthy",
      sqliteMode: dbManager.isInMemory() ? "in_memory" : "persistent_wal",
      encryptionVault: process.env.OMNIMCP_ENCRYPTION_KEY && process.env.OMNIMCP_ENCRYPTION_KEY.length === 64
        ? "configured"
        : "ephemeral_session",
      totalExecutions: stats.totalExecutions,
      successRate: stats.successRate,
      avgLatencyMs: stats.avgLatencyMs,
    },
  });
};

// Dynamic, secure CORS allowlist supporting localhost and verified cloud deployment origins
export const isAllowedOrigin = (origin: string): boolean => {
  if (!origin) return true;
  try {
    const url = new URL(origin);
    const hostname = url.hostname.toLowerCase();
    // Allow local development and loopback
    if (
      hostname === "localhost" ||
      hostname === "127.0.0.1" ||
      hostname === "0.0.0.0" ||
      hostname === "::1"
    ) {
      return true;
    }
    // Allow cloud hosting platforms (Voroa, Railway, Render, Vercel, Fly)
    if (
      hostname.endsWith(".onvoroa.com") ||
      hostname.endsWith(".railway.app") ||
      hostname.endsWith(".render.com") ||
      hostname.endsWith(".vercel.app") ||
      hostname.endsWith(".fly.dev")
    ) {
      return true;
    }
  } catch {
    // Invalid origin URL format
  }

  // Check custom environment variables (comma-separated list or '*')
  const customAllowed = process.env.ALLOWED_ORIGINS || process.env.CORS_ORIGIN || "";
  if (customAllowed) {
    const list = customAllowed.split(",").map((s) => s.trim().toLowerCase());
    if (list.includes("*") || list.includes(origin.toLowerCase())) {
      return true;
    }
  }
  return false;
};

export function createHttpGateway(gatewayServer: OmniMCPGatewayServer) {
  telemetryManager.initFromDatabase();
  const app = express();

  app.use(
    cors({
      origin: (origin, callback) => {
        // Safe origin validation: never throw an unhandled Error (which crashes or causes 500/502).
        // Returning callback(null, false) standardly suppresses CORS headers for rejected origins.
        if (!origin || isAllowedOrigin(origin)) {
          return callback(null, true);
        }
        log.warn({ origin }, "Blocked unauthorized cross-origin request");
        return callback(null, false);
      },
      methods: ["GET", "POST", "DELETE", "OPTIONS"],
      allowedHeaders: [
        "Content-Type",
        "Authorization",
        "X-OmniMCP-Token",
        "mcp-session-id",
        "mcp-protocol-version",
        "last-event-id",
      ],
      exposedHeaders: ["X-Total-Count", "mcp-session-id"],
      credentials: false,
    })
  );

  app.use(express.json({ limit: "2mb" }));
  app.use(express.static(publicDir));

  // --------------------------------------------------------------------------
  // 1. Official MCP Streamable HTTP Transport (POST, GET, DELETE)
  // --------------------------------------------------------------------------
  app.use("/mcp", createRemoteMcpRouter());

  // Keep track of active SSE sessions
  const sseTransports = new Map<string, SSEServerTransport>();

  // --------------------------------------------------------------------------
  // 1. MCP Streamable HTTP / SSE Transport Endpoints (Agent Only)
  // --------------------------------------------------------------------------
  app.get("/sse", requireAgentAuth, async (req: Request, res: Response): Promise<void> => {
    log.info("Client initiating SSE connection to OmniMCP Gateway");
    const transport = new SSEServerTransport("/message", res);
    const sessionId = transport.sessionId;
    sseTransports.set(sessionId, transport);

    req.on("close", () => {
      log.info({ sessionId }, "SSE connection closed");
      sseTransports.delete(sessionId);
    });

    await gatewayServer.getServer().connect(transport);
  });

  app.post("/message", requireAgentAuth, async (req: Request, res: Response): Promise<void> => {
    const sessionId = typeof req.query.sessionId === "string" ? req.query.sessionId : "";
    const transport = sseTransports.get(sessionId);

    if (!transport) {
      res.status(404).json({ error: `Session '${sessionId}' not found.` });
      return;
    }

    await transport.handlePostMessage(req, res);
  });

  // --------------------------------------------------------------------------
  // 2. Dashboard REST Management APIs
  // --------------------------------------------------------------------------

  // Public Liveness Check (Docker, Kubernetes & Container Healthcheck Probe)
  app.get("/health", (_req: Request, res: Response): void => {
    res.status(200).json({
      status: "ok",
      uptime: Math.floor(process.uptime()),
      timestamp: new Date().toISOString(),
    });
  });

  // Health & Summary (Protected Detailed Diagnostic Report)
  app.get("/api/health", requireAgentOrOperatorAuth, async (_req: Request, res: Response): Promise<void> => {
    const reports = await healthMonitor.checkAllServers();
    res.json({
      status: "healthy",
      version: "1.0.0",
      activeConnections: serverRegistry.getConnectedServers().length,
      reports,
    });
  });

  // Aggregated Execution & System Stats (OPERATOR ONLY)
  app.get("/api/stats", requireOperatorAuth, handleGetStats);
  app.get("/api/telemetry/timeline", requireOperatorAuth, handleGetTelemetryTimeline);
  app.get("/api/dashboard/summary", requireOperatorAuth, handleGetDashboardSummary);

  // Servers Registry Management
  app.get("/api/servers", requireAgentOrOperatorAuth, (_req: Request, res: Response): void => {
    const servers = serverRegistry.getAllServers();
    res.json(servers);
  });

  // Security: Zod schema for updating server settings via HTTP API.
  // Using .strict() ensures any unexpected properties (command, args, cwd, env, transport, etc.) are rejected.
  const UpdateServerSchema = z
    .object({
      id: z
        .string()
        .min(1)
        .max(64)
        .regex(/^[a-zA-Z0-9_-]+$/, "Invalid server id format"),
      enabled: z.boolean().optional(),
      autoConnect: z.boolean().optional(),
      description: z.string().max(512).optional(),
    })
    .strict();

  const PROHIBITED_UPDATE_FIELDS = new Set([
    "command",
    "args",
    "cwd",
    "env",
    "transport",
    "url",
    "headers",
    "allowedPermissions",
    "requiresApprovalForDestructive",
  ]);

  app.post("/api/servers", requireOperatorAuth, async (req: Request, res: Response): Promise<void> => {
    try {
      const body = req.body ?? {};

      // Defense-in-depth: Immediately reject any request attempting to provide or mutate execution parameters
      for (const field of Object.keys(body)) {
        if (PROHIBITED_UPDATE_FIELDS.has(field)) {
          res.status(400).json({
            error: `Security violation: Modifying execution parameter '${field}' via HTTP API is strictly prohibited.`,
          });
          return;
        }
      }

      const parseResult = UpdateServerSchema.safeParse(body);
      if (!parseResult.success) {
        res.status(400).json({
          error: `Invalid server configuration update: ${parseResult.error.issues.map((e) => e.message).join(", ")}`,
        });
        return;
      }

      const { id, enabled, autoConnect, description } = parseResult.data;

      // Only pre-approved servers can be configured
      if (!PRE_APPROVED_SERVER_IDS.has(id)) {
        res.status(403).json({
          error:
            `Arbitrary STDIO server registration is disabled for security. ` +
            `'${id}' is not in the pre-approved server registry. ` +
            `To add custom servers, modify src/registry.ts directly.`,
        });
        return;
      }

      const existing = serverRegistry.getServer(id);
      if (!existing) {
        res.status(404).json({ error: `Server '${id}' not found in registry.` });
        return;
      }

      // Pre-approved server execution settings (command, args, cwd, env) remain strictly immutable.
      const updated = serverRegistry.updateServerSettings(id, {
        enabled,
        autoConnect,
        description,
      });

      log.info({ serverId: id, enabled: updated.enabled, autoConnect: updated.autoConnect }, "Server configuration updated via API");
      res.status(200).json(updated);
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  app.post("/api/servers/:id/connect", requireOperatorAuth, async (req: Request, res: Response): Promise<void> => {
    const serverId = String(req.params.id);
    const s = serverRegistry.getServer(serverId);
    if (!s) {
      res.status(404).json({ error: `Server '${serverId}' not found` });
      return;
    }

    try {
      // Async DNS validation against DNS rebinding prior to outbound connection
      if (s.transport === "http" || s.transport === "sse") {
        await serverRegistry.validateRemoteUrl(s);
      }

      // Dynamic runtime environment synchronization for cloud/container instances
      if (serverId === "github") {
        const ghToken =
          process.env.GITHUB_PERSONAL_ACCESS_TOKEN ||
          process.env.GITHUB_TOKEN ||
          process.env.GH_TOKEN ||
          "";
        if (ghToken) {
          s.env = { ...(s.env || {}), GITHUB_PERSONAL_ACCESS_TOKEN: ghToken, GITHUB_TOKEN: ghToken };
        }
      } else if (serverId === "context7") {
        const ctx7ApiKey = process.env.CONTEXT7_API_KEY || "";
        if (ctx7ApiKey) {
          s.env = { ...(s.env || {}), CONTEXT7_API_KEY: ctx7ApiKey };
        }
      } else if (serverId === "sentry") {
        const sentryToken = process.env.SENTRY_AUTH_TOKEN || process.env.SENTRY_TOKEN || "";
        if (sentryToken) {
          s.env = {
            ...(s.env || {}),
            SENTRY_AUTH_TOKEN: sentryToken,
            SENTRY_TOKEN: sentryToken,
            SENTRY_ORG: process.env.SENTRY_ORG || process.env.SENTRY_ORG_SLUG || "",
            SENTRY_PROJECT: process.env.SENTRY_PROJECT || "",
            SENTRY_HOST: process.env.SENTRY_HOST || "https://sentry.io",
            SENTRY_CLI_NO_PERSISTENCE: "true",
          };
        }
      } else if (serverId === "supabase") {
        const supaUrl = process.env.SUPABASE_URL || "";
        const supaKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY || "";
        if (supaUrl || supaKey) {
          s.env = {
            ...(s.env || {}),
            ...(supaUrl ? { SUPABASE_URL: supaUrl } : {}),
            ...(supaKey ? { SUPABASE_SERVICE_ROLE_KEY: supaKey } : {}),
          };
        }
      }

      await clientManager.connectServer(s);
      const tools = await discoveryEngine.discoverServerTools(serverId);
      res.json({ status: "connected", serverId, toolCount: tools.length });
    } catch (err: any) {
      log.error({ serverId, err: err.message }, "Failed to connect downstream server");
      res.status(500).json({ error: err.message });
    }
  });

  app.post("/api/servers/:id/disconnect", requireOperatorAuth, async (req: Request, res: Response): Promise<void> => {
    const serverId = String(req.params.id);
    try {
      await clientManager.disconnectServer(serverId);
      discoveryEngine.unregisterServerTools(serverId);
      res.json({ status: "disconnected", serverId });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.delete("/api/servers/:id", requireOperatorAuth, async (req: Request, res: Response): Promise<void> => {
    const serverId = String(req.params.id);
    try {
      if (clientManager.isConnected(serverId)) {
        await clientManager.disconnectServer(serverId);
      }
      serverRegistry.removeServer(serverId);
      discoveryEngine.unregisterServerTools(serverId);
      res.json({ status: "removed", serverId });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Tools Exploration & Execution
  app.get("/api/tools", requireAgentOrOperatorAuth, (req: Request, res: Response): void => {
    const query = typeof req.query.q === "string" ? req.query.q : "";
    const serverId = typeof req.query.server === "string" ? req.query.server : undefined;
    const perm = typeof req.query.perm === "string" ? (req.query.perm as PermissionLevel) : undefined;
    const tools = discoveryEngine.searchTools(query, serverId, perm);
    res.json(tools);
  });

  app.post("/api/tools/execute", requireAgentAuth, async (req: Request, res: Response): Promise<void> => {
    const { tool_id, parameters, confirm_sensitive, approval_token } = req.body;
    if (!tool_id) {
      res.status(400).json({ error: "tool_id is required" });
      return;
    }

    const result = await executionEngine.executeTool(tool_id, parameters || {}, {
      confirmSensitive: Boolean(confirm_sensitive),
      approvalToken: typeof approval_token === "string" ? approval_token : undefined,
    });

    res.json(result);
  });

  // --------------------------------------------------------------------------
  // Authenticated Agent Session Endpoints
  // --------------------------------------------------------------------------
  app.post("/api/auth/session", requireAgentAuth, (req: Request, res: Response): void => {
    const parentPrincipal = (req as any).agentPrincipal || "unknown_agent";

    // 1. Sliding window rate limiting: maximum 10 session creations per minute per principal
    const rateCheck = checkSessionCreationRateLimit(parentPrincipal, 10);
    if (!rateCheck.allowed) {
      res.status(429).json({
        error: "Too Many Requests",
        message: `Session creation rate limit exceeded for principal '${parentPrincipal}'. Maximum 10 requests per minute. Retry after ${rateCheck.retryAfterSeconds}s.`,
        retryAfter: rateCheck.retryAfterSeconds,
      });
      return;
    }

    try {
      const targetPrincipal =
        parentPrincipal && parentPrincipal !== "shared_agent_token"
          ? `${parentPrincipal}_${crypto.randomUUID().slice(0, 8)}`
          : undefined;

      // 2. Active session quota per principal: maximum 20 active sessions
      const session = createAgentSession(targetPrincipal, 86400, 20);
      res.status(201).json({
        sessionToken: session.sessionToken,
        principalId: session.principalId,
        expiresAt: session.expiresAt,
      });
    } catch (err: any) {
      if (err instanceof SessionQuotaExceededError) {
        res.status(429).json({
          error: "Too Many Requests",
          message: err.message,
        });
        return;
      }
      res.status(500).json({ error: err.message });
    }
  });

  // --------------------------------------------------------------------------
  // Human Approval Workflow Endpoints
  // --------------------------------------------------------------------------

  // 1. Register a pending approval request (Agent or Operator can request)
  app.post("/api/approvals/request", requireAgentOrOperatorAuth, (req: Request, res: Response): void => {
    try {
      const { toolId, serverId, parameters } = req.body ?? {};
      if (!toolId || typeof toolId !== "string") {
        res.status(400).json({ error: "toolId string is required." });
        return;
      }
      const inferredServer = serverId || (toolId.includes(":") ? toolId.split(":")[0] : "default");
      // Bind approval request strictly to the server-verified principal
      const verifiedPrincipal = (req as any).agentPrincipal || (req as any).operatorIdentity || "unknown";
      const approvalReq = permissionManager.requestApproval(
        toolId,
        inferredServer,
        parameters || {},
        300,
        verifiedPrincipal
      );
      res.status(201).json(approvalReq);
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  // 2. List all approval requests with optional status filter (OPERATOR ONLY)
  app.get("/api/approvals", requireOperatorAuth, handleGetApprovals);

  // 2b. List all pending approval requests (OPERATOR ONLY)
  app.get("/api/approvals/pending", requireOperatorAuth, (_req: Request, res: Response): void => {
    const pending = permissionManager.getPendingApprovals();
    res.json(pending);
  });

  // 3. Inspect a specific approval request (Agent with verified ownership, or Operator with global access)
  app.get("/api/approvals/:id", requireAgentOrOperatorAuth, handleGetApprovalRequest);

  // 4. Explicit human approval — generates the single-use parameter-bound token (OPERATOR ONLY)
  app.post("/api/approvals/:id/approve", requireOperatorAuth, handleApproveRequest);

  // 5. Explicit human rejection (OPERATOR ONLY)
  app.post("/api/approvals/:id/reject", requireOperatorAuth, handleRejectRequest);

  // 6. Approval Audit Log Retrieval (OPERATOR ONLY)
  app.get("/api/approvals/audit", requireOperatorAuth, (req: Request, res: Response): void => {
    const requestId = typeof req.query.requestId === "string" ? req.query.requestId : undefined;
    const limit = typeof req.query.limit === "string" ? parseInt(req.query.limit, 10) : 50;
    const audits = dbManager.queryApprovalAudits(requestId, isNaN(limit) ? 50 : limit);
    res.json(audits);
  });

  // Smart Routing Engine
  app.post("/api/router/match", requireAgentOrOperatorAuth, (req: Request, res: Response): void => {
    const { task } = req.body;
    if (!task) {
      res.status(400).json({ error: "task string is required" });
      return;
    }
    const matched = smartRouter.matchCapabilities(task);
    res.json(matched);
  });

  app.post("/api/router/execute", requireAgentOrOperatorAuth, async (req: Request, res: Response): Promise<void> => {
    const plan = req.body;
    if (!plan || !plan.task || !Array.isArray(plan.steps)) {
      res.status(400).json({ error: "Invalid plan format" });
      return;
    }
    const summary = await smartRouter.executePlan(plan);
    res.json(summary);
  });

  // Execution History & Audit Logs (OPERATOR ONLY)
  app.get("/api/history", requireOperatorAuth, handleGetHistory);
  app.get("/api/history/:traceId", requireOperatorAuth, handleGetHistoryByTraceId);

  // Monitoring Metrics (OPERATOR ONLY)
  app.get("/api/monitoring", requireOperatorAuth, (_req: Request, res: Response): void => {
    const servers = serverRegistry.getAllServers();
    const metrics: Record<string, any> = {};

    for (const s of servers) {
      metrics[s.id] = {
        server: s,
        recentLatency: dbManager.getRecentMetrics(s.id, 20),
      };
    }

    res.json(metrics);
  });

  // Permission Policies
  app.get("/api/permissions", requireAgentOrOperatorAuth, (_req: Request, res: Response): void => {
    const tools = discoveryEngine.getAllTools();
    const permissions = tools.map((t) => ({
      toolId: t.id,
      serverName: t.serverName,
      permissionLevel: t.permissionLevel,
      requiresApproval: t.requiresApproval,
    }));
    res.json(permissions);
  });

  app.post("/api/permissions/override", requireOperatorAuth, (req: Request, res: Response): void => {
    const { tool_id, permission_level, requires_approval, rate_limit_per_minute } = req.body;
    if (!tool_id) {
      res.status(400).json({ error: "tool_id is required" });
      return;
    }

    permissionManager.setPolicyOverride(tool_id, {
      permissionLevel: permission_level,
      requiresApproval: requires_approval,
      rateLimitPerMinute: rate_limit_per_minute,
    });

    res.json({ status: "updated", tool_id });
  });

  // Google Antigravity Client Configuration Generator (OPERATOR ONLY)
  app.get("/api/config/antigravity", requireOperatorAuth, handleGetAntigravityConfig);

  // Gateway Settings & System Diagnostics (OPERATOR ONLY)
  app.get("/api/settings", requireOperatorAuth, handleGetSettings);

  // ============================================================================
  // Profiles Management Endpoints
  // ============================================================================

  app.get("/api/profiles", requireAgentOrOperatorAuth, (_req: Request, res: Response): void => {
    const profiles = profilesManager.listProfiles();
    const active = profilesManager.getActiveProfile();
    res.json({
      profiles,
      activeProfileId: active?.id || null,
      total: profiles.length,
    });
  });

  app.get("/api/profiles/active", requireAgentOrOperatorAuth, (_req: Request, res: Response): void => {
    const active = profilesManager.getActiveProfile();
    if (!active) {
      res.status(404).json({ error: "No active profile found" });
      return;
    }
    res.json(active);
  });

  app.post("/api/profiles/:id/activate", requireAgentOrOperatorAuth, (req: Request, res: Response): void => {
    const id = String(req.params.id);
    const updated = profilesManager.setActiveProfile(id);
    if (!updated) {
      res.status(404).json({ error: `Profile '${id}' not found` });
      return;
    }
    res.json({ status: "activated", profile: updated });
  });

  app.post("/api/profiles", requireOperatorAuth, (req: Request, res: Response): void => {
    try {
      const parsed = CreateProfileSchema.parse(req.body);
      const created = profilesManager.createProfile(parsed);
      res.status(201).json(created);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(400).json({ error: "Invalid profile data", details: msg });
    }
  });

  app.put("/api/profiles/:id", requireOperatorAuth, (req: Request, res: Response): void => {
    try {
      const id = String(req.params.id);
      const parsed = UpdateProfileSchema.parse(req.body);
      const updated = profilesManager.updateProfile(id, parsed);
      if (!updated) {
        res.status(404).json({ error: `Profile '${id}' not found` });
        return;
      }
      res.json(updated);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(400).json({ error: "Invalid profile update", details: msg });
    }
  });

  app.post("/api/profiles/:id/duplicate", requireOperatorAuth, (req: Request, res: Response): void => {
    const id = String(req.params.id);
    const newName = typeof req.body?.name === "string" ? req.body.name : undefined;
    const duplicated = profilesManager.duplicateProfile(id, newName);
    if (!duplicated) {
      res.status(404).json({ error: `Profile '${id}' not found` });
      return;
    }
    res.status(201).json(duplicated);
  });

  app.delete("/api/profiles/:id", requireOperatorAuth, (req: Request, res: Response): void => {
    const id = String(req.params.id);
    const success = profilesManager.deleteProfile(id);
    if (!success) {
      res.status(400).json({ error: `Cannot delete profile '${id}' (profile not found or is default)` });
      return;
    }
    res.json({ status: "deleted", id });
  });

  // ============================================================================
  // Projects & Kanban Tasks Endpoints
  // ============================================================================

  app.get("/api/projects", requireAgentOrOperatorAuth, (_req: Request, res: Response): void => {
    const projects = dbManager.listProjects();
    res.json({ projects, total: projects.length });
  });

  app.post("/api/projects", requireOperatorAuth, (req: Request, res: Response): void => {
    const name = req.body?.name;
    if (!name || typeof name !== "string") {
      res.status(400).json({ error: "Project name is required" });
      return;
    }
    const id = req.body?.id || ("proj_" + crypto.randomBytes(4).toString("hex"));
    const project = dbManager.upsertProject({
      id,
      name: name.trim(),
      description: req.body?.description,
      color: req.body?.color,
    });
    res.status(201).json(project);
  });

  app.delete("/api/projects/:id", requireOperatorAuth, (req: Request, res: Response): void => {
    const id = String(req.params.id);
    const deleted = dbManager.deleteProject(id);
    res.json({ status: deleted ? "deleted" : "not_found", id });
  });

  app.get("/api/tasks", requireAgentOrOperatorAuth, (req: Request, res: Response): void => {
    const filter = {
      projectId: typeof req.query.projectId === "string" ? req.query.projectId : undefined,
      status: typeof req.query.status === "string" ? (req.query.status as TaskStatus) : undefined,
      profileId: typeof req.query.profileId === "string" ? req.query.profileId : undefined,
      integrationId: typeof req.query.integrationId === "string" ? req.query.integrationId : undefined,
    };
    const tasks = dbManager.listTasks(filter);
    res.json({ tasks, total: tasks.length });
  });

  app.get("/api/tasks/:id", requireAgentOrOperatorAuth, (req: Request, res: Response): void => {
    const id = String(req.params.id);
    const task = dbManager.getTask(id);
    if (!task) {
      res.status(404).json({ error: "Task not found" });
      return;
    }
    res.json(task);
  });

  app.post("/api/tasks", requireAgentOrOperatorAuth, (req: Request, res: Response): void => {
    try {
      const parsed = CreateTaskSchema.parse(req.body);
      const id = "task_" + crypto.randomBytes(5).toString("hex");
      const created = dbManager.upsertTask({
        id,
        ...parsed,
      });
      res.status(201).json(created);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(400).json({ error: "Invalid task data", details: msg });
    }
  });

  app.patch("/api/tasks/:id", requireAgentOrOperatorAuth, (req: Request, res: Response): void => {
    try {
      const id = String(req.params.id);
      const existing = dbManager.getTask(id);
      if (!existing) {
        res.status(404).json({ error: "Task not found" });
        return;
      }
      const parsed = UpdateTaskSchema.parse(req.body);

      // If status update only
      if (parsed.status && Object.keys(parsed).length <= 2 && (parsed.position !== undefined || Object.keys(parsed).length === 1)) {
        const updated = dbManager.updateTaskStatus(id, parsed.status, parsed.position);
        res.json(updated);
        return;
      }

      const updated = dbManager.upsertTask({
        id,
        projectId: parsed.projectId !== undefined ? (parsed.projectId || undefined) : existing.projectId,
        title: parsed.title !== undefined ? parsed.title : existing.title,
        description: parsed.description !== undefined ? (parsed.description || undefined) : existing.description,
        status: parsed.status !== undefined ? parsed.status : existing.status,
        priority: parsed.priority !== undefined ? parsed.priority : existing.priority,
        assignee: parsed.assignee !== undefined ? (parsed.assignee || undefined) : existing.assignee,
        dueDate: parsed.dueDate !== undefined ? (parsed.dueDate || undefined) : existing.dueDate,
        profileId: parsed.profileId !== undefined ? (parsed.profileId || undefined) : existing.profileId,
        integrationId: parsed.integrationId !== undefined ? (parsed.integrationId || undefined) : existing.integrationId,
        labels: parsed.labels !== undefined ? parsed.labels : existing.labels,
        checklist: parsed.checklist !== undefined ? parsed.checklist : existing.checklist,
        position: parsed.position !== undefined ? parsed.position : existing.position,
      });

      res.json(updated);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(400).json({ error: "Invalid task update", details: msg });
    }
  });

  app.delete("/api/tasks/:id", requireAgentOrOperatorAuth, (req: Request, res: Response): void => {
    const id = String(req.params.id);
    const deleted = dbManager.deleteTask(id);
    res.json({ status: deleted ? "deleted" : "not_found", id });
  });

  // ============================================================================
  // Agent Tokens & Remote MCP Management Endpoints (OPERATOR ONLY)
  // ============================================================================

  app.get("/api/agent-tokens", requireOperatorAuth, (_req: Request, res: Response): void => {
    res.json(remoteTokenManager.listTokens());
  });

  app.post("/api/agent-tokens", requireOperatorAuth, (req: Request, res: Response): void => {
    try {
      const { principalId, assignedProfileId, name, expiresAt } = req.body || {};
      const result = remoteTokenManager.createToken({ principalId, assignedProfileId, name, expiresAt });
      const { tokenHash: _, ...safeRecord } = result.record;
      res.status(201).json({
        token: result.rawToken,
        record: safeRecord,
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(400).json({ error: msg });
    }
  });

  app.post("/api/agent-tokens/:id/revoke", requireOperatorAuth, (req: Request, res: Response): void => {
    const id = String(req.params.id);
    const success = remoteTokenManager.revokeToken(id);
    if (!success) {
      res.status(404).json({ error: "Token not found" });
      return;
    }
    res.json({ status: "revoked", id });
  });

  app.post("/api/agent-tokens/:id/rotate", requireOperatorAuth, (req: Request, res: Response): void => {
    const id = String(req.params.id);
    const result = remoteTokenManager.rotateToken(id);
    if (!result) {
      res.status(404).json({ error: "Token not found" });
      return;
    }
    const { tokenHash: _, ...safeNewRecord } = result.newRecord;
    res.json({
      token: result.newRawToken,
      record: safeNewRecord,
    });
  });

  app.get("/api/remote-sessions", requireOperatorAuth, (_req: Request, res: Response): void => {
    res.json({
      activeCount: remoteSessionManager.getActiveSessionsCount(),
      sessions: remoteSessionManager.getActiveSessions(),
    });
  });

  // Global unhandled error handler middleware — ensures any unhandled error always returns JSON envelope
  app.use((err: any, _req: Request, res: Response, _next: NextFunction): void => {
    log.error({ err: err?.message || String(err) }, "Unhandled HTTP server error");
    if (!res.headersSent) {
      res.status(err.status || 500).json({ error: err.message || "Internal server error" });
    }
  });

  return app;
}
