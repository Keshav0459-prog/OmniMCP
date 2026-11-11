import { PermissionLevel, DiscoveredTool, ServerState, ServerConfig } from "./types.js";
import { sanitizeData } from "./security.js";
import { createChildLogger } from "./logger.js";
import { dbManager } from "./db.js";
import crypto from "node:crypto";

const log = createChildLogger("permissions");

/**
 * Pre-registered explicit permission catalog for all known standard tools.
 * Eliminates heuristic guesswork for known integrations.
 */
export const KNOWN_TOOL_POLICIES: Record<string, { level: PermissionLevel; requiresApproval: boolean }> = {
  // Filesystem
  "filesystem:read_file": { level: "READ_ONLY", requiresApproval: false },
  "filesystem:read_text_file": { level: "READ_ONLY", requiresApproval: false },
  "filesystem:read_media_file": { level: "READ_ONLY", requiresApproval: false },
  "filesystem:read_multiple_files": { level: "READ_ONLY", requiresApproval: false },
  "filesystem:list_directory": { level: "READ_ONLY", requiresApproval: false },
  "filesystem:list_directory_with_sizes": { level: "READ_ONLY", requiresApproval: false },
  "filesystem:directory_tree": { level: "READ_ONLY", requiresApproval: false },
  "filesystem:search_files": { level: "READ_ONLY", requiresApproval: false },
  "filesystem:get_file_info": { level: "READ_ONLY", requiresApproval: false },
  "filesystem:list_allowed_directories": { level: "READ_ONLY", requiresApproval: false },
  "filesystem:write_file": { level: "WRITE_PROTECTED", requiresApproval: false },
  "filesystem:append_file": { level: "WRITE_PROTECTED", requiresApproval: false },
  "filesystem:edit_file": { level: "WRITE_PROTECTED", requiresApproval: false },
  "filesystem:create_directory": { level: "WRITE_PROTECTED", requiresApproval: false },
  "filesystem:copy_file": { level: "WRITE_PROTECTED", requiresApproval: false },
  "filesystem:move_file": { level: "DESTRUCTIVE_ADMIN", requiresApproval: true },

  // GitHub
  "github:search_repositories": { level: "READ_ONLY", requiresApproval: false },
  "github:get_file_contents": { level: "READ_ONLY", requiresApproval: false },
  "github:list_commits": { level: "READ_ONLY", requiresApproval: false },
  "github:list_issues": { level: "READ_ONLY", requiresApproval: false },
  "github:search_code": { level: "READ_ONLY", requiresApproval: false },
  "github:search_issues": { level: "READ_ONLY", requiresApproval: false },
  "github:search_users": { level: "READ_ONLY", requiresApproval: false },
  "github:get_issue": { level: "READ_ONLY", requiresApproval: false },
  "github:get_pull_request": { level: "READ_ONLY", requiresApproval: false },
  "github:list_pull_requests": { level: "READ_ONLY", requiresApproval: false },
  "github:get_pull_request_files": { level: "READ_ONLY", requiresApproval: false },
  "github:get_pull_request_status": { level: "READ_ONLY", requiresApproval: false },
  "github:get_pull_request_comments": { level: "READ_ONLY", requiresApproval: false },
  "github:get_pull_request_reviews": { level: "READ_ONLY", requiresApproval: false },
  "github:create_or_update_file": { level: "WRITE_PROTECTED", requiresApproval: false },
  "github:create_issue": { level: "WRITE_PROTECTED", requiresApproval: false },
  "github:update_issue": { level: "WRITE_PROTECTED", requiresApproval: false },
  "github:add_issue_comment": { level: "WRITE_PROTECTED", requiresApproval: false },
  "github:create_pull_request": { level: "WRITE_PROTECTED", requiresApproval: false },
  "github:create_branch": { level: "WRITE_PROTECTED", requiresApproval: false },
  "github:fork_repository": { level: "WRITE_PROTECTED", requiresApproval: false },
  "github:create_pull_request_review": { level: "WRITE_PROTECTED", requiresApproval: false },
  "github:update_pull_request_branch": { level: "WRITE_PROTECTED", requiresApproval: false },
  "github:create_repository": { level: "WRITE_PROTECTED", requiresApproval: false },
  "github:push_files": { level: "DESTRUCTIVE_ADMIN", requiresApproval: true },
  "github:merge_pull_request": { level: "DESTRUCTIVE_ADMIN", requiresApproval: true },

  // Supabase
  "supabase:supabase_list_tables": { level: "READ_ONLY", requiresApproval: false },
  "supabase:supabase_query_table": { level: "READ_ONLY", requiresApproval: false },
  "supabase:supabase_list_users": { level: "READ_ONLY", requiresApproval: false },
  "supabase:supabase_insert_record": { level: "WRITE_PROTECTED", requiresApproval: false },
  "supabase:supabase_update_record": { level: "WRITE_PROTECTED", requiresApproval: false },
  "supabase:supabase_execute_rpc": { level: "WRITE_PROTECTED", requiresApproval: false },
  "supabase:supabase_delete_record": { level: "DESTRUCTIVE_ADMIN", requiresApproval: true },

  // Sentry
  "sentry:whoami": { level: "READ_ONLY", requiresApproval: false },
  "sentry:find_issues": { level: "READ_ONLY", requiresApproval: false },
  "sentry:get_issue_details": { level: "READ_ONLY", requiresApproval: false },
  "sentry:find_projects": { level: "READ_ONLY", requiresApproval: false },
  "sentry:find_releases": { level: "READ_ONLY", requiresApproval: false },

  // Playwright
  "playwright:browser_snapshot": { level: "READ_ONLY", requiresApproval: false },
  "playwright:browser_console_messages": { level: "READ_ONLY", requiresApproval: false },
  "playwright:browser_network_requests": { level: "READ_ONLY", requiresApproval: false },
  "playwright:browser_take_screenshot": { level: "READ_ONLY", requiresApproval: false },
  "playwright:browser_tabs": { level: "READ_ONLY", requiresApproval: false },
  "playwright:browser_find": { level: "READ_ONLY", requiresApproval: false },
  "playwright:browser_navigate": { level: "WRITE_PROTECTED", requiresApproval: false },
  "playwright:browser_click": { level: "WRITE_PROTECTED", requiresApproval: false },
  "playwright:browser_type": { level: "WRITE_PROTECTED", requiresApproval: false },
  "playwright:browser_fill_form": { level: "WRITE_PROTECTED", requiresApproval: false },
  "playwright:browser_press_key": { level: "WRITE_PROTECTED", requiresApproval: false },
  "playwright:browser_hover": { level: "WRITE_PROTECTED", requiresApproval: false },
  "playwright:browser_drag": { level: "WRITE_PROTECTED", requiresApproval: false },
  "playwright:browser_drop": { level: "WRITE_PROTECTED", requiresApproval: false },
  "playwright:browser_file_upload": { level: "WRITE_PROTECTED", requiresApproval: false },
  "playwright:browser_select_option": { level: "WRITE_PROTECTED", requiresApproval: false },
  "playwright:browser_resize": { level: "WRITE_PROTECTED", requiresApproval: false },
  "playwright:browser_emulate_media": { level: "WRITE_PROTECTED", requiresApproval: false },
  "playwright:browser_handle_dialog": { level: "WRITE_PROTECTED", requiresApproval: false },
  "playwright:browser_wait_for": { level: "WRITE_PROTECTED", requiresApproval: false },
  "playwright:browser_navigate_back": { level: "WRITE_PROTECTED", requiresApproval: false },
  "playwright:browser_network_request": { level: "WRITE_PROTECTED", requiresApproval: false },
  "playwright:browser_evaluate": { level: "WRITE_PROTECTED", requiresApproval: false },
  "playwright:browser_run_code_unsafe": { level: "DESTRUCTIVE_ADMIN", requiresApproval: true },
  "playwright:browser_close": { level: "DESTRUCTIVE_ADMIN", requiresApproval: true },

  // shadcn
  "shadcn:list_components": { level: "READ_ONLY", requiresApproval: false },
  "shadcn:get_component": { level: "READ_ONLY", requiresApproval: false },
  "shadcn:list_blocks": { level: "READ_ONLY", requiresApproval: false },
  "shadcn:get_block": { level: "READ_ONLY", requiresApproval: false },

  // Context7
  "context7:resolve-library-id": { level: "READ_ONLY", requiresApproval: false },
  "context7:query-docs": { level: "READ_ONLY", requiresApproval: false },
};

const DESTRUCTIVE_KEYWORDS = [
  "delete",
  "remove",
  "drop",
  "truncate",
  "destroy",
  "terminate",
  "kill",
  "exec",
  "shell",
  "eval",
  "purge",
  "overwrite",
  "push_files",
  "delete_record",
  "drop_table",
];

const WRITE_KEYWORDS = [
  "write",
  "append",
  "edit",
  "create",
  "update",
  "patch",
  "post",
  "insert",
  "copy",
  "move",
  "fork",
  "mkdir",
  "fill",
  "click",
  "type",
  "navigate",
];

const READ_KEYWORDS = [
  "read",
  "get",
  "list",
  "search",
  "find",
  "query",
  "inspect",
  "resolve",
  "whoami",
  "snapshot",
  "status",
  "info",
];

export interface PolicyOverride {
  permissionLevel?: PermissionLevel;
  requiresApproval?: boolean;
  rateLimitPerMinute?: number;
}

export interface ApprovalRequest {
  id: string;
  toolId: string;
  serverId: string;
  parameters: Record<string, unknown>;
  paramsHash: string;
  requestedAt: string;
  expiresAt: number;
  status: "pending" | "approved" | "rejected" | "consumed";
  requesterPrincipal: string; // Server-verified principal/session of the requesting agent/operator
  approvedAt?: string;
  approvedBy?: string;
  rejectedAt?: string;
  rejectedBy?: string;
  rejectionReason?: string;
  token?: string;
}

export interface IssuedTokenMetadata {
  requestId: string;
  toolId: string;
  serverId: string;
  paramsHash: string;
  expiresAt: number;
  issuedAt: number;
}

/**
 * Recursively canonicalizes JSON data structures:
 * - Deterministically sorts object keys at all nesting levels.
 * - Preserves array element ordering while canonicalizing elements within.
 * - Preserves primitives (string, number, boolean, null).
 * - Rejects non-JSON types (undefined, function, symbol, BigInt, circular references).
 */
export function canonicalizeJson(value: unknown, seen = new WeakSet<object>()): unknown {
  if (value === null || typeof value === "boolean" || typeof value === "number" || typeof value === "string") {
    return value;
  }
  if (typeof value === "bigint" || typeof value === "symbol" || typeof value === "function" || value === undefined) {
    throw new Error(`Unsupported non-JSON value encountered in parameters: ${typeof value}`);
  }
  if (typeof value === "object") {
    if (seen.has(value)) {
      throw new Error("Circular reference detected in parameters");
    }
    seen.add(value);

    if (Array.isArray(value)) {
      return value.map((item) => canonicalizeJson(item, seen));
    }

    const sortedKeys = Object.keys(value as Record<string, unknown>).sort();
    const result: Record<string, unknown> = {};
    for (const key of sortedKeys) {
      const val = (value as Record<string, unknown>)[key];
      if (val === undefined) continue;
      result[key] = canonicalizeJson(val, seen);
    }
    return result;
  }
  throw new Error(`Unrecognized data type in parameters: ${typeof value}`);
}

export class PermissionManager {
  private policyOverrides: Map<string, PolicyOverride> = new Map();
  private callWindows: Map<string, number[]> = new Map();
  private defaultRateLimitPerMinute = 120;
  private pendingRequests: Map<string, ApprovalRequest> = new Map();
  private activeTokens: Map<string, IssuedTokenMetadata> = new Map();

  /**
   * Classifies a tool's permission tier.
   * Priority:
   * 1. Manual Policy Override
   * 2. Pre-registered Known Tool Catalog
   * 3. Keyword Pattern Matching
   * 4. Safe Default: Unknown tools default to WRITE_PROTECTED with required approval (Never blind READ_ONLY).
   */
  public classifyTool(
    toolName: string,
    description?: string
  ): { level: PermissionLevel; requiresApproval: boolean } {
    const lowerName = toolName.toLowerCase();
    const lowerDesc = (description || "").toLowerCase();

    // 1. Check custom override
    const override = this.policyOverrides.get(toolName);
    if (override && override.permissionLevel) {
      return {
        level: override.permissionLevel,
        requiresApproval: override.requiresApproval ?? (override.permissionLevel === "DESTRUCTIVE_ADMIN"),
      };
    }

    // 2. Check explicit known catalog
    if (KNOWN_TOOL_POLICIES[toolName]) {
      return KNOWN_TOOL_POLICIES[toolName];
    }

    // Also check original name without server prefix
    const bareName = toolName.includes(":") ? toolName.split(":")[1] : toolName;
    for (const [key, policy] of Object.entries(KNOWN_TOOL_POLICIES)) {
      if (key.endsWith(`:${bareName}`)) {
        return policy;
      }
    }

    // 3. Pattern Matching heuristics
    for (const kw of DESTRUCTIVE_KEYWORDS) {
      if (lowerName.includes(kw) || lowerDesc.includes(`permanently ${kw}`)) {
        return { level: "DESTRUCTIVE_ADMIN", requiresApproval: true };
      }
    }

    for (const kw of WRITE_KEYWORDS) {
      if (lowerName.includes(kw)) {
        return { level: "WRITE_PROTECTED", requiresApproval: false };
      }
    }

    for (const kw of READ_KEYWORDS) {
      if (lowerName.startsWith(kw) || lowerName.includes(`_${kw}`) || lowerName.includes(`-${kw}`)) {
        return { level: "READ_ONLY", requiresApproval: false };
      }
    }

    // 4. Safe Default-Deny / Cautious Default:
    // Unknown tools are treated as WRITE_PROTECTED and require approval.
    log.warn(
      { toolName },
      "Unknown tool encountered without explicit policy or keywords. Defaulting to WRITE_PROTECTED with approval required."
    );
    return { level: "WRITE_PROTECTED", requiresApproval: true };
  }

  public computeParamsHash(parameters?: Record<string, unknown>): string {
    if (!parameters || Object.keys(parameters).length === 0) {
      return "empty";
    }
    const canonical = canonicalizeJson(parameters);
    return crypto.createHash("sha256").update(JSON.stringify(canonical)).digest("hex");
  }

  /**
   * Registers a pending human approval request.
   * Does NOT generate an approval token. The token is only issued after an explicit
   * authenticated human approval action.
   */
  public requestApproval(
    toolId: string,
    serverId: string,
    parameters: Record<string, unknown> = {},
    ttlSeconds = 300,
    requesterPrincipal = "unknown"
  ): ApprovalRequest {
    const id = crypto.randomUUID();
    const paramsHash = this.computeParamsHash(parameters);
    const now = Date.now();
    const req: ApprovalRequest = {
      id,
      toolId,
      serverId,
      parameters,
      paramsHash,
      requestedAt: new Date(now).toISOString(),
      expiresAt: now + ttlSeconds * 1000,
      status: "pending",
      requesterPrincipal,
    };
    this.pendingRequests.set(id, req);
    log.info({ requestId: id, toolId, serverId, requesterPrincipal }, "Human approval request registered");

    dbManager.insertApprovalAudit({
      id: crypto.randomUUID(),
      requestId: id,
      eventType: "approval_requested",
      toolId,
      serverId,
      paramsHash,
      operatorIdentity: requesterPrincipal,
      timestamp: req.requestedAt,
      status: "pending",
      details: { parameters, requesterPrincipal },
    });

    return req;
  }

  /**
   * Lists all active pending approval requests for human review.
   */
  public getPendingApprovals(): ApprovalRequest[] {
    const now = Date.now();
    const result: ApprovalRequest[] = [];
    for (const req of this.pendingRequests.values()) {
      if (req.status === "pending" && req.expiresAt > now) {
        result.push(req);
      }
    }
    return result;
  }

  /**
   * Lists approval requests for human operator review with optional status filtering.
   * Parameter values are sanitized, and raw approval tokens are strictly omitted.
   */
  public getAllApprovals(statusFilter?: string): ApprovalRequest[] {
    const now = Date.now();
    const result: ApprovalRequest[] = [];
    for (const req of this.pendingRequests.values()) {
      let effectiveStatus = req.status;
      if (req.status === "pending" && req.expiresAt <= now) {
        effectiveStatus = "expired" as any;
      }
      if (!statusFilter || statusFilter === "all" || effectiveStatus === statusFilter) {
        result.push({
          ...req,
          parameters: sanitizeData(req.parameters) as Record<string, unknown>,
          status: effectiveStatus as any,
          token: undefined, // Never expose raw approval tokens to dashboard
        });
      }
    }
    // Reverse first so equal timestamps maintain reverse-insertion order (newest created first)
    return result.reverse().sort((a, b) => new Date(b.requestedAt).getTime() - new Date(a.requestedAt).getTime());
  }

  /**
   * Retrieves an approval request by its ID.
   */
  public getApprovalRequest(id: string): ApprovalRequest | undefined {
    return this.pendingRequests.get(id);
  }

  /**
   * Explicit human approval of a pending request.
   * Generates a cryptographically secure, parameter-bound, single-use token.
   */
  public approveRequest(
    requestId: string,
    humanUser = "authenticated_human"
  ): { request: ApprovalRequest; token: string } {
    const req = this.pendingRequests.get(requestId);
    if (!req) {
      throw new Error(`Approval request '${requestId}' not found`);
    }
    if (Date.now() > req.expiresAt) {
      req.status = "rejected";
      req.rejectionReason = "Expired before approval";
      throw new Error(`Approval request '${requestId}' has expired`);
    }
    if (req.status !== "pending") {
      throw new Error(`Approval request '${requestId}' is already ${req.status}`);
    }

    const token = `omnimcp_appr_${crypto.randomBytes(32).toString("hex")}`;
    req.status = "approved";
    req.approvedAt = new Date().toISOString();
    req.approvedBy = humanUser;
    req.token = token;

    this.activeTokens.set(token, {
      requestId: req.id,
      toolId: req.toolId,
      serverId: req.serverId,
      paramsHash: req.paramsHash,
      expiresAt: req.expiresAt,
      issuedAt: Date.now(),
    });

    dbManager.insertApprovalAudit({
      id: crypto.randomUUID(),
      requestId,
      eventType: "approval_approved",
      toolId: req.toolId,
      serverId: req.serverId,
      paramsHash: req.paramsHash,
      operatorIdentity: humanUser,
      timestamp: req.approvedAt!,
      status: "approved",
    });

    log.info({ requestId, toolId: req.toolId, humanUser }, "Approval granted by authenticated operator");
    return { request: req, token };
  }

  /**
   * Explicit human rejection of a pending approval request.
   */
  public rejectRequest(
    requestId: string,
    humanUser = "authenticated_human",
    reason = "Rejected by operator"
  ): ApprovalRequest {
    const req = this.pendingRequests.get(requestId);
    if (!req) {
      throw new Error(`Approval request '${requestId}' not found`);
    }

    req.status = "rejected";
    req.rejectedAt = new Date().toISOString();
    req.rejectedBy = humanUser;
    req.rejectionReason = reason;

    if (req.token) {
      this.activeTokens.delete(req.token);
      req.token = undefined;
    }

    dbManager.insertApprovalAudit({
      id: crypto.randomUUID(),
      requestId,
      eventType: "approval_rejected",
      toolId: req.toolId,
      serverId: req.serverId,
      paramsHash: req.paramsHash,
      operatorIdentity: humanUser,
      timestamp: req.rejectedAt!,
      status: "rejected",
      details: { reason },
    });

    log.warn({ requestId, toolId: req.toolId, reason, humanUser }, "Approval request rejected by operator");
    return req;
  }

  /**
   * Issues a cryptographically random, parameter-bound, time-bounded approval token directly (e.g. for testing).
   */
  public issueApprovalToken(
    toolId: string,
    parameters?: Record<string, unknown>,
    ttlSeconds = 120,
    serverId = "default"
  ): string {
    const token = `omnimcp_appr_${crypto.randomBytes(32).toString("hex")}`;
    const paramsHash = this.computeParamsHash(parameters);
    const expiresAt = Date.now() + ttlSeconds * 1000;
    this.activeTokens.set(token, {
      requestId: crypto.randomUUID(),
      toolId,
      serverId,
      paramsHash,
      expiresAt,
      issuedAt: Date.now(),
    });
    return token;
  }

  /**
   * Verifies and consumes a one-time approval token against tool ID, server ID, and exact parameters.
   */
  public consumeApprovalToken(
    token: string,
    toolId: string,
    serverIdOrParams?: string | Record<string, unknown>,
    parameters?: Record<string, unknown>
  ): { valid: boolean; reason?: string } {
    let serverId: string | undefined;
    let actualParams: Record<string, unknown> | undefined;

    if (typeof serverIdOrParams === "string") {
      serverId = serverIdOrParams;
      actualParams = parameters;
    } else if (typeof serverIdOrParams === "object" && serverIdOrParams !== null) {
      actualParams = serverIdOrParams as Record<string, unknown>;
      serverId = undefined;
    } else {
      actualParams = parameters;
    }

    const approval = this.activeTokens.get(token);
    if (!approval) {
      dbManager.insertApprovalAudit({
        id: crypto.randomUUID(),
        requestId: "unknown",
        eventType: "approval_failed",
        toolId,
        serverId: serverId || "unknown",
        paramsHash: "unknown",
        timestamp: new Date().toISOString(),
        status: "failed",
        details: { reason: "Invalid or already consumed approval token" },
      });
      return { valid: false, reason: "Invalid or already consumed approval token" };
    }

    // Single-use: delete immediately to prevent replay attacks
    this.activeTokens.delete(token);

    if (Date.now() > approval.expiresAt) {
      dbManager.insertApprovalAudit({
        id: crypto.randomUUID(),
        requestId: approval.requestId,
        eventType: "approval_failed",
        toolId,
        serverId: serverId || approval.serverId,
        paramsHash: approval.paramsHash,
        timestamp: new Date().toISOString(),
        status: "failed",
        details: { reason: "Approval token has expired" },
      });
      return { valid: false, reason: "Approval token has expired" };
    }

    if (approval.toolId !== toolId) {
      dbManager.insertApprovalAudit({
        id: crypto.randomUUID(),
        requestId: approval.requestId,
        eventType: "approval_failed",
        toolId,
        serverId: serverId || approval.serverId,
        paramsHash: approval.paramsHash,
        timestamp: new Date().toISOString(),
        status: "failed",
        details: { reason: `Tool mismatch: issued for '${approval.toolId}', called '${toolId}'` },
      });
      return {
        valid: false,
        reason: `Approval token tool mismatch (issued for '${approval.toolId}', called '${toolId}')`,
      };
    }

    if (serverId && approval.serverId !== "default" && approval.serverId !== serverId) {
      dbManager.insertApprovalAudit({
        id: crypto.randomUUID(),
        requestId: approval.requestId,
        eventType: "approval_failed",
        toolId,
        serverId,
        paramsHash: approval.paramsHash,
        timestamp: new Date().toISOString(),
        status: "failed",
        details: { reason: `Server mismatch: issued for '${approval.serverId}', called '${serverId}'` },
      });
      return {
        valid: false,
        reason: `Approval token server mismatch (issued for '${approval.serverId}', called '${serverId}')`,
      };
    }

    // Verify parameter integrity (tamper-resistance)
    let currentHash: string;
    try {
      currentHash = this.computeParamsHash(actualParams);
    } catch (err: any) {
      dbManager.insertApprovalAudit({
        id: crypto.randomUUID(),
        requestId: approval.requestId,
        eventType: "approval_failed",
        toolId,
        serverId: serverId || approval.serverId,
        paramsHash: approval.paramsHash,
        timestamp: new Date().toISOString(),
        status: "failed",
        details: { reason: `Parameter canonicalization error: ${err.message}` },
      });
      return { valid: false, reason: `Parameter canonicalization error: ${err.message}` };
    }

    if (approval.paramsHash !== currentHash) {
      dbManager.insertApprovalAudit({
        id: crypto.randomUUID(),
        requestId: approval.requestId,
        eventType: "approval_failed",
        toolId,
        serverId: serverId || approval.serverId,
        paramsHash: currentHash,
        timestamp: new Date().toISOString(),
        status: "failed",
        details: { reason: "Parameter tampering detected", expectedHash: approval.paramsHash, actualHash: currentHash },
      });
      return {
        valid: false,
        reason: "Parameter tampering detected: execution parameters do not match approved parameters",
      };
    }

    const matchingReq = this.pendingRequests.get(approval.requestId);
    if (matchingReq) {
      matchingReq.status = "consumed";
      matchingReq.token = undefined;
    }

    dbManager.insertApprovalAudit({
      id: crypto.randomUUID(),
      requestId: approval.requestId,
      eventType: "approval_consumed",
      toolId,
      serverId: serverId || approval.serverId,
      paramsHash: approval.paramsHash,
      timestamp: new Date().toISOString(),
      status: "consumed",
    });

    return { valid: true };
  }

  /**
   * Cleans up expired pending approval requests and unconsumed tokens from memory.
   * Records approval_expired events in database for expired pending requests.
   */
  public cleanupExpired(): { expiredRequests: number; expiredTokens: number } {
    const now = Date.now();
    let expiredRequests = 0;
    let expiredTokens = 0;

    for (const [id, req] of this.pendingRequests.entries()) {
      if (req.status === "pending" && now > req.expiresAt) {
        req.status = "rejected";
        req.rejectionReason = "Expired before approval";
        req.rejectedAt = new Date(now).toISOString();

        dbManager.insertApprovalAudit({
          id: crypto.randomUUID(),
          requestId: id,
          eventType: "approval_expired",
          toolId: req.toolId,
          serverId: req.serverId,
          paramsHash: req.paramsHash,
          timestamp: req.rejectedAt,
          status: "expired",
        });

        this.pendingRequests.delete(id);
        expiredRequests++;
      }
    }

    for (const [token, meta] of this.activeTokens.entries()) {
      if (now > meta.expiresAt) {
        this.activeTokens.delete(token);
        expiredTokens++;
      }
    }

    return { expiredRequests, expiredTokens };
  }

  public checkRateLimit(toolId: string): { allowed: boolean; retryAfterSeconds?: number } {
    const rateLimit = this.getToolRateLimit(toolId);
    const now = Date.now();
    const windowStart = now - 60000;

    let timestamps = this.callWindows.get(toolId) || [];
    timestamps = timestamps.filter((t) => t > windowStart);

    if (timestamps.length >= rateLimit) {
      const oldest = timestamps[0] || now;
      const retryAfterSeconds = Math.max(1, Math.ceil((oldest + 60000 - now) / 1000));
      return { allowed: false, retryAfterSeconds };
    }

    timestamps.push(now);
    this.callWindows.set(toolId, timestamps);
    return { allowed: true };
  }

  public setPolicyOverride(toolId: string, override: PolicyOverride): void {
    this.policyOverrides.set(toolId, override);
    log.info({ toolId, policy: override }, "Policy override set for tool");
  }

  public checkExecutionAllowed(
    tool: DiscoveredTool,
    serverState: ServerConfig | ServerState,
    _confirmSensitive?: boolean,
    approvalToken?: string,
    parameters?: Record<string, unknown>
  ): { allowed: boolean; reason?: string; requiresHumanApproval?: boolean; approvalPrompt?: unknown } {
    // 1. Check server-level enabled status
    if (serverState.enabled === false) {
      return { allowed: false, reason: `Downstream server '${serverState.id}' is disabled in configuration.` };
    }

    // 2. Check server-level allowed permissions
    if (
      serverState.allowedPermissions &&
      !serverState.allowedPermissions.includes(tool.permissionLevel)
    ) {
      return {
        allowed: false,
        reason: `Tool permission tier '${tool.permissionLevel}' is not permitted by server '${serverState.id}' policy.`,
      };
    }

    // 3. Approval gate for sensitive / destructive actions
    // Strict Human Approval Integrity:
    // Read-only tools NEVER require approval.
    // DESTRUCTIVE_ADMIN tools and tools classified with requiresApproval: true MUST have explicit human approval.
    // An AI-generated 'confirm_sensitive: true' boolean CANNOT bypass human approval!
    const isDestructive = tool.permissionLevel === "DESTRUCTIVE_ADMIN";
    const needsApproval =
      tool.requiresApproval ||
      (isDestructive && serverState.requiresApprovalForDestructive !== false);

    if (needsApproval) {
      if (!approvalToken) {
        // Auto-register pending approval request so human operator can see it in dashboard
        const pendingReq = this.requestApproval(tool.id, serverState.id, parameters || {});
        return {
          allowed: false,
          requiresHumanApproval: true,
          reason: `Tool '${tool.id}' is classified as ${tool.permissionLevel} and requires explicit human approval. AI-generated 'confirm_sensitive' flag is rejected. Approval request '${pendingReq.id}' has been registered. An authenticated human operator must approve this request at /api/approvals/${pendingReq.id}/approve to obtain an approval token.`,
          approvalPrompt: {
            requestId: pendingReq.id,
            toolId: tool.id,
            serverId: serverState.id,
            parameters,
            expiresAt: pendingReq.expiresAt,
          },
        };
      }

      const tokenCheck = this.consumeApprovalToken(approvalToken, tool.id, serverState.id, parameters);
      if (!tokenCheck.valid) {
        return {
          allowed: false,
          reason: `Human approval verification failed for '${tool.id}': ${tokenCheck.reason}`,
        };
      }
    }

    // 4. Rate limiting check (sliding window)
    const rateCheck = this.checkRateLimit(tool.id);
    if (!rateCheck.allowed) {
      const rateLimit = this.getToolRateLimit(tool.id);
      log.warn({ toolId: tool.id, rateLimit }, "Rate limit exceeded for tool");
      return {
        allowed: false,
        reason: `Rate limit exceeded for tool '${tool.id}'. Maximum ${rateLimit} calls per minute. Retry after ${rateCheck.retryAfterSeconds}s.`,
      };
    }

    return { allowed: true };
  }

  public clearApprovals(): void {
    this.pendingRequests.clear();
    this.activeTokens.clear();
  }

  private getToolRateLimit(toolId: string): number {
    const override = this.policyOverrides.get(toolId);
    if (override && typeof override.rateLimitPerMinute === "number") {
      return override.rateLimitPerMinute;
    }
    return this.defaultRateLimitPerMinute;
  }
}

export const permissionManager = new PermissionManager();
