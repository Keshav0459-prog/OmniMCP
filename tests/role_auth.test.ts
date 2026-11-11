import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  requireOperatorAuth,
  requireAgentAuth,
  requireAgentOrOperatorAuth,
  handleGetApprovalRequest,
  createAgentSession,
  clearAllAgentSessions,
  revokeAgentSession,
  getAgentSession,
  resolveAgentPrincipal,
  hashSessionToken,
  isRawTokenInSessionMap,
  getActiveSessionCount,
  checkSessionCreationRateLimit,
  clearSessionRateLimits,
  SessionQuotaExceededError,
  cleanupExpiredAgentSessions,
  startSessionCleanupTimer,
  stopSessionCleanupTimer,
  isCleanupTimerActive,
} from "../src/http-gateway.js";
import { permissionManager } from "../src/permissions.js";
import { dbManager } from "../src/db.js";
import { buildChildEnvironment, BANNED_RESERVED_SECRETS } from "../src/client-manager.js";

function runMiddleware(
  middleware: (req: any, res: any, next: any) => void | Promise<void>,
  options: {
    headers?: Record<string, string>;
    query?: Record<string, string>;
    body?: any;
    params?: Record<string, string>;
  } = {}
) {
  let statusCode = 200;
  let responseData: any = null;
  let nextCalled = false;

  const req: any = {
    headers: options.headers || {},
    query: options.query || {},
    body: options.body || {},
    params: options.params || {},
  };

  const res: any = {
    status(code: number) {
      statusCode = code;
      return res;
    },
    json(data: any) {
      responseData = data;
      return res;
    },
    send(data: any) {
      responseData = data;
      return res;
    },
  };

  const next = () => {
    nextCalled = true;
  };

  middleware(req, res, next);

  return {
    status: statusCode,
    body: responseData,
    nextCalled,
    req,
  };
}

function executeApprovalPipeline(
  options: {
    headers?: Record<string, string>;
    query?: Record<string, string>;
    params?: Record<string, string>;
    body?: any;
  } = {}
) {
  const authRes = runMiddleware(requireAgentOrOperatorAuth, options);
  if (!authRes.nextCalled) {
    return authRes;
  }
  let handlerStatus = 200;
  let handlerData: any = null;
  const res: any = {
    status(code: number) {
      handlerStatus = code;
      return res;
    },
    json(data: any) {
      handlerData = data;
      return res;
    },
    send(data: any) {
      handlerData = data;
      return res;
    },
  };
  handleGetApprovalRequest(authRes.req, res);
  return {
    status: handlerStatus,
    body: handlerData,
    req: authRes.req,
  };
}

describe("Phase 2.2 — Role-Separated Authentication & Trust Boundaries", () => {
  const AGENT_SECRET = "omnimcp_agent_test_secret_1234567890abcdef";
  const OPERATOR_SECRET = "omnimcp_operator_test_secret_0987654321fedcba";

  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    originalEnv = { ...process.env };
    process.env.OMNIMCP_AGENT_TOKEN = AGENT_SECRET;
    process.env.OMNIMCP_OPERATOR_TOKEN = OPERATOR_SECRET;
    delete process.env.OMNIMCP_AUTH_TOKEN;

    permissionManager.clearApprovals();
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it("should enforce fail-closed behavior when credentials are missing", () => {
    delete process.env.OMNIMCP_OPERATOR_TOKEN;
    delete process.env.OMNIMCP_AGENT_TOKEN;
    delete process.env.OMNIMCP_AUTH_TOKEN;

    // Operator endpoint without configured secret
    const opResult = runMiddleware(requireOperatorAuth, {
      headers: { authorization: `Bearer ${OPERATOR_SECRET}` },
    });
    expect(opResult.status).toBe(500);
    expect(opResult.body.error).toBe("Server misconfiguration");
    expect(opResult.nextCalled).toBe(false);

    // Agent execution endpoint without configured secret
    const agentResult = runMiddleware(requireAgentAuth, {
      headers: { authorization: `Bearer ${AGENT_SECRET}` },
    });
    expect(agentResult.status).toBe(500);
    expect(agentResult.body.error).toBe("Server misconfiguration");
    expect(agentResult.nextCalled).toBe(false);
  });

  it("should reject requests with missing or invalid tokens", () => {
    // Missing token on operator route
    const missingOp = runMiddleware(requireOperatorAuth);
    expect(missingOp.status).toBe(401);
    expect(missingOp.nextCalled).toBe(false);

    // Missing token on agent route
    const missingAgent = runMiddleware(requireAgentAuth);
    expect(missingAgent.status).toBe(401);
    expect(missingAgent.nextCalled).toBe(false);

    // Invalid token on operator route
    const invalidOp = runMiddleware(requireOperatorAuth, {
      headers: { authorization: "Bearer invalid_secret_token" },
    });
    expect(invalidOp.status).toBe(403);
    expect(invalidOp.nextCalled).toBe(false);

    // Invalid token on agent route
    const invalidAgent = runMiddleware(requireAgentAuth, {
      headers: { authorization: "Bearer invalid_secret_token" },
    });
    expect(invalidAgent.status).toBe(403);
    expect(invalidAgent.nextCalled).toBe(false);
  });

  it("should strictly block an agent token from accessing operator endpoints (CRITICAL BOUNDARY)", () => {
    // Agent attempts to access operator-only route with valid Agent Token
    const result = runMiddleware(requireOperatorAuth, {
      headers: { authorization: `Bearer ${AGENT_SECRET}` },
    });

    expect(result.status).toBe(403);
    expect(result.nextCalled).toBe(false);
    expect(result.body.message).toContain("Agent credentials cannot access human operator approval endpoints");
  });

  it("should reject forged admin headers and derive operator identity only from verified operator auth", () => {
    // Agent sends forged x-omnimcp-user: super_admin with its agent token
    const attackResult = runMiddleware(requireOperatorAuth, {
      headers: {
        authorization: `Bearer ${AGENT_SECRET}`,
        "x-omnimcp-user": "super_admin",
      },
    });
    expect(attackResult.status).toBe(403);
    expect(attackResult.nextCalled).toBe(false);

    // Legitimate operator with forged header
    const legitimateResult = runMiddleware(requireOperatorAuth, {
      headers: {
        authorization: `Bearer ${OPERATOR_SECRET}`,
        "x-omnimcp-user": "some_arbitrary_untrusted_header_username",
      },
    });
    expect(legitimateResult.status).toBe(200);
    expect(legitimateResult.nextCalled).toBe(true);
    // Identity must be derived from token verification, NEVER the client header
    expect(legitimateResult.req.operatorIdentity).toBe("authenticated_operator");
    expect(legitimateResult.req.operatorIdentity).not.toContain("arbitrary");
  });

  it("should block operator token from directly invoking agent-only execution endpoints", () => {
    // Operator attempts to execute tools directly using Operator Token
    const result = runMiddleware(requireAgentAuth, {
      headers: { authorization: `Bearer ${OPERATOR_SECRET}` },
    });

    expect(result.status).toBe(403);
    expect(result.nextCalled).toBe(false);
    expect(result.body.message).toContain("Operator credentials cannot directly invoke agent-only execution endpoints");
  });

  it("should allow either role on shared catalog and inspection endpoints", () => {
    // Agent token on shared endpoint
    const agentAccess = runMiddleware(requireAgentOrOperatorAuth, {
      headers: { authorization: `Bearer ${AGENT_SECRET}` },
    });
    expect(agentAccess.status).toBe(200);
    expect(agentAccess.nextCalled).toBe(true);
    expect(agentAccess.req.role).toBe("agent");

    // Operator token on shared endpoint
    const operatorAccess = runMiddleware(requireAgentOrOperatorAuth, {
      headers: { authorization: `Bearer ${OPERATOR_SECRET}` },
    });
    expect(operatorAccess.status).toBe(200);
    expect(operatorAccess.nextCalled).toBe(true);
    expect(operatorAccess.req.role).toBe("operator");
  });

  it("should simulate full lifecycle: Agent requests -> Agent self-approval fails -> Operator approves -> Audit persists", () => {
    const params = { target: "system32", action: "format" };

    // 1. Agent registers approval request
    const req = permissionManager.requestApproval("fs:delete_file", "filesystem", params);
    expect(req.status).toBe("pending");

    // 2. Attack: Agent attempts to approve with agent token (via middleware check)
    const agentApprovalAttempt = runMiddleware(requireOperatorAuth, {
      headers: { authorization: `Bearer ${AGENT_SECRET}` },
    });
    expect(agentApprovalAttempt.status).toBe(403);
    expect(agentApprovalAttempt.nextCalled).toBe(false);

    // 3. Request remains pending
    const pendingReq = permissionManager.getApprovalRequest(req.id);
    expect(pendingReq?.status).toBe("pending");
    expect(pendingReq?.token).toBeUndefined();

    // 4. Operator legitimately approves
    const operatorCheck = runMiddleware(requireOperatorAuth, {
      headers: { authorization: `Bearer ${OPERATOR_SECRET}` },
    });
    expect(operatorCheck.status).toBe(200);
    expect(operatorCheck.nextCalled).toBe(true);

    const { token } = permissionManager.approveRequest(req.id, operatorCheck.req.operatorIdentity);
    expect(token).toBeDefined();

    // 5. Audit logs verify operator identity was correctly recorded
    const audits = dbManager.queryApprovalAudits(req.id);
    const approvedEvent = audits.find((e) => e.eventType === "approval_approved");
    expect(approvedEvent).toBeDefined();
    expect(approvedEvent?.operatorIdentity).toBe("authenticated_operator");

    // 6. Token consumption succeeds with exact parameters
    const consumeRes = permissionManager.consumeApprovalToken(token, "fs:delete_file", "filesystem", params);
    expect(consumeRes.valid).toBe(true);

    // 7. Token replay fails
    const replayRes = permissionManager.consumeApprovalToken(token, "fs:delete_file", "filesystem", params);
    expect(replayRes.valid).toBe(false);
  });

  it("should persist approval audit events to SQLite database", () => {
    const params = { db_name: "prod_users", drop: true };
    const req = permissionManager.requestApproval("db:drop_table", "postgres", params, 300);

    // 1. Verify approval_requested audit record
    let logs = dbManager.queryApprovalAudits(req.id);
    expect(logs.length).toBe(1);
    expect(logs[0].eventType).toBe("approval_requested");
    expect(logs[0].toolId).toBe("db:drop_table");
    expect(logs[0].serverId).toBe("postgres");

    // 2. Approve request
    const { token } = permissionManager.approveRequest(req.id, "verified_human");
    logs = dbManager.queryApprovalAudits(req.id);
    expect(logs.length).toBe(2);
    const approvedLog = logs.find((l) => l.eventType === "approval_approved");
    expect(approvedLog).toBeDefined();
    expect(approvedLog?.operatorIdentity).toBe("verified_human");

    // 3. Consume token
    const consumeRes = permissionManager.consumeApprovalToken(token, "db:drop_table", "postgres", params);
    expect(consumeRes.valid).toBe(true);
    logs = dbManager.queryApprovalAudits(req.id);
    expect(logs.length).toBe(3);
    const consumedLog = logs.find((l) => l.eventType === "approval_consumed");
    expect(consumedLog).toBeDefined();

    // 4. Replay attempt should fail
    const replayRes = permissionManager.consumeApprovalToken(token, "db:drop_table", "postgres", params);
    expect(replayRes.valid).toBe(false);
  });

  it("should clean up expired pending requests and record audit logs", async () => {
    const req = permissionManager.requestApproval("fs:delete", "fs", { target: "tmp" }, 1);
    expect(permissionManager.getPendingApprovals().length).toBe(1);

    // Sleep 1100ms so it expires
    await new Promise((r) => setTimeout(r, 1100));

    // Run cleanup
    const cleanup = permissionManager.cleanupExpired();
    expect(cleanup.expiredRequests).toBe(1);

    // Pending list should now be 0
    expect(permissionManager.getPendingApprovals().length).toBe(0);

    // Audit log should record approval_expired
    const logs = dbManager.queryApprovalAudits(req.id);
    expect(logs.some((l) => l.eventType === "approval_expired")).toBe(true);
  });

  it("should strictly ban customEnv from overriding reserved secrets in child processes", () => {
    const maliciousCustomEnv: Record<string, string> = {
      OMNIMCP_ENCRYPTION_KEY: "malicious_override_key",
      OMNIMCP_AUTH_TOKEN: "malicious_override_token",
      OMNIMCP_AGENT_TOKEN: "malicious_agent_token",
      OMNIMCP_OPERATOR_TOKEN: "malicious_operator_token",
      DATABASE_URL: "postgres://attacker:stolen@evil.com/db",
      AWS_SECRET_ACCESS_KEY: "malicious_aws_key",
      STRIPE_SECRET_KEY: "malicious_stripe_key",
      ALLOWED_CUSTOM_VAR: "legitimate_custom_value",
    };

    const childEnv = buildChildEnvironment(maliciousCustomEnv);

    // All reserved secrets must be stripped
    for (const secretKey of BANNED_RESERVED_SECRETS) {
      expect(childEnv[secretKey]).toBeUndefined();
      expect(childEnv[secretKey.toLowerCase()]).toBeUndefined();
    }

    // Legitimate custom vars must remain
    expect(childEnv.ALLOWED_CUSTOM_VAR).toBe("legitimate_custom_value");
    expect(childEnv.PATH).toBeDefined();
  });
});

describe("Phase 2.3 — Cross-Agent Approval Isolation & Dashboard Session Hardening", () => {
  const MASTER_AGENT_TOKEN = "omnimcp_agent_master_secret_1122334455";
  const OPERATOR_TOKEN = "omnimcp_operator_master_secret_9988776655";

  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    originalEnv = { ...process.env };
    process.env.OMNIMCP_AGENT_TOKEN = MASTER_AGENT_TOKEN;
    process.env.OMNIMCP_OPERATOR_TOKEN = OPERATOR_TOKEN;
    delete process.env.OMNIMCP_AUTH_TOKEN;
    delete process.env.OMNIMCP_AGENT_TOKENS;

    permissionManager.clearApprovals();
    clearAllAgentSessions();
  });

  afterEach(() => {
    process.env = originalEnv;
    clearAllAgentSessions();
  });

  it("should reject URL-based operator authentication via query parameters", () => {
    // 1. Query parameter token must be rejected by operator auth
    const opQueryRes = runMiddleware(requireOperatorAuth, {
      query: { token: OPERATOR_TOKEN },
    });
    expect(opQueryRes.status).toBe(401);
    expect(opQueryRes.body.error).toBe("Unauthorized");
    expect(opQueryRes.nextCalled).toBe(false);

    // 2. Query parameter operator_token must also be rejected
    const opParamRes = runMiddleware(requireOperatorAuth, {
      query: { operator_token: OPERATOR_TOKEN },
    });
    expect(opParamRes.status).toBe(401);
    expect(opParamRes.nextCalled).toBe(false);

    // 3. Header-based authorization must still succeed
    const opHeaderRes = runMiddleware(requireOperatorAuth, {
      headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
    });
    expect(opHeaderRes.status).toBe(200);
    expect(opHeaderRes.nextCalled).toBe(true);
  });

  it("should prevent Agent A from inspecting Agent B's approval request", () => {
    // Issue server-validated sessions for two separate agents
    const sessionA = createAgentSession("agent_alpha_corp");
    const sessionB = createAgentSession("agent_beta_corp");

    // Agent B creates a sensitive approval request
    const reqB = permissionManager.requestApproval(
      "database:drop_schema",
      "postgres",
      { schema: "beta_production" },
      300,
      sessionB.principalId
    );

    // Agent A attempts to inspect Agent B's approval request using Agent A's session token
    const inspectionRes = executeApprovalPipeline({
      headers: { authorization: `Bearer ${sessionA.sessionToken}` },
      params: { id: reqB.id },
    });

    expect(inspectionRes.status).toBe(403);
    expect(inspectionRes.body.error).toBe("Forbidden");
    expect(inspectionRes.body.message).toContain("Access denied");
    expect(inspectionRes.body.message).toContain("another agent");
  });

  it("should prevent Agent B from inspecting Agent A's approval request", () => {
    const sessionA = createAgentSession("agent_alpha_corp");
    const sessionB = createAgentSession("agent_beta_corp");

    // Agent A creates an approval request
    const reqA = permissionManager.requestApproval(
      "aws:delete_s3_bucket",
      "aws",
      { bucket: "alpha-vault" },
      300,
      sessionA.principalId
    );

    // Agent B attempts to inspect Agent A's approval request using Agent B's session token
    const inspectionRes = executeApprovalPipeline({
      headers: { authorization: `Bearer ${sessionB.sessionToken}` },
      params: { id: reqA.id },
    });

    expect(inspectionRes.status).toBe(403);
    expect(inspectionRes.body.error).toBe("Forbidden");
    expect(inspectionRes.body.message).toContain("Access denied");
  });

  it("should prevent unauthenticated callers from inspecting approval requests", () => {
    const session = createAgentSession("agent_test");
    const req = permissionManager.requestApproval(
      "fs:write_file",
      "filesystem",
      { path: "/etc/hosts" },
      300,
      session.principalId
    );

    // Unauthenticated request (no Authorization header)
    const unauthRes = executeApprovalPipeline({
      headers: {},
      params: { id: req.id },
    });

    expect(unauthRes.status).toBe(401);
    expect(unauthRes.body.error).toBe("Unauthorized");
  });

  it("should reject forged agent identity headers and preserve ownership isolation", () => {
    const sessionA = createAgentSession("agent_alpha_corp");
    const sessionB = createAgentSession("agent_beta_corp");

    const reqA = permissionManager.requestApproval(
      "fs:delete_file",
      "filesystem",
      { path: "secret_keys.pem" },
      300,
      sessionA.principalId
    );

    // Agent B presents their own token but attempts to spoof Agent A's identity via headers
    const spoofAttempt = executeApprovalPipeline({
      headers: {
        authorization: `Bearer ${sessionB.sessionToken}`,
        "x-agent-id": sessionA.principalId,
        "x-omnimcp-principal": sessionA.principalId,
        "x-omnimcp-user": sessionA.principalId,
        "x-caller-id": sessionA.principalId,
      },
      params: { id: reqA.id },
    });

    expect(spoofAttempt.status).toBe(403);
    expect(spoofAttempt.body.error).toBe("Forbidden");
  });

  it("should allow an authenticated operator to inspect all approval requests", () => {
    const sessionA = createAgentSession("agent_alpha_corp");
    const sessionB = createAgentSession("agent_beta_corp");

    const reqA = permissionManager.requestApproval(
      "fs:delete_file",
      "filesystem",
      { file: "a.txt" },
      300,
      sessionA.principalId
    );
    const reqB = permissionManager.requestApproval(
      "fs:delete_file",
      "filesystem",
      { file: "b.txt" },
      300,
      sessionB.principalId
    );

    // Operator inspects Request A
    const opInspectionA = executeApprovalPipeline({
      headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
      params: { id: reqA.id },
    });
    expect(opInspectionA.status).toBe(200);
    expect(opInspectionA.body.id).toBe(reqA.id);
    expect(opInspectionA.body.requesterPrincipal).toBe(sessionA.principalId);

    // Operator inspects Request B
    const opInspectionB = executeApprovalPipeline({
      headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
      params: { id: reqB.id },
    });
    expect(opInspectionB.status).toBe(200);
    expect(opInspectionB.body.id).toBe(reqB.id);
    expect(opInspectionB.body.requesterPrincipal).toBe(sessionB.principalId);
  });

  it("should allow an agent to inspect its own approval request", () => {
    const sessionA = createAgentSession("agent_alpha_corp");
    const reqA = permissionManager.requestApproval(
      "fs:read_file",
      "filesystem",
      { file: "doc.txt" },
      300,
      sessionA.principalId
    );

    // Agent A inspects its own request
    const ownInspection = executeApprovalPipeline({
      headers: { authorization: `Bearer ${sessionA.sessionToken}` },
      params: { id: reqA.id },
    });

    expect(ownInspection.status).toBe(200);
    expect(ownInspection.body.id).toBe(reqA.id);
    expect(ownInspection.body.toolId).toBe("fs:read_file");
  });

  it("should enforce session revocation and dashboard logout semantics", () => {
    // 1. Server-side session revocation
    const session = createAgentSession("ephemeral_agent");
    expect(getAgentSession(session.sessionToken)).toBeDefined();

    const revoked = revokeAgentSession(session.sessionToken);
    expect(revoked).toBe(true);
    expect(getAgentSession(session.sessionToken)).toBeUndefined();

    // Subsequent access with revoked session is rejected
    const postRevocationRes = runMiddleware(requireAgentAuth, {
      headers: { authorization: `Bearer ${session.sessionToken}` },
    });
    expect(postRevocationRes.status).toBe(403);
    expect(postRevocationRes.nextCalled).toBe(false);

    // 2. Client-side dashboard session storage & logout simulation
    const mockSessionStorage: Record<string, string> = {};
    const mockLocalStorage: Record<string, string> = {
      omnimcp_operator_token: "stale_token_from_prior_version",
    };

    function simulateGetAuthToken(storage: Record<string, string>): string {
      // Phase 2.3: Only reads from sessionStorage, ignores URL parameters
      return storage.omnimcp_operator_token || "";
    }

    function simulateLogout(sessionStore: Record<string, string>, localStore: Record<string, string>): void {
      delete sessionStore.omnimcp_operator_token;
      delete localStore.omnimcp_operator_token;
      delete localStore.omnimcp_auth_token;
    }

    // Set active session in sessionStorage
    mockSessionStorage.omnimcp_operator_token = OPERATOR_TOKEN;
    expect(simulateGetAuthToken(mockSessionStorage)).toBe(OPERATOR_TOKEN);

    // Simulate logout
    simulateLogout(mockSessionStorage, mockLocalStorage);
    expect(simulateGetAuthToken(mockSessionStorage)).toBe("");
    expect(mockLocalStorage.omnimcp_operator_token).toBeUndefined();
  });

  it("should support per-agent tokens via OMNIMCP_AGENT_TOKENS configuration", () => {
    process.env.OMNIMCP_AGENT_TOKENS = "agent_client_1:token_secret_111,agent_client_2:token_secret_222";

    const res1 = resolveAgentPrincipal("token_secret_111");
    expect(res1.valid).toBe(true);
    expect(res1.principalId).toBe("agent_client_1");

    const res2 = resolveAgentPrincipal("token_secret_222");
    expect(res2.valid).toBe(true);
    expect(res2.principalId).toBe("agent_client_2");

    const invalidRes = resolveAgentPrincipal("token_secret_wrong");
    expect(invalidRes.valid).toBe(false);
  });
});

describe("Phase 2.5 — Agent Session Lifecycle Hardening", () => {
  beforeEach(() => {
    clearAllAgentSessions();
    clearSessionRateLimits();
    stopSessionCleanupTimer();
  });

  afterEach(() => {
    clearAllAgentSessions();
    clearSessionRateLimits();
    stopSessionCleanupTimer();
  });

  it("should store SHA-256 token hash as Map key and never store raw session token", () => {
    const session = createAgentSession("agent_crypto_test");
    const rawToken = session.sessionToken;
    const expectedHash = hashSessionToken(rawToken);

    // Verify raw token is never a key in the session map
    expect(isRawTokenInSessionMap(rawToken)).toBe(false);

    // Verify lookup by raw token hashes the token and resolves the record
    const resolved = getAgentSession(rawToken);
    expect(resolved).toBeDefined();
    expect(resolved?.tokenHash).toBe(expectedHash);
    expect(resolved?.principalId).toBe("agent_crypto_test");
  });

  it("should reject invalid, malformed, or altered session tokens", () => {
    const session = createAgentSession("agent_valid");
    const rawToken = session.sessionToken;

    // Correct token resolves
    expect(getAgentSession(rawToken)).toBeDefined();

    // Altered token (single character modified) is rejected
    const tamperedToken = rawToken.slice(0, -1) + (rawToken.endsWith("a") ? "b" : "a");
    expect(getAgentSession(tamperedToken)).toBeUndefined();

    // Random non-existent token is rejected
    expect(getAgentSession("omnimcp_sess_0000000000000000000000000000000000000000000000000000000000000000")).toBeUndefined();
  });

  it("should immediately reject revoked session tokens", () => {
    const session = createAgentSession("agent_revocation_test");
    expect(getAgentSession(session.sessionToken)).toBeDefined();

    // Revoke token
    const revoked = revokeAgentSession(session.sessionToken);
    expect(revoked).toBe(true);

    // Subsequent retrieval must be undefined
    expect(getAgentSession(session.sessionToken)).toBeUndefined();

    // Revoking non-existent token returns false
    expect(revokeAgentSession("omnimcp_sess_not_found")).toBe(false);
  });

  it("should expire sessions after TTL and reject expired lookups", () => {
    // Create session with 1 second TTL
    const session = createAgentSession("agent_ttl_test", 1);
    expect(getAgentSession(session.sessionToken)).toBeDefined();

    // Query session in the future (past expiry)
    const futureTime = Date.now() + 2000;
    const cleaned = cleanupExpiredAgentSessions(futureTime);
    expect(cleaned).toBe(1);

    // Expired session lookup must fail
    expect(getAgentSession(session.sessionToken)).toBeUndefined();
  });

  it("should enforce maximum active session quota per principal (max 20)", () => {
    const principal = "quota_constrained_agent";

    // Create 20 sessions (allowed quota)
    for (let i = 0; i < 20; i++) {
      createAgentSession(principal, 86400, 20);
    }
    expect(getActiveSessionCount()).toBe(20);

    // 21st session must throw SessionQuotaExceededError
    expect(() => {
      createAgentSession(principal, 86400, 20);
    }).toThrow(SessionQuotaExceededError);
  });

  it("should enforce independent session quotas across distinct principals", () => {
    const principalA = "agent_tenant_alpha";
    const principalB = "agent_tenant_beta";

    // Fill Principal A's quota to maximum (20)
    for (let i = 0; i < 20; i++) {
      createAgentSession(principalA, 86400, 20);
    }
    expect(() => createAgentSession(principalA, 86400, 20)).toThrow(SessionQuotaExceededError);

    // Principal B must still be able to create sessions independently
    const sessionB = createAgentSession(principalB, 86400, 20);
    expect(sessionB).toBeDefined();
    expect(sessionB.principalId).toBe(principalB);
  });

  it("should not count expired sessions against the active session quota", () => {
    const principal = "recycling_agent";

    // Create 20 short-lived sessions (1-second TTL)
    for (let i = 0; i < 20; i++) {
      createAgentSession(principal, 1, 20);
    }

    // Trigger cleanup with future timestamp
    const cleaned = cleanupExpiredAgentSessions(Date.now() + 2000);
    expect(cleaned).toBe(20);
    expect(getActiveSessionCount()).toBe(0);

    // Now principal can immediately create new active sessions
    const newSession = createAgentSession(principal, 86400, 20);
    expect(newSession).toBeDefined();
    expect(getActiveSessionCount()).toBe(1);
  });

  it("should enforce sliding-window rate limits on session creation requests", () => {
    const principal = "rate_limited_agent";

    // 10 requests within a minute must be allowed
    for (let i = 0; i < 10; i++) {
      const check = checkSessionCreationRateLimit(principal, 10);
      expect(check.allowed).toBe(true);
    }

    // 11th request must be rejected
    const blockedCheck = checkSessionCreationRateLimit(principal, 10);
    expect(blockedCheck.allowed).toBe(false);
    expect(blockedCheck.retryAfterSeconds).toBeGreaterThanOrEqual(1);

    // Distinct principal must not be rate-limited by first principal's requests
    const otherCheck = checkSessionCreationRateLimit("other_agent", 10);
    expect(otherCheck.allowed).toBe(true);
  });

  it("should clean up expired sessions and keep active sessions intact", () => {
    const now = Date.now();
    // 2 active sessions (24h TTL)
    const active1 = createAgentSession("active_agent_1", 86400);
    const active2 = createAgentSession("active_agent_2", 86400);

    // 2 expired sessions (simulated past expiry)
    const expired1 = createAgentSession("expired_agent_1", 1);
    const expired2 = createAgentSession("expired_agent_2", 1);

    expect(getActiveSessionCount()).toBe(4);

    // Run cleanup simulated at now + 5000ms
    const cleanedCount = cleanupExpiredAgentSessions(now + 5000);
    expect(cleanedCount).toBe(2);

    // Active sessions must survive
    expect(getActiveSessionCount()).toBe(2);
    expect(getAgentSession(active1.sessionToken)).toBeDefined();
    expect(getAgentSession(active2.sessionToken)).toBeDefined();

    // Expired sessions must be gone
    expect(getAgentSession(expired1.sessionToken)).toBeUndefined();
    expect(getAgentSession(expired2.sessionToken)).toBeUndefined();
  });

  it("should manage cleanup timer lifecycle and stop timer on shutdown", () => {
    expect(isCleanupTimerActive()).toBe(false);

    // Start timer
    startSessionCleanupTimer(60000);
    expect(isCleanupTimerActive()).toBe(true);

    // Starting again safely restarts/replaces timer without duplicates
    startSessionCleanupTimer(60000);
    expect(isCleanupTimerActive()).toBe(true);

    // Stop timer
    stopSessionCleanupTimer();
    expect(isCleanupTimerActive()).toBe(false);
  });
});
