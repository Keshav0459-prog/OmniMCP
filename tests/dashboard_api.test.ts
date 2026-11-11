import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import {
  requireOperatorAuth,
  requireAgentAuth,
  requireAgentOrOperatorAuth,
  handleGetStats,
  handleGetTelemetryTimeline,
  handleGetDashboardSummary,
  handleGetHistory,
  handleGetHistoryByTraceId,
  handleGetAntigravityConfig,
  handleGetSettings,
  handleGetApprovals,
  handleGetApprovalRequest,
  handleApproveRequest,
  handleRejectRequest,
  resolveAgentPrincipal,
  getAgentToken,
  getPerAgentTokens,
  createAgentSession,
  PLACEHOLDER_AGENT_TOKEN,
  isAllowedOrigin,
} from "../src/http-gateway.js";
import { dbManager } from "../src/db.js";
import { executionHistory } from "../src/history.js";
import { permissionManager } from "../src/permissions.js";
import { ExecutionRecord } from "../src/types.js";
import crypto from "node:crypto";

function invokePipeline(
  middleware: (req: any, res: any, next: any) => void | Promise<void>,
  handler: (req: any, res: any) => void | Promise<void>,
  options: {
    headers?: Record<string, string>;
    query?: Record<string, string>;
    params?: Record<string, string>;
    body?: any;
  } = {}
) {
  let statusCode = 200;
  let responseData: any = null;
  const responseHeaders: Record<string, string> = {};
  let nextCalled = false;

  const req: any = {
    headers: options.headers || {},
    query: options.query || {},
    params: options.params || {},
    body: options.body || {},
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
    setHeader(name: string, value: string) {
      responseHeaders[name.toLowerCase()] = String(value);
      return res;
    },
    getHeader(name: string) {
      return responseHeaders[name.toLowerCase()];
    },
  };

  const next = () => {
    nextCalled = true;
  };

  middleware(req, res, next);

  if (nextCalled) {
    handler(req, res);
  }

  return {
    status: statusCode,
    body: responseData,
    headers: responseHeaders,
    nextCalled,
  };
}

describe("Phase 4.1 Stage B — Dashboard & Server Management Backend APIs", () => {
  const OPERATOR_TOKEN = "test_operator_token_stage_b_12345";
  const AGENT_TOKEN = "test_agent_token_stage_b_67890";

  let originalEnv: NodeJS.ProcessEnv;

  beforeAll(() => {
    originalEnv = { ...process.env };
    process.env.OMNIMCP_OPERATOR_TOKEN = OPERATOR_TOKEN;
    process.env.OMNIMCP_AGENT_TOKEN = AGENT_TOKEN;
    delete process.env.OMNIMCP_AUTH_TOKEN;
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  describe("GET /api/stats (Operator Only Aggregated Stats)", () => {
    it("should reject unauthenticated requests with 401", () => {
      const res = invokePipeline(requireOperatorAuth, handleGetStats);
      expect(res.status).toBe(401);
      expect(res.body.error).toBe("Unauthorized");
      expect(res.nextCalled).toBe(false);
    });

    it("should reject agent credentials with 403 Forbidden", () => {
      const res = invokePipeline(requireOperatorAuth, handleGetStats, {
        headers: { authorization: `Bearer ${AGENT_TOKEN}` },
      });
      expect(res.status).toBe(403);
      expect(res.body.error).toBe("Forbidden");
      expect(res.nextCalled).toBe(false);
    });

    it("should return valid stats structure with operator credentials", () => {
      const res = invokePipeline(requireOperatorAuth, handleGetStats, {
        headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
      });

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty("totalExecutions");
      expect(res.body).toHaveProperty("successfulExecutions");
      expect(res.body).toHaveProperty("failedExecutions");
      expect(res.body).toHaveProperty("deniedExecutions");
      expect(res.body).toHaveProperty("successRate");
      expect(res.body).toHaveProperty("avgLatencyMs");
      expect(res.body).toHaveProperty("pendingApprovals");

      expect(typeof res.body.totalExecutions).toBe("number");
      expect(typeof res.body.successfulExecutions).toBe("number");
      expect(typeof res.body.failedExecutions).toBe("number");
      expect(typeof res.body.deniedExecutions).toBe("number");
      expect(typeof res.body.successRate).toBe("number");
      expect(typeof res.body.avgLatencyMs).toBe("number");
      expect(typeof res.body.pendingApprovals).toBe("number");

      // Verify zero-division safety and no NaN / Infinity
      expect(Number.isNaN(res.body.successRate)).toBe(false);
      expect(Number.isNaN(res.body.avgLatencyMs)).toBe(false);
    });

    it("should accurately reflect recorded executions in database stats aggregation", () => {
      const testTrace = crypto.randomBytes(8).toString("hex");

      const recordSuccess: ExecutionRecord = {
        id: crypto.randomUUID(),
        traceId: testTrace,
        toolId: "filesystem:read_file",
        serverId: "filesystem",
        originalToolName: "read_file",
        inputParameters: { path: "test.txt" },
        outputResult: { content: "hello" },
        status: "success",
        durationMs: 120,
        timestamp: new Date().toISOString(),
      };

      const recordError: ExecutionRecord = {
        id: crypto.randomUUID(),
        traceId: testTrace,
        toolId: "filesystem:write_file",
        serverId: "filesystem",
        originalToolName: "write_file",
        inputParameters: { path: "out.txt" },
        status: "error",
        durationMs: 80,
        error: "Disk write error",
        timestamp: new Date().toISOString(),
      };

      dbManager.insertAuditLog(recordSuccess);
      dbManager.insertAuditLog(recordError);

      const res = invokePipeline(requireOperatorAuth, handleGetStats, {
        headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
      });

      expect(res.status).toBe(200);
      expect(res.body.totalExecutions).toBeGreaterThanOrEqual(2);
      expect(res.body.successfulExecutions).toBeGreaterThanOrEqual(1);
      expect(res.body.failedExecutions).toBeGreaterThanOrEqual(1);
      expect(res.body.successRate).toBeGreaterThan(0);
      expect(res.body.avgLatencyMs).toBeGreaterThan(0);
    });
  });

  describe("GET /api/history & GET /api/history/:traceId (Trace Filtering)", () => {
    const specificTraceId = `trace_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`;
    const specificRecordId = crypto.randomUUID();

    const deniedTraceId = `denied_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`;
    const failedTraceId = `failed_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`;

    beforeAll(() => {
      const record: ExecutionRecord = {
        id: specificRecordId,
        traceId: specificTraceId,
        toolId: "context7:resolve_library",
        serverId: "context7",
        originalToolName: "resolve_library",
        inputParameters: { query: "react" },
        outputResult: { libraries: ["react@19.0.0"] },
        status: "success",
        durationMs: 45,
        timestamp: new Date().toISOString(),
      };

      const deniedRecord: ExecutionRecord = {
        id: crypto.randomUUID(),
        traceId: deniedTraceId,
        toolId: "filesystem:delete_file",
        serverId: "filesystem",
        originalToolName: "delete_file",
        inputParameters: { path: "/etc/passwd" },
        status: "denied",
        durationMs: 2,
        error: "Execution blocked: Operation requires human approval.",
        timestamp: new Date().toISOString(),
      };

      const failedRecord: ExecutionRecord = {
        id: crypto.randomUUID(),
        traceId: failedTraceId,
        toolId: "playwright:browser_navigate",
        serverId: "playwright",
        originalToolName: "browser_navigate",
        inputParameters: {},
        outputResult: null,
        status: "error",
        durationMs: 120,
        error: "net::ERR_NAME_NOT_RESOLVED",
        timestamp: new Date().toISOString(),
      };

      dbManager.insertAuditLog(record);
      dbManager.insertAuditLog(deniedRecord);
      dbManager.insertAuditLog(failedRecord);
    });

    it("should filter history by traceId query parameter", () => {
      const res = invokePipeline(requireOperatorAuth, handleGetHistory, {
        headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
        query: { traceId: specificTraceId },
      });

      expect(res.status).toBe(200);
      expect(Array.isArray(res.body)).toBe(true);
      expect(res.body.length).toBeGreaterThanOrEqual(1);
      expect(res.body[0].traceId).toBe(specificTraceId);
      expect(res.body[0].toolId).toBe("context7:resolve_library");
    });

    it("should return individual record by traceId via GET /api/history/:traceId", () => {
      const res = invokePipeline(requireOperatorAuth, handleGetHistoryByTraceId, {
        headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
        params: { traceId: specificTraceId },
      });

      expect(res.status).toBe(200);
      expect(res.body.traceId).toBe(specificTraceId);
      expect(res.body.toolId).toBe("context7:resolve_library");
      expect(res.body.status).toBe("success");
      expect(res.body.durationMs).toBe(45);
    });

    it("should return 404 for unknown trace ID via GET /api/history/:traceId", () => {
      const unknownTrace = "non_existent_trace_999999";
      const res = invokePipeline(requireOperatorAuth, handleGetHistoryByTraceId, {
        headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
        params: { traceId: unknownTrace },
      });

      expect(res.status).toBe(404);
      expect(res.body.error).toBe("Execution trace not found");
      expect(res.body.traceId).toBe(unknownTrace);
    });

    it("should safely handle malformed trace IDs without throwing 500", () => {
      const malformedTrace = "' OR 1=1; DROP TABLE audit_logs; --";
      const res = invokePipeline(requireOperatorAuth, handleGetHistoryByTraceId, {
        headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
        params: { traceId: malformedTrace },
      });

      expect(res.status).toBe(404);
      expect(res.body.error).toBe("Execution trace not found");
    });

    it("should support genuine offset and limit pagination", () => {
      const res1 = invokePipeline(requireOperatorAuth, handleGetHistory, {
        headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
        query: { limit: "1", offset: "0" },
      });
      const res2 = invokePipeline(requireOperatorAuth, handleGetHistory, {
        headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
        query: { limit: "1", offset: "1" },
      });

      expect(res1.status).toBe(200);
      expect(res2.status).toBe(200);
      expect(res1.body.length).toBe(1);
      expect(res2.body.length).toBe(1);
      expect(res1.body[0].id).not.toBe(res2.body[0].id);
    });

    it("should correctly serialize denied records with error details and safe parameters", () => {
      const res = invokePipeline(requireOperatorAuth, handleGetHistoryByTraceId, {
        headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
        params: { traceId: deniedTraceId },
      });

      expect(res.status).toBe(200);
      expect(res.body.status).toBe("denied");
      expect(res.body.error).toContain("requires human approval");
      expect(res.body.inputParameters).toEqual({ path: "/etc/passwd" });
    });

    it("should correctly serialize failed records with empty input parameters and null output", () => {
      const res = invokePipeline(requireOperatorAuth, handleGetHistoryByTraceId, {
        headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
        params: { traceId: failedTraceId },
      });

      expect(res.status).toBe(200);
      expect(res.body.status).toBe("error");
      expect(res.body.error).toBe("net::ERR_NAME_NOT_RESOLVED");
      expect(res.body.inputParameters).toEqual({});
      expect(res.body.outputResult).toBeUndefined();
    });

    it("should return accurate X-Total-Count header matching filtered count", () => {
      const res = invokePipeline(requireOperatorAuth, handleGetHistory, {
        headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
        query: { server: "context7" },
      });

      expect(res.status).toBe(200);
      expect(res.headers).toHaveProperty("x-total-count");
      const totalHeaderCount = parseInt(res.headers["x-total-count"], 10);
      expect(totalHeaderCount).toBeGreaterThanOrEqual(1);

      // Verify that count equals exact matching records in database
      const directCount = dbManager.countAuditLogs("context7");
      expect(totalHeaderCount).toBe(directCount);
    });

    it("should safely handle NaN, negative, decimal, and malformed offset parameters", () => {
      // 1. NaN offset defaults to 0
      const resNaN = invokePipeline(requireOperatorAuth, handleGetHistory, {
        headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
        query: { offset: "NaN", limit: "1" },
      });
      expect(resNaN.status).toBe(200);
      expect(resNaN.body.length).toBe(1);

      // 2. Negative offset defaults to 0
      const resNeg = invokePipeline(requireOperatorAuth, handleGetHistory, {
        headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
        query: { offset: "-99", limit: "1" },
      });
      expect(resNeg.status).toBe(200);
      expect(resNeg.body.length).toBe(1);
      expect(resNeg.body[0].id).toBe(resNaN.body[0].id);

      // 3. Decimal offset is floored to integer
      const resDec = invokePipeline(requireOperatorAuth, handleGetHistory, {
        headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
        query: { offset: "1.8", limit: "1" },
      });
      expect(resDec.status).toBe(200);
      expect(resDec.body.length).toBe(1);

      // 4. Malformed string defaults to 0
      const resMalformed = invokePipeline(requireOperatorAuth, handleGetHistory, {
        headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
        query: { offset: "invalid_offset_xyz", limit: "1" },
      });
      expect(resMalformed.status).toBe(200);
      expect(resMalformed.body[0].id).toBe(resNaN.body[0].id);
    });

    it("should safely handle non-positive, oversized, and NaN limit parameters", () => {
      // 1. Zero limit defaults to 50
      const resZero = invokePipeline(requireOperatorAuth, handleGetHistory, {
        headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
        query: { limit: "0" },
      });
      expect(resZero.status).toBe(200);

      // 2. Oversized limit is clamped to 100
      const resOversized = invokePipeline(requireOperatorAuth, handleGetHistory, {
        headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
        query: { limit: "9999" },
      });
      expect(resOversized.status).toBe(200);
      expect(resOversized.body.length).toBeLessThanOrEqual(100);

      // 3. Negative limit defaults to 50
      const resNeg = invokePipeline(requireOperatorAuth, handleGetHistory, {
        headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
        query: { limit: "-10" },
      });
      expect(resNeg.status).toBe(200);
    });

    it("should sanitize secrets in downstream error messages before persisting in SQLite", () => {
      const secretToken = "sntrys_1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
      const bearerSecret = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisJWTSecret123456";

      const recordWithSecretError = executionHistory.recordExecution(
        "sentry:query_events",
        "sentry",
        "query_events",
        { project: "demo" },
        null,
        "error",
        15,
        `Failed to reach upstream Sentry using token ${secretToken} with authorization header ${bearerSecret}`
      );

      // Inspect persisted SQLite record directly from database
      const persisted = dbManager.getAuditLogByTraceId(recordWithSecretError.traceId);
      expect(persisted).toBeDefined();
      expect(persisted!.error).not.toContain(secretToken);
      expect(persisted!.error).not.toContain("doNotLeakThisJWTSecret123456");
      expect(persisted!.error).toContain("[REDACTED_SECRET]");
    });

    it("should sanitize nested objects, arrays, and credentials in input/output before persisting in SQLite", () => {
      const nestedSecretRecord = executionHistory.recordExecution(
        "filesystem:write_config",
        "filesystem",
        "write_config",
        {
          config: {
            database: {
              password: "SuperSecretPassword123!",
              api_key: "omnimcp_approval_token_sensitive_secret_99999",
            },
            tags: ["production", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.secretSignature12345678"],
          },
        },
        {
          authStatus: "connected",
          service_role_key: "sb_secret_abcdef1234567890abcdef1234567890",
        },
        "success",
        30
      );

      // Query raw row from SQLite to guarantee database persistence has zero plaintext secrets
      const rawRow = dbManager.getAuditLogByTraceId(nestedSecretRecord.traceId);
      expect(rawRow).toBeDefined();

      const rawInputJson = JSON.stringify(rawRow!.inputParameters);
      const rawOutputJson = JSON.stringify(rawRow!.outputResult);

      expect(rawInputJson).not.toContain("SuperSecretPassword123!");
      expect(rawInputJson).not.toContain("omnimcp_approval_token_sensitive_secret_99999");
      expect(rawInputJson).not.toContain("secretSignature12345678");
      expect(rawInputJson).toContain("[REDACTED_SECRET]");

      expect(rawOutputJson).not.toContain("sb_secret_abcdef1234567890abcdef1234567890");
      expect(rawOutputJson).toContain("[REDACTED_SECRET]");
    });

    it("should reject agent credentials on GET /api/history/:traceId with 403", () => {
      const res = invokePipeline(requireOperatorAuth, handleGetHistoryByTraceId, {
        headers: { authorization: `Bearer ${AGENT_TOKEN}` },
        params: { traceId: specificTraceId },
      });

      expect(res.status).toBe(403);
      expect(res.nextCalled).toBe(false);
    });
  });

  describe("GET /api/config/antigravity (Client Configuration Generator)", () => {
    it("should reject unauthenticated request with 401", () => {
      const res = invokePipeline(requireOperatorAuth, handleGetAntigravityConfig);
      expect(res.status).toBe(401);
      expect(res.nextCalled).toBe(false);
    });

    it("should reject agent credentials with 403 Forbidden", () => {
      const res = invokePipeline(requireOperatorAuth, handleGetAntigravityConfig, {
        headers: { authorization: `Bearer ${AGENT_TOKEN}` },
      });
      expect(res.status).toBe(403);
      expect(res.nextCalled).toBe(false);
    });

    it("should return valid Antigravity mcpServers configuration snippet", () => {
      const res = invokePipeline(requireOperatorAuth, handleGetAntigravityConfig, {
        headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
      });

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty("mcpServers");
      expect(res.body.mcpServers).toHaveProperty("omnimcp");

      const serverConf = res.body.mcpServers.omnimcp;
      expect(serverConf).toHaveProperty("command");
      expect(serverConf).toHaveProperty("args");
      expect(serverConf).toHaveProperty("cwd");
      // Critical: STDIO config must NOT contain an env block or token placeholders
      expect(serverConf).not.toHaveProperty("env");

      // Verify command and args structure
      expect(typeof serverConf.command).toBe("string");
      expect(Array.isArray(serverConf.args)).toBe(true);
      expect(serverConf.args).toContain("--stdio");
      expect(serverConf.args.some((a: string) => a.includes("dist") && a.includes("index.js"))).toBe(true);

      // Verify zero tokens leaked in payload
      const rawJson = JSON.stringify(res.body);
      expect(rawJson).not.toContain("OMNIMCP_AGENT_TOKEN");
      expect(rawJson).not.toContain("your_agent_token_here");
      expect(rawJson).not.toContain(OPERATOR_TOKEN);
    });
  });

  describe("Security RBAC Integrity Guard: /api/tools/execute", () => {
    it("MUST strictly reject operator credentials with 403 Forbidden", () => {
      let statusCode = 200;
      let responseData: any = null;
      let nextCalled = false;

      const req: any = {
        headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
        body: {
          tool_id: "filesystem:read_file",
          parameters: { path: "README.md" },
        },
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
      };

      requireAgentAuth(req, res, () => {
        nextCalled = true;
      });

      expect(nextCalled).toBe(false);
      expect(statusCode).toBe(403);
      expect(responseData.error).toBe("Forbidden");
      expect(responseData.message).toContain("Operator credentials cannot directly invoke agent-only execution endpoints");
    });
  });

  describe("Phase 4.1 Stage F — Approval Inbox & Human Approval Workflow", () => {
    const ALPHA_TOKEN = "test_agent_token_alpha_123";
    const BETA_TOKEN = "test_agent_token_beta_456";

    beforeAll(() => {
      process.env.OMNIMCP_AGENT_TOKENS = `agent-alpha:${ALPHA_TOKEN},agent-beta:${BETA_TOKEN}`;
    });

    afterAll(() => {
      delete process.env.OMNIMCP_AGENT_TOKENS;
    });

    describe("GET /api/approvals (Operator Only Inbox Queue)", () => {
      it("should reject unauthenticated request with 401", () => {
        const res = invokePipeline(requireOperatorAuth, handleGetApprovals);
        expect(res.status).toBe(401);
        expect(res.body.error).toBe("Unauthorized");
      });

      it("should reject agent credentials with 403 Forbidden", () => {
        const res = invokePipeline(requireOperatorAuth, handleGetApprovals, {
          headers: { authorization: `Bearer ${ALPHA_TOKEN}` },
        });
        expect(res.status).toBe(403);
        expect(res.body.error).toBe("Forbidden");
      });

      it("should return approvals list sorted newest first for operator", () => {
        const req1 = permissionManager.requestApproval(
          "filesystem:write_file",
          "filesystem",
          { path: "/tmp/test1.txt", content: "data 1" },
          300,
          "agent-alpha"
        );
        req1.requestedAt = new Date(Date.now() - 5000).toISOString();

        const req2 = permissionManager.requestApproval(
          "bash:execute",
          "bash",
          { command: "rm -rf /tmp/test" },
          300,
          "agent-beta"
        );
        req2.requestedAt = new Date(Date.now()).toISOString();

        const res = invokePipeline(requireOperatorAuth, handleGetApprovals, {
          headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
          query: { status: "all" },
        });

        expect(res.status).toBe(200);
        expect(Array.isArray(res.body)).toBe(true);
        expect(res.body.length).toBeGreaterThanOrEqual(2);

        const idx1 = res.body.findIndex((r: any) => r.id === req1.id);
        const idx2 = res.body.findIndex((r: any) => r.id === req2.id);
        expect(idx2).toBeLessThan(idx1);
      });

      it("CRITICAL SECURITY: MUST NEVER expose raw approval tokens in inbox listing", () => {
        const req = permissionManager.requestApproval(
          "postgres:drop_table",
          "postgres",
          { table: "users" },
          300,
          "agent-alpha"
        );
        permissionManager.approveRequest(req.id, "authenticated_operator");

        const res = invokePipeline(requireOperatorAuth, handleGetApprovals, {
          headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
          query: { status: "approved" },
        });

        expect(res.status).toBe(200);
        const approvedItem = res.body.find((r: any) => r.id === req.id);
        expect(approvedItem).toBeDefined();
        expect(approvedItem.status).toBe("approved");
        expect(approvedItem.token).toBeUndefined();
      });

      it("should sanitize sensitive parameters in approval inbox listing", () => {
        const req = permissionManager.requestApproval(
          "auth:login",
          "auth",
          { username: "admin", password: "SuperSecretPassword123!", api_token: "tok_secret_99999" },
          300,
          "agent-alpha"
        );

        const res = invokePipeline(requireOperatorAuth, handleGetApprovals, {
          headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
          query: { status: "pending" },
        });

        expect(res.status).toBe(200);
        const item = res.body.find((r: any) => r.id === req.id);
        expect(item).toBeDefined();
        expect(item.parameters.password).toBe("[REDACTED_SECRET]");
        expect(item.parameters.api_token).toBe("[REDACTED_SECRET]");
        expect(item.parameters.username).toBe("admin");
      });

      it("should filter by status correctly (pending, approved, rejected, expired, consumed)", () => {
        const resPending = invokePipeline(requireOperatorAuth, handleGetApprovals, {
          headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
          query: { status: "pending" },
        });
        expect(resPending.status).toBe(200);
        expect(resPending.body.every((r: any) => r.status === "pending")).toBe(true);

        const resApproved = invokePipeline(requireOperatorAuth, handleGetApprovals, {
          headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
          query: { status: "approved" },
        });
        expect(resApproved.status).toBe(200);
        expect(resApproved.body.every((r: any) => r.status === "approved")).toBe(true);

        const rejReq = permissionManager.requestApproval(
          "filesystem:delete",
          "filesystem",
          { path: "/critical.db" },
          300,
          "agent-alpha"
        );
        permissionManager.rejectRequest(rejReq.id, "authenticated_operator", "Too dangerous");

        const resRejected = invokePipeline(requireOperatorAuth, handleGetApprovals, {
          headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
          query: { status: "rejected" },
        });
        expect(resRejected.status).toBe(200);
        const foundRej = resRejected.body.find((r: any) => r.id === rejReq.id);
        expect(foundRej).toBeDefined();
        expect(foundRej.status).toBe("rejected");
        expect(foundRej.rejectionReason).toBe("Too dangerous");
      });
    });

    describe("GET /api/approvals/:id (Approval Detail Inspector)", () => {
      it("should reject unauthenticated request with 401", () => {
        const res = invokePipeline(requireAgentOrOperatorAuth, handleGetApprovalRequest, {
          params: { id: "nonexistent-id" },
        });
        expect(res.status).toBe(401);
      });

      it("should return 404 for non-existent approval request", () => {
        const res = invokePipeline(requireAgentOrOperatorAuth, handleGetApprovalRequest, {
          headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
          params: { id: "00000000-0000-0000-0000-000000000000" },
        });
        expect(res.status).toBe(404);
      });

      it("operator can inspect any approval request with sanitized parameters and NO raw token", () => {
        const req = permissionManager.requestApproval(
          "system:deploy",
          "system",
          { env: "prod", secret_key: "TopSecretKeyVal!" },
          300,
          "agent-alpha"
        );

        const res = invokePipeline(requireAgentOrOperatorAuth, handleGetApprovalRequest, {
          headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
          params: { id: req.id },
        });

        expect(res.status).toBe(200);
        expect(res.body.id).toBe(req.id);
        expect(res.body.toolId).toBe("system:deploy");
        expect(res.body.requesterPrincipal).toBe("agent-alpha");
        expect(res.body.token).toBeUndefined();
        expect(res.body.parameters.secret_key).toBe("[REDACTED_SECRET]");
        expect(res.body.paramsHash).toBeDefined();
      });

      it("agent can inspect its OWN approval request (receives token if approved)", () => {
        const req = permissionManager.requestApproval(
          "system:restart",
          "system",
          { grace_period: 30 },
          300,
          "agent-alpha"
        );
        const { token } = permissionManager.approveRequest(req.id, "authenticated_operator");

        const res = invokePipeline(requireAgentOrOperatorAuth, handleGetApprovalRequest, {
          headers: { authorization: `Bearer ${ALPHA_TOKEN}` },
          params: { id: req.id },
        });

        expect(res.status).toBe(200);
        expect(res.body.id).toBe(req.id);
        expect(res.body.token).toBe(token);
      });

      it("agent CANNOT inspect approval request belonging to another agent (403 Forbidden)", () => {
        const req = permissionManager.requestApproval(
          "database:migrate",
          "database",
          { version: "v2" },
          300,
          "agent-beta"
        );

        const res = invokePipeline(requireAgentOrOperatorAuth, handleGetApprovalRequest, {
          headers: { authorization: `Bearer ${ALPHA_TOKEN}` },
          params: { id: req.id },
        });

        expect(res.status).toBe(403);
        expect(res.body.error).toBe("Forbidden");
        expect(res.body.message).toContain("Access denied: You do not have permission to inspect approval requests created by another agent");
      });
    });

    describe("POST /api/approvals/:id/approve (Operator Approval Action)", () => {
      it("should reject unauthenticated request with 401", () => {
        const res = invokePipeline(requireOperatorAuth, handleApproveRequest, {
          params: { id: "test-id" },
        });
        expect(res.status).toBe(401);
      });

      it("should reject agent credentials with 403 Forbidden (RBAC separation)", () => {
        const res = invokePipeline(requireOperatorAuth, handleApproveRequest, {
          headers: { authorization: `Bearer ${ALPHA_TOKEN}` },
          params: { id: "test-id" },
        });
        expect(res.status).toBe(403);
        expect(res.body.error).toBe("Forbidden");
      });

      it("operator can approve a pending request and generate parameter-bound token", () => {
        const req = permissionManager.requestApproval(
          "filesystem:chmod",
          "filesystem",
          { path: "/var/log", mode: "755" },
          300,
          "agent-alpha"
        );

        const res = invokePipeline(requireOperatorAuth, handleApproveRequest, {
          headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
          params: { id: req.id },
        });

        expect(res.status).toBe(200);
        expect(res.body.status).toBe("approved");
        expect(res.body.requestId).toBe(req.id);
        expect(res.body.toolId).toBe("filesystem:chmod");
        expect(typeof res.body.token).toBe("string");
        expect(res.body.token.length).toBeGreaterThan(16);

        const updated = permissionManager.getApprovalRequest(req.id);
        expect(updated?.status).toBe("approved");
        expect(updated?.approvedBy).toBe("authenticated_operator");

        const audits = dbManager.queryApprovalAudits(req.id);
        expect(audits.some((a) => a.eventType === "approval_approved" && a.status === "approved")).toBe(true);
      });

      it("should reject approval of an already approved or rejected request with 400", () => {
        const req = permissionManager.requestApproval(
          "cloud:scale",
          "cloud",
          { instances: 5 },
          300,
          "agent-alpha"
        );
        permissionManager.approveRequest(req.id, "authenticated_operator");

        const res = invokePipeline(requireOperatorAuth, handleApproveRequest, {
          headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
          params: { id: req.id },
        });

        expect(res.status).toBe(400);
        expect(res.body.error).toContain("is already approved");
      });
    });

    describe("POST /api/approvals/:id/reject (Operator Rejection Action)", () => {
      it("should reject unauthenticated request with 401", () => {
        const res = invokePipeline(requireOperatorAuth, handleRejectRequest, {
          params: { id: "test-id" },
        });
        expect(res.status).toBe(401);
      });

      it("should reject agent credentials with 403 Forbidden", () => {
        const res = invokePipeline(requireOperatorAuth, handleRejectRequest, {
          headers: { authorization: `Bearer ${ALPHA_TOKEN}` },
          params: { id: "test-id" },
        });
        expect(res.status).toBe(403);
      });

      it("operator can reject a pending request with optional reason", () => {
        const req = permissionManager.requestApproval(
          "network:firewall_drop",
          "network",
          { port: 22 },
          300,
          "agent-alpha"
        );

        const res = invokePipeline(requireOperatorAuth, handleRejectRequest, {
          headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
          params: { id: req.id },
          body: { reason: "Cannot close SSH during maintenance window" },
        });

        expect(res.status).toBe(200);
        expect(res.body.status).toBe("rejected");
        expect(res.body.requestId).toBe(req.id);
        expect(res.body.reason).toBe("Cannot close SSH during maintenance window");

        const updated = permissionManager.getApprovalRequest(req.id);
        expect(updated?.status).toBe("rejected");
        expect(updated?.rejectionReason).toBe("Cannot close SSH during maintenance window");
        expect(updated?.rejectedBy).toBe("authenticated_operator");

        const audits = dbManager.queryApprovalAudits(req.id);
        expect(audits.some((a) => a.eventType === "approval_rejected" && a.status === "rejected")).toBe(true);
      });
    });

    describe("Dynamic Expiry & Cryptographic Binding & Replay Protection", () => {
      it("should dynamically evaluate expired requests and prevent approval", () => {
        const req = permissionManager.requestApproval(
          "system:reboot",
          "system",
          { immediate: true },
          1,
          "agent-alpha"
        );

        // Force expiry timestamp
        (req as any).expiresAt = Date.now() - 1000;

        const expiredList = permissionManager.getAllApprovals("expired");
        expect(expiredList.some((r) => r.id === req.id)).toBe(true);

        expect(() => {
          permissionManager.approveRequest(req.id, "authenticated_operator");
        }).toThrow(/expired/i);
      });

      it("should reject execution if parameters are tampered with (SHA-256 mismatch)", () => {
        const req = permissionManager.requestApproval(
          "filesystem:write_file",
          "filesystem",
          { path: "/data/file.txt", content: "safe data" },
          300,
          "agent-alpha"
        );

        const { token } = permissionManager.approveRequest(req.id, "authenticated_operator");

        const tamperedResult = permissionManager.consumeApprovalToken(
          token,
          "filesystem:write_file",
          "filesystem",
          { path: "/data/file.txt", content: "MALICIOUS OVERWRITE!" }
        );

        expect(tamperedResult.valid).toBe(false);
        expect(tamperedResult.reason).toContain("Parameter tampering detected");
      });

      it("should allow valid execution and strictly reject replay of consumed token", () => {
        const validParams = { path: "/data/legit.txt", content: "legitimate payload" };
        const req = permissionManager.requestApproval(
          "filesystem:write_file",
          "filesystem",
          validParams,
          300,
          "agent-alpha"
        );

        const { token } = permissionManager.approveRequest(req.id, "authenticated_operator");

        const firstResult = permissionManager.consumeApprovalToken(
          token,
          "filesystem:write_file",
          "filesystem",
          validParams
        );
        expect(firstResult.valid).toBe(true);

        const consumed = permissionManager.getApprovalRequest(req.id);
        expect(consumed?.status).toBe("consumed");

        const replayResult = permissionManager.consumeApprovalToken(
          token,
          "filesystem:write_file",
          "filesystem",
          validParams
        );
        expect(replayResult.valid).toBe(false);
        expect(replayResult.reason).toContain("Invalid or already consumed approval token");
      });
    });
  });

  describe("Phase 4.1 Stage G — Antigravity Config Generator & Settings Polish", () => {
    describe("Configurable Antigravity Configuration Generator", () => {
      it("should accept custom nodePath and projectPath query parameters with Windows path normalization", () => {
        const customNode = "C:\\Program Files\\nodejs\\node.exe";
        const customProject = "C:\\Repositories\\OmniMCP";

        const res = invokePipeline(requireOperatorAuth, handleGetAntigravityConfig, {
          headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
          query: {
            nodePath: customNode,
            projectPath: customProject,
          },
        });

        expect(res.status).toBe(200);
        expect(res.body).toHaveProperty("mcpServers");
        expect(res.body.mcpServers).toHaveProperty("omnimcp");

        const cfg = res.body.mcpServers.omnimcp;
        // Verify Windows backslashes were converted to forward slashes for universal compatibility
        expect(cfg.command).toBe("C:/Program Files/nodejs/node.exe");
        expect(cfg.cwd).toBe("C:/Repositories/OmniMCP");
        expect(cfg.args[0]).toBe("C:/Repositories/OmniMCP/dist/index.js");
        expect(cfg.args[1]).toBe("--stdio");

        // STDIO config must not contain env or tokens
        expect(cfg).not.toHaveProperty("env");

        // Zero secret leakage
        const rawJson = JSON.stringify(res.body);
        expect(rawJson).not.toContain(OPERATOR_TOKEN);
        expect(rawJson).not.toContain(AGENT_TOKEN);
        expect(rawJson).not.toContain("OMNIMCP_AGENT_TOKEN");
      });

      it("should reject agent credentials on GET /api/config/antigravity with 403 Forbidden", () => {
        const res = invokePipeline(requireOperatorAuth, handleGetAntigravityConfig, {
          headers: { authorization: `Bearer ${AGENT_TOKEN}` },
        });
        expect(res.status).toBe(403);
        expect(res.body.error).toBe("Forbidden");
      });
    });

    describe("GET /api/settings (Operator Only Gateway Settings & Diagnostics)", () => {
      it("should reject unauthenticated request with 401", () => {
        const res = invokePipeline(requireOperatorAuth, handleGetSettings);
        expect(res.status).toBe(401);
        expect(res.body.error).toBe("Unauthorized");
      });

      it("should reject agent credentials with 403 Forbidden", () => {
        const res = invokePipeline(requireOperatorAuth, handleGetSettings, {
          headers: { authorization: `Bearer ${AGENT_TOKEN}` },
        });
        expect(res.status).toBe(403);
        expect(res.body.error).toBe("Forbidden");
      });

      it("should return complete, live, sanitized settings structure for operator", () => {
        const res = invokePipeline(requireOperatorAuth, handleGetSettings, {
          headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
        });

        expect(res.status).toBe(200);

        // 1. Gateway Group
        expect(res.body).toHaveProperty("gateway");
        const gw = res.body.gateway;
        expect(gw.status).toBe("active");
        expect(gw.version).toBe("1.0.0");
        expect(Array.isArray(gw.transports)).toBe(true);
        expect(gw.transports).toContain("stdio");
        expect(gw.transports).toContain("http");
        expect(gw.transports).toContain("sse");
        expect(gw.coreToolCount).toBe(10);
        expect(typeof gw.connectedServersCount).toBe("number");
        expect(typeof gw.totalServersCount).toBe("number");
        expect(typeof gw.nodeVersion).toBe("string");
        expect(typeof gw.platform).toBe("string");
        expect(typeof gw.uptimeSeconds).toBe("number");
        expect(typeof gw.distExists).toBe("boolean");
        expect(gw.downstreamHttpTransportStatus).toBe("not_implemented");

        // 2. Authentication Group
        expect(res.body).toHaveProperty("authentication");
        const auth = res.body.authentication;
        expect(auth.agentAuthStatus).toBe("configured");
        expect(auth.operatorAuthStatus).toBe("configured");
        expect(auth.sessionAuthEnabled).toBe(true);
        expect(typeof auth.activeSessionsCount).toBe("number");
        expect(typeof auth.tokenRotationGuidance).toBe("string");
        expect(auth.tokenRotationGuidance).toContain("OMNIMCP_AGENT_TOKEN");

        // 3. Security Group
        expect(res.body).toHaveProperty("security");
        const sec = res.body.security;
        expect(sec.approvalWorkflowStatus).toBe("active");
        expect(typeof sec.pendingApprovalsCount).toBe("number");
        expect(sec.approvalQueueType).toBe("session_in_memory");
        expect(typeof sec.approvalTtlSeconds).toBe("number");
        expect(sec.secretRedactionStatus).toBe("enabled");
        expect(sec.auditSanitizationStatus).toBe("test_verified");
        expect(sec.downstreamHttpTransport).toBe("not_implemented");
        expect(Array.isArray(sec.allowedDirectories)).toBe(true);
        expect(Array.isArray(sec.preApprovedServers)).toBe(true);
        expect(sec.preApprovedServers).toContain("filesystem");
        expect(sec.preApprovedServers).toContain("context7");
        expect(sec.preApprovedServers).toContain("playwright");

        // 4. Diagnostics Group
        expect(res.body).toHaveProperty("diagnostics");
        const diag = res.body.diagnostics;
        expect(diag.gatewayHealth).toBe("healthy");
        expect(typeof diag.sqliteMode).toBe("string");
        expect(typeof diag.totalExecutions).toBe("number");
        expect(typeof diag.successRate).toBe("number");
        expect(typeof diag.avgLatencyMs).toBe("number");

        // CRITICAL SECURITY: Zero credential leakage in settings output
        const rawJson = JSON.stringify(res.body);
        expect(rawJson).not.toContain(OPERATOR_TOKEN);
        expect(rawJson).not.toContain(AGENT_TOKEN);
      });
    });

    describe("Approval Token Retrieval Lifecycle Protections (Checks A & C)", () => {
      const ALPHA_TOKEN = "test_agent_token_alpha_123";

      beforeAll(() => {
        process.env.OMNIMCP_AGENT_TOKENS = `agent-alpha:${ALPHA_TOKEN}`;
      });

      afterAll(() => {
        delete process.env.OMNIMCP_AGENT_TOKENS;
      });

      it("Check A: agent inspecting a rejected request MUST receive token: undefined", () => {
        const req = permissionManager.requestApproval(
          "filesystem:delete",
          "filesystem",
          { path: "/critical.file" },
          300,
          "agent-alpha"
        );
        permissionManager.rejectRequest(req.id, "authenticated_operator", "Denied by admin");

        const res = invokePipeline(requireAgentOrOperatorAuth, handleGetApprovalRequest, {
          headers: { authorization: `Bearer test_agent_token_alpha_123` },
          params: { id: req.id },
        });

        expect(res.status).toBe(200);
        expect(res.body.id).toBe(req.id);
        expect(res.body.status).toBe("rejected");
        expect(res.body.token).toBeUndefined();
      });

      it("Check A: agent inspecting an expired request MUST receive token: undefined", () => {
        const req = permissionManager.requestApproval(
          "system:reboot",
          "system",
          { force: true },
          1,
          "agent-alpha"
        );
        // Force expired timestamp
        (req as any).expiresAt = Date.now() - 5000;

        const res = invokePipeline(requireAgentOrOperatorAuth, handleGetApprovalRequest, {
          headers: { authorization: `Bearer test_agent_token_alpha_123` },
          params: { id: req.id },
        });

        expect(res.status).toBe(200);
        expect(res.body.id).toBe(req.id);
        expect(res.body.token).toBeUndefined();
      });

      it("Check A: agent inspecting a consumed request MUST receive token: undefined", () => {
        const validParams = { path: "/safe.txt", content: "data" };
        const req = permissionManager.requestApproval(
          "filesystem:write_file",
          "filesystem",
          validParams,
          300,
          "agent-alpha"
        );
        const { token } = permissionManager.approveRequest(req.id, "authenticated_operator");

        // Consume token
        permissionManager.consumeApprovalToken(token, "filesystem:write_file", "filesystem", validParams);

        const res = invokePipeline(requireAgentOrOperatorAuth, handleGetApprovalRequest, {
          headers: { authorization: `Bearer test_agent_token_alpha_123` },
          params: { id: req.id },
        });

        expect(res.status).toBe(200);
        expect(res.body.id).toBe(req.id);
        expect(res.body.status).toBe("consumed");
        expect(res.body.token).toBeUndefined();
      });

      it("Check C: rejection reason is sanitized and operator identity derived strictly from session", () => {
        const req = permissionManager.requestApproval(
          "db:drop_database",
          "postgres",
          { db: "prod" },
          300,
          "agent-alpha"
        );

        const res = invokePipeline(requireOperatorAuth, handleRejectRequest, {
          headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
          params: { id: req.id },
          body: {
            reason: "  Unsafe operation: <script>alert(1)</script> password=SecretPass99!  ",
          },
        });

        expect(res.status).toBe(200);
        expect(res.body.status).toBe("rejected");

        const updated = permissionManager.getApprovalRequest(req.id);
        expect(updated?.rejectedBy).toBe("authenticated_operator");
        expect(updated?.rejectionReason).not.toContain("SecretPass99!");
        expect(updated?.rejectionReason).toContain("[REDACTED_SECRET]");
      });
    });
  });

  describe("Stage H.1: Final STDIO Configuration & HTTP Placeholder Security Fix", () => {
    it("1. Generated Antigravity config contains no agent or operator token and no env block", () => {
      const res = invokePipeline(requireOperatorAuth, handleGetAntigravityConfig, {
        headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
      });
      expect(res.status).toBe(200);
      const omnimcp = res.body.mcpServers.omnimcp;
      expect(omnimcp).not.toHaveProperty("env");
      expect(JSON.stringify(res.body)).not.toContain("OMNIMCP_AGENT_TOKEN");
      expect(JSON.stringify(res.body)).not.toContain("OMNIMCP_OPERATOR_TOKEN");
      expect(JSON.stringify(res.body)).not.toContain("your_agent_token_here");
    });

    it("2. Generated configuration still parses as valid JSON with command, args, and cwd", () => {
      const res = invokePipeline(requireOperatorAuth, handleGetAntigravityConfig, {
        headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
      });
      const parsed = JSON.parse(JSON.stringify(res.body));
      expect(parsed.mcpServers.omnimcp.command).toBeDefined();
      expect(Array.isArray(parsed.mcpServers.omnimcp.args)).toBe(true);
      expect(parsed.mcpServers.omnimcp.args).toContain("--stdio");
      expect(parsed.mcpServers.omnimcp.cwd).toBeDefined();
    });

    it("3. Placeholder token 'your_agent_token_here' is rejected by HTTP authentication", () => {
      const dummyHandler = (_req: any, res: any) => { res.status(200).json({ ok: true }); };
      const res = invokePipeline(requireAgentAuth, dummyHandler, {
        headers: { authorization: `Bearer ${PLACEHOLDER_AGENT_TOKEN}` },
      });
      expect(res.status).toBe(403);
      expect(res.body.error).toBe("Forbidden");
    });

    it("4. Placeholder cannot authenticate through alternative agent-token resolution paths", () => {
      // Direct principal resolution
      const resolution = resolveAgentPrincipal(PLACEHOLDER_AGENT_TOKEN);
      expect(resolution.valid).toBe(false);

      // If process.env.OMNIMCP_AGENT_TOKEN was set to the placeholder, getAgentToken() must return undefined
      const origToken = process.env.OMNIMCP_AGENT_TOKEN;
      try {
        process.env.OMNIMCP_AGENT_TOKEN = PLACEHOLDER_AGENT_TOKEN;
        expect(getAgentToken()).toBeUndefined();
      } finally {
        process.env.OMNIMCP_AGENT_TOKEN = origToken;
      }

      // If per-agent tokens contain the placeholder, it must be filtered out
      const origAgentTokens = process.env.OMNIMCP_AGENT_TOKENS;
      try {
        process.env.OMNIMCP_AGENT_TOKENS = `evil_agent:${PLACEHOLDER_AGENT_TOKEN},good_agent:valid_token_123`;
        const map = getPerAgentTokens();
        expect(map.has(PLACEHOLDER_AGENT_TOKEN)).toBe(false);
        expect(map.get("valid_token_123")).toBe("good_agent");
      } finally {
        process.env.OMNIMCP_AGENT_TOKENS = origAgentTokens;
      }
    });

    it("5. Legitimate agent token remains accepted", () => {
      const dummyHandler = (_req: any, res: any) => { res.status(200).json({ ok: true }); };
      const res = invokePipeline(requireAgentAuth, dummyHandler, {
        headers: { authorization: `Bearer ${AGENT_TOKEN}` },
      });
      expect(res.status).toBe(200);
      expect(res.body.ok).toBe(true);
    });

    it("6. Legitimate session tokens continue working", () => {
      const session = createAgentSession("agent-regression-tester");
      expect(session.sessionToken).toBeDefined();

      const resolution = resolveAgentPrincipal(session.sessionToken);
      expect(resolution.valid).toBe(true);
      expect(resolution.principalId).toBe("agent-regression-tester");

      const dummyHandler = (_req: any, res: any) => {
        res.status(200).json({ principal: (res as any).agentPrincipal || "agent-regression-tester" });
      };
      const res = invokePipeline(requireAgentAuth, dummyHandler, {
        headers: { authorization: `Bearer ${session.sessionToken}` },
      });
      expect(res.status).toBe(200);
      expect(res.body.principal).toBe("agent-regression-tester");
    });

    it("7. Operator authentication and RBAC remain strictly separated", () => {
      const dummyHandler = (_req: any, res: any) => { res.status(200).json({ ok: true }); };

      // Operator cannot call agent-only endpoint
      const agentRes = invokePipeline(requireAgentAuth, dummyHandler, {
        headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
      });
      expect(agentRes.status).toBe(403);

      // Agent cannot call operator-only endpoint
      const opRes = invokePipeline(requireOperatorAuth, dummyHandler, {
        headers: { authorization: `Bearer ${AGENT_TOKEN}` },
      });
      expect(opRes.status).toBe(403);
    });
  });

  describe("CORS Origin Validation (Cloud Deployment & Local)", () => {
    it("allows requests with empty origin (same-origin, curl, server-to-server)", () => {
      expect(isAllowedOrigin("")).toBe(true);
    });

    it("allows localhost and 127.0.0.1 on any port", () => {
      expect(isAllowedOrigin("http://localhost:3000")).toBe(true);
      expect(isAllowedOrigin("http://127.0.0.1:3000")).toBe(true);
      expect(isAllowedOrigin("http://localhost")).toBe(true);
      expect(isAllowedOrigin("http://127.0.0.1")).toBe(true);
      expect(isAllowedOrigin("https://localhost:8080")).toBe(true);
    });

    it("allows Voroa cloud deployment domains (*.onvoroa.com)", () => {
      expect(isAllowedOrigin("https://omnimcp-gravity.onvoroa.com")).toBe(true);
      expect(isAllowedOrigin("https://app.getvoroa.com")).toBe(false); // only onvoroa.com apps
      expect(isAllowedOrigin("https://my-subdomain.onvoroa.com")).toBe(true);
    });

    it("allows other standard cloud deployment domains", () => {
      expect(isAllowedOrigin("https://my-app.railway.app")).toBe(true);
      expect(isAllowedOrigin("https://my-service.render.com")).toBe(true);
      expect(isAllowedOrigin("https://my-mcp.vercel.app")).toBe(true);
    });

    it("supports custom ALLOWED_ORIGINS environment variable", () => {
      const orig = process.env.ALLOWED_ORIGINS;
      try {
        process.env.ALLOWED_ORIGINS = "https://custom-domain.com, https://another.org";
        expect(isAllowedOrigin("https://custom-domain.com")).toBe(true);
        expect(isAllowedOrigin("https://another.org")).toBe(true);
        expect(isAllowedOrigin("https://unauthorized.com")).toBe(false);
      } finally {
        if (orig) process.env.ALLOWED_ORIGINS = orig;
        else delete process.env.ALLOWED_ORIGINS;
      }
    });

    it("rejects unauthorized untrusted domains", () => {
      expect(isAllowedOrigin("https://evil-attacker.com")).toBe(false);
      expect(isAllowedOrigin("http://phishing-site.xyz")).toBe(false);
    });
  });

  describe("Real-time Telemetry & Consolidated Dashboard Summary", () => {
    it("returns real-time telemetry timeline with buckets, histogram, and server aggregates", async () => {
      // Ingest a couple of executions
      executionHistory.recordExecution(
        "github:list_issues",
        "github",
        "list_issues",
        {},
        { issues: [] },
        "success",
        45
      );
      executionHistory.recordExecution(
        "sentry:get_issue",
        "sentry",
        "get_issue",
        {},
        undefined,
        "error",
        120,
        "Sentry API rate limited"
      );

      const res = invokePipeline(requireOperatorAuth, handleGetTelemetryTimeline, {
        headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
        query: { range: "1h" },
      });

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty("timeline");
      expect(Array.isArray(res.body.timeline)).toBe(true);
      expect(res.body.timeline.length).toBeGreaterThan(0);
      expect(res.body).toHaveProperty("histogram");
      expect(res.body.histogram).toHaveProperty("buckets");
      expect(res.body).toHaveProperty("servers");
      expect(res.body.servers).toHaveProperty("github");
      expect(res.body.servers).toHaveProperty("sentry");
      expect(res.body.servers.sentry.error).toBeGreaterThanOrEqual(1);
      expect(res.body.servers.sentry.lastError).toBeDefined();
      expect(res.body.recentErrors.length).toBeGreaterThanOrEqual(1);
      expect(res.body.summary.total).toBeGreaterThanOrEqual(2);
    });

    it("returns consolidated dashboard summary in single fast call", () => {
      const res = invokePipeline(requireOperatorAuth, handleGetDashboardSummary, {
        headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
      });

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty("stats");
      expect(res.body).toHaveProperty("health");
      expect(res.body).toHaveProperty("servers");
      expect(res.body).toHaveProperty("toolsCount");
      expect(res.body).toHaveProperty("recentHistory");
      expect(res.body).toHaveProperty("telemetry");
      expect(res.body).toHaveProperty("profiles");
      expect(res.body).toHaveProperty("tasks");
    });
  });
});
