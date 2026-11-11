import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  isDownstreamToolError,
  classifyDownstreamResponse,
  extractDownstreamErrorMessage,
  executionEngine,
} from "../src/executor.js";
import { clientManager } from "../src/client-manager.js";
import { discoveryEngine } from "../src/discovery.js";
import { serverRegistry } from "../src/registry.js";
import { executionHistory } from "../src/history.js";
import { profilesManager } from "../src/profiles.js";
import { DiscoveredTool } from "../src/types.js";

describe("Phase 3.2 — Downstream Error Propagation & Protocol Normalization", () => {
  beforeEach(() => {
    executionHistory.clearHistory();
  });

  describe("1. MCP Specification Conformance (classifyDownstreamResponse & isDownstreamToolError)", () => {
    it("Case 1: should classify standard MCP CallToolResult with isError: true as tool_error", () => {
      const res = {
        content: [{ type: "text", text: "Error: Failed to list blocks from shadcn/ui repository" }],
        isError: true,
      };
      const classification = classifyDownstreamResponse(res);
      expect(classification.kind).toBe("tool_error");
      if (classification.kind === "tool_error") {
        expect(classification.errorMessage).toBe("Error: Failed to list blocks from shadcn/ui repository");
      }
      expect(isDownstreamToolError(res)).toBe(true);
    });

    it("Case 2: should classify standard MCP CallToolResult with isError: false as success", () => {
      const res = {
        content: [{ type: "text", text: "Everything worked fine" }],
        isError: false,
      };
      const classification = classifyDownstreamResponse(res);
      expect(classification.kind).toBe("success");
      expect(isDownstreamToolError(res)).toBe(false);
    });

    it("Case 3: should classify standard MCP CallToolResult without isError (absent) as success", () => {
      const res = {
        content: [{ type: "text", text: "Heading 1\nParagraph text" }],
      };
      const classification = classifyDownstreamResponse(res);
      expect(classification.kind).toBe("success");
      expect(isDownstreamToolError(res)).toBe(false);
    });

    it("Case 4: should reject truthy non-boolean isError (e.g. 'true') as a protocol violation", () => {
      const res = {
        content: [{ type: "text", text: "Operation message" }],
        isError: "true",
      };
      const classification = classifyDownstreamResponse(res);
      expect(classification.kind).toBe("invalid_response");
      if (classification.kind === "invalid_response") {
        expect(classification.errorMessage).toContain("Protocol violation: Downstream MCP 'isError' field must be a boolean");
      }
      expect(isDownstreamToolError(res)).toBe(true);
    });

    it("Case 4b: should reject numeric isError (e.g. 1) as a protocol violation", () => {
      const res = {
        content: [{ type: "text", text: "Operation message" }],
        isError: 1,
      };
      const classification = classifyDownstreamResponse(res);
      expect(classification.kind).toBe("invalid_response");
      if (classification.kind === "invalid_response") {
        expect(classification.errorMessage).toContain("Protocol violation");
      }
      expect(isDownstreamToolError(res)).toBe(true);
    });

    it("Case 5: should reject responses missing a 'content' array as invalid protocol responses", () => {
      const res = { unexpectedField: "no content array provided" };
      const classification = classifyDownstreamResponse(res);
      expect(classification.kind).toBe("invalid_response");
      if (classification.kind === "invalid_response") {
        expect(classification.errorMessage).toContain("missing 'content' array");
      }
      expect(isDownstreamToolError(res)).toBe(true);
    });

    it("Case 5b: should classify null, undefined, primitive, or array responses as invalid_response", () => {
      expect(classifyDownstreamResponse(null).kind).toBe("invalid_response");
      expect(classifyDownstreamResponse(undefined).kind).toBe("invalid_response");
      expect(classifyDownstreamResponse("unexpected string").kind).toBe("invalid_response");
      expect(classifyDownstreamResponse(12345).kind).toBe("invalid_response");
      expect(classifyDownstreamResponse([]).kind).toBe("invalid_response");

      expect(isDownstreamToolError(null)).toBe(true);
      expect(isDownstreamToolError(undefined)).toBe(true);
      expect(isDownstreamToolError("unexpected string")).toBe(true);
      expect(isDownstreamToolError(12345)).toBe(true);
    });

    it("should classify responses with JSON-RPC error property as tool_error", () => {
      const res = { error: { code: -32603, message: "Database connection failed" } };
      const classification = classifyDownstreamResponse(res);
      expect(classification.kind).toBe("tool_error");
      expect(isDownstreamToolError(res)).toBe(true);
    });
  });

  describe("2. Error Message Extraction & Secret Redaction (extractDownstreamErrorMessage)", () => {
    it("should extract human-readable text from standard MCP content array", () => {
      const res = {
        content: [
          { type: "text", text: "Error: Component 'button' not found in registry" },
        ],
        isError: true,
      };
      const msg = extractDownstreamErrorMessage(res);
      expect(msg).toBe("Error: Component 'button' not found in registry");
    });

    it("should concatenate multiple text blocks in content array", () => {
      const res = {
        content: [
          { type: "text", text: "Error: Step 1 failed." },
          { type: "text", text: "Details: Database connection refused." },
        ],
        isError: true,
      };
      const msg = extractDownstreamErrorMessage(res);
      expect(msg).toContain("Error: Step 1 failed.");
      expect(msg).toContain("Details: Database connection refused.");
    });

    it("should redact sensitive tokens or credentials in downstream error messages", () => {
      const res = {
        content: [
          {
            type: "text",
            text: "Failed authentication for token: omnimcp_appr_1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
          },
        ],
        isError: true,
      };
      const msg = extractDownstreamErrorMessage(res);
      expect(msg).not.toContain("omnimcp_appr_1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
      expect(msg).toContain("[REDACTED_SECRET]");
    });

    it("should handle error property with object message", () => {
      const res = {
        error: { code: 500, message: "Downstream API unavailable" },
      };
      expect(extractDownstreamErrorMessage(res)).toBe("Downstream API unavailable");
    });

    it("should handle null or undefined safely", () => {
      expect(extractDownstreamErrorMessage(null)).toBe("Downstream tool returned an empty response");
      expect(extractDownstreamErrorMessage(undefined)).toBe("Downstream tool returned an empty response");
    });
  });

  describe("3. Execution Engine Integration & Audit Log Classification", () => {
    const mockServerId = "mock_test_server";
    const mockToolId = "mock_test_server:test_operation";

    const mockTool: DiscoveredTool = {
      id: mockToolId,
      serverId: mockServerId,
      originalName: "test_operation",
      serverName: "Mock Test Server",
      description: "Mock test tool for error propagation",
      inputSchema: { type: "object", properties: {} },
      permissionLevel: "READ_ONLY",
      requiresApproval: false,
    };

    beforeEach(() => {
      vi.spyOn(profilesManager, "evaluateToolAccess").mockReturnValue({ allowed: true });
      vi.spyOn(discoveryEngine, "getTool").mockReturnValue(mockTool);
      vi.spyOn(serverRegistry, "getServer").mockReturnValue({
        id: mockServerId,
        name: "Mock Test Server",
        description: "Test Server",
        category: "development",
        transport: "stdio",
        enabled: true,
        autoConnect: false,
        command: "node",
        args: [],
        allowedPermissions: ["READ_ONLY", "WRITE_PROTECTED", "DESTRUCTIVE_ADMIN"],
        requiresApprovalForDestructive: false,
      } as any);
    });

    afterEach(() => {
      vi.restoreAllMocks();
    });

    it("Case 1 (Live): should classify downstream isError: true as status: 'error' and preserve original content", async () => {
      const mockResult = {
        content: [
          { type: "text", text: "Error: Failed to list blocks from shadcn/ui repository" },
        ],
        isError: true,
      };

      const mockClient = {
        callTool: vi.fn().mockResolvedValue(mockResult),
      };
      vi.spyOn(clientManager, "getClient").mockReturnValue(mockClient as any);

      const result = await executionEngine.executeTool(mockToolId, {});

      // 1. Gateway response must be 'error', NOT 'success'
      expect(result.status).toBe("error");
      expect(result.toolId).toBe(mockToolId);
      expect(result.serverId).toBe(mockServerId);
      expect(result.error).toBe("Error: Failed to list blocks from shadcn/ui repository");

      // 2. Original downstream content structure is preserved
      expect(result.content).toEqual(mockResult);

      // 3. Trace ID and duration are preserved
      expect(result.traceId).toBeDefined();
      expect(typeof result.traceId).toBe("string");
      expect(result.traceId.length).toBe(16);
      expect(result.durationMs).toBeGreaterThanOrEqual(0);

      // 4. Execution history records 'error', not 'success'
      const history = executionHistory.getHistory(1);
      expect(history.length).toBe(1);
      expect(history[0].status).toBe("error");
      expect(history[0].error).toBe("Error: Failed to list blocks from shadcn/ui repository");
      expect(history[0].traceId).toBe(result.traceId);
    });

    it("Case 2 & 3: should classify downstream isError: false or absent as status: 'success'", async () => {
      const mockResult = {
        content: [{ type: "text", text: "Components listed successfully: [button, dialog, card]" }],
        isError: false,
      };

      const mockClient = {
        callTool: vi.fn().mockResolvedValue(mockResult),
      };
      vi.spyOn(clientManager, "getClient").mockReturnValue(mockClient as any);

      const result = await executionEngine.executeTool(mockToolId, {});

      // Must be success
      expect(result.status).toBe("success");
      expect(result.error).toBeUndefined();
      expect(result.content).toEqual(mockResult);
      expect(result.traceId).toBeDefined();

      // Execution history records 'success'
      const history = executionHistory.getHistory(1);
      expect(history.length).toBe(1);
      expect(history[0].status).toBe("success");
      expect(history[0].error).toBeUndefined();
    });

    it("Case 4: should reject string isError: 'true' as protocol violation error", async () => {
      const mockResult = {
        content: [{ type: "text", text: "Ambiguous error string" }],
        isError: "true",
      };

      const mockClient = {
        callTool: vi.fn().mockResolvedValue(mockResult),
      };
      vi.spyOn(clientManager, "getClient").mockReturnValue(mockClient as any);

      const result = await executionEngine.executeTool(mockToolId, {});

      expect(result.status).toBe("error");
      expect(result.error).toContain("Protocol violation");
      expect(result.content).toEqual(mockResult);

      const history = executionHistory.getHistory(1);
      expect(history[0].status).toBe("error");
      expect(history[0].error).toContain("Protocol violation");
    });

    it("Case 5: should safely classify missing 'content' array as invalid protocol response", async () => {
      const mockResult = {
        result: "not valid MCP CallToolResult structure",
      };

      const mockClient = {
        callTool: vi.fn().mockResolvedValue(mockResult),
      };
      vi.spyOn(clientManager, "getClient").mockReturnValue(mockClient as any);

      const result = await executionEngine.executeTool(mockToolId, {});

      expect(result.status).toBe("error");
      expect(result.error).toContain("missing 'content' array");

      const history = executionHistory.getHistory(1);
      expect(history[0].status).toBe("error");
      expect(history[0].error).toContain("missing 'content' array");
    });

    it("Case 6: should handle transport exceptions separately as transport failures", async () => {
      const mockClient = {
        callTool: vi.fn().mockRejectedValue(new Error("Downstream process connection closed unexpectedly")),
      };
      vi.spyOn(clientManager, "getClient").mockReturnValue(mockClient as any);

      const result = await executionEngine.executeTool(mockToolId, {});

      expect(result.status).toBe("error");
      expect(result.error).toContain("Downstream process connection closed unexpectedly");
      expect(result.content).toBeNull();
      expect(result.traceId).toBeDefined();

      const history = executionHistory.getHistory(1);
      expect(history[0].status).toBe("error");
      expect(history[0].error).toContain("Downstream process connection closed unexpectedly");
    });
  });
});
