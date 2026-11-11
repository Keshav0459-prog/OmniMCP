import { clientManager } from "./client-manager.js";
import { discoveryEngine } from "./discovery.js";
import { serverRegistry } from "./registry.js";
import { permissionManager } from "./permissions.js";
import { executionHistory } from "./history.js";
import { profilesManager } from "./profiles.js";
import { sanitizeData } from "./security.js";
import { createChildLogger } from "./logger.js";
import { telemetryManager } from "./telemetry.js";

const log = createChildLogger("executor");

export interface ExecutionOptions {
  timeoutMs?: number;
  confirmSensitive?: boolean;
  approvalToken?: string;
  profileId?: string;
}

export interface ExecutionResult {
  toolId: string;
  serverId: string;
  status: "success" | "error" | "denied";
  content: unknown;
  durationMs: number;
  error?: string;
  traceId: string;
  approvalPrompt?: unknown;
}

export type DownstreamResponseClassification =
  | { kind: "success"; content: unknown }
  | { kind: "tool_error"; errorMessage: string; content: unknown }
  | { kind: "invalid_response"; errorMessage: string; content: unknown };

/**
 * Evaluates the downstream MCP response strictly according to the Model Context Protocol (MCP) specification.
 *
 * MCP CallToolResult specification:
 * {
 *   content: (TextContent | ImageContent | AudioContent | EmbeddedResource)[];
 *   isError?: boolean;
 *   _meta?: Record<string, unknown>;
 * }
 *
 * Strict Protocol Rules:
 * 1. If null, undefined, primitive, or non-object -> invalid_response
 * 2. If 'isError' is present, it MUST be a boolean. Non-boolean types (e.g. string "true") are protocol violations -> invalid_response
 * 3. If isError === true -> tool_error (downstream operation failed)
 * 4. If content is missing or not an array (and no explicit error object) -> invalid_response
 * 5. If isError is false or absent AND content is a valid array -> success
 */
export function classifyDownstreamResponse(rawResult: unknown): DownstreamResponseClassification {
  if (rawResult === null || rawResult === undefined) {
    return {
      kind: "invalid_response",
      errorMessage: "Downstream server returned an empty response (null or undefined).",
      content: rawResult,
    };
  }

  if (typeof rawResult !== "object" || Array.isArray(rawResult)) {
    return {
      kind: "invalid_response",
      errorMessage: `Downstream server returned an invalid MCP payload type: ${typeof rawResult}. Expected object.`,
      content: rawResult,
    };
  }

  const res = rawResult as Record<string, unknown>;

  // Strict check: if 'isError' field is present, it MUST be a boolean
  if ("isError" in res && res.isError !== undefined && typeof res.isError !== "boolean") {
    return {
      kind: "invalid_response",
      errorMessage: `Protocol violation: Downstream MCP 'isError' field must be a boolean, got ${typeof res.isError}.`,
      content: rawResult,
    };
  }

  // Downstream tool operational failure (MCP CallToolResult with isError === true)
  if (res.isError === true) {
    const errorMsg = extractDownstreamErrorMessage(rawResult);
    return {
      kind: "tool_error",
      errorMessage: errorMsg,
      content: rawResult,
    };
  }

  // Validate structural conformance: MCP tool response must contain an array of content items
  if (!Array.isArray(res.content)) {
    // If child returned an explicit error object in lieu of standard CallToolResult
    if (res.error !== undefined && res.error !== null) {
      const errorMsg = extractDownstreamErrorMessage(rawResult);
      return {
        kind: "tool_error",
        errorMessage: errorMsg,
        content: rawResult,
      };
    }

    return {
      kind: "invalid_response",
      errorMessage: "Downstream server returned an invalid MCP tool response: missing 'content' array.",
      content: rawResult,
    };
  }

  // Valid successful MCP response (isError === false or absent, content is a valid array)
  return {
    kind: "success",
    content: rawResult,
  };
}

/**
 * Backward-compatible helper checking whether the response represents an operational tool error or protocol invalidity.
 */
export function isDownstreamToolError(rawResult: unknown): boolean {
  const classification = classifyDownstreamResponse(rawResult);
  return classification.kind === "tool_error" || classification.kind === "invalid_response";
}

/**
 * Extracts a human-readable, sanitized error string from downstream tool error responses.
 * Preserves downstream error details while ensuring no secrets or internal stack traces leak.
 */
export function extractDownstreamErrorMessage(rawResult: unknown): string {
  if (rawResult === null || rawResult === undefined) {
    return "Downstream tool returned an empty response";
  }
  if (typeof rawResult !== "object") {
    return String(sanitizeData(rawResult));
  }

  const res = rawResult as Record<string, unknown>;

  // 1. Check MCP standard content array for text messages
  if (Array.isArray(res.content)) {
    const textPieces = res.content
      .map((item) => {
        if (typeof item === "string") return item.trim();
        if (item && typeof item === "object" && typeof (item as any).text === "string") {
          return (item as any).text.trim();
        }
        return "";
      })
      .filter((t) => t.length > 0);

    if (textPieces.length > 0) {
      return String(sanitizeData(textPieces.join("\n")));
    }
  }

  // 2. Check error property
  if (typeof res.error === "string" && res.error.trim()) {
    return String(sanitizeData(res.error.trim()));
  }
  if (res.error && typeof res.error === "object") {
    const errObj = res.error as Record<string, unknown>;
    if (typeof errObj.message === "string" && errObj.message.trim()) {
      return String(sanitizeData(errObj.message.trim()));
    }
  }

  // 3. Check message property
  if (typeof res.message === "string" && res.message.trim()) {
    return String(sanitizeData(res.message.trim()));
  }

  return "Downstream tool reported an error (isError: true)";
}

function truncatePayload(data: unknown, maxLen = 10000): unknown {
  if (typeof data === "string") {
    if (data.length > maxLen) {
      return data.substring(0, maxLen) + `... [TRUNCATED ${data.length - maxLen} CHARS]`;
    }
    return data;
  }
  if (Array.isArray(data)) {
    return data.map((item) => truncatePayload(item, maxLen));
  }
  if (typeof data === "object" && data !== null) {
    const res: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(data)) {
      res[k] = truncatePayload(v, maxLen);
    }
    return res;
  }
  return data;
}

export class ToolExecutionEngine {
  private defaultTimeoutMs = 30000;

  public async executeTool(
    toolId: string,
    parameters: Record<string, unknown> = {},
    options: ExecutionOptions = {}
  ): Promise<ExecutionResult> {
    telemetryManager.incrementInFlight();
    try {
      return await this.executeToolInternal(toolId, parameters, options);
    } finally {
      telemetryManager.decrementInFlight();
    }
  }

  private async executeToolInternal(
    toolId: string,
    parameters: Record<string, unknown> = {},
    options: ExecutionOptions = {}
  ): Promise<ExecutionResult> {
    const startTime = Date.now();

    // 1. Resolve Tool
    let tool = discoveryEngine.getTool(toolId);

    // If tool not in cache, try splitting by colon to find server and discover
    if (!tool && toolId.includes(":")) {
      const [serverId] = toolId.split(":");
      await discoveryEngine.discoverServerTools(serverId);
      tool = discoveryEngine.getTool(toolId);
    }

    const defaultTimeout = (toolId.startsWith("stitch:") || tool?.serverId === "stitch")
      ? (Number(process.env.STITCH_TIMEOUT_MS) || 120000)
      : this.defaultTimeoutMs;
    const timeoutMs = options.timeoutMs || defaultTimeout;

    if (!tool) {
      const err = `Tool '${toolId}' is not found in discovered tools. Run 'search_tools' to inspect available tools.`;
      const record = executionHistory.recordExecution(
        toolId,
        "unknown",
        toolId,
        truncatePayload(parameters) as Record<string, unknown>,
        undefined,
        "error",
        Date.now() - startTime,
        err
      );
      return {
        toolId,
        serverId: "unknown",
        status: "error",
        content: null,
        durationMs: Date.now() - startTime,
        error: err,
        traceId: record.traceId,
      };
    }

    const serverState = serverRegistry.getServer(tool.serverId);
    if (!serverState) {
      const err = `Server '${tool.serverId}' not found in registry.`;
      const record = executionHistory.recordExecution(
        toolId,
        tool.serverId,
        tool.originalName,
        truncatePayload(parameters) as Record<string, unknown>,
        undefined,
        "error",
        Date.now() - startTime,
        err
      );
      return {
        toolId,
        serverId: tool.serverId,
        status: "error",
        content: null,
        durationMs: Date.now() - startTime,
        error: err,
        traceId: record.traceId,
      };
    }

    // 2. Active Profile Check (Enforces server integration, granular overrides, and Read-Only bounds)
    const profileCheck = profilesManager.evaluateToolAccess(toolId, tool.serverId, tool.permissionLevel, options.profileId);
    if (!profileCheck.allowed) {
      const err = profileCheck.reason || "Execution denied: Tool not permitted under the active profile.";
      const record = executionHistory.recordExecution(
        toolId,
        tool.serverId,
        tool.originalName,
        truncatePayload(parameters) as Record<string, unknown>,
        undefined,
        "denied",
        Date.now() - startTime,
        err
      );
      log.warn({ toolId, reason: err }, "Tool execution denied by active profile");
      return {
        toolId,
        serverId: tool.serverId,
        status: "denied",
        content: null,
        durationMs: Date.now() - startTime,
        error: err,
        traceId: record.traceId,
      };
    }

    // 3. Permission Check
    const permCheck = permissionManager.checkExecutionAllowed(
      tool,
      serverState,
      options.confirmSensitive,
      options.approvalToken,
      parameters
    );
    if (!permCheck.allowed) {
      const err = permCheck.reason || "Execution denied by permission policy.";
      const record = executionHistory.recordExecution(
        toolId,
        tool.serverId,
        tool.originalName,
        truncatePayload(parameters) as Record<string, unknown>,
        undefined,
        "denied",
        Date.now() - startTime,
        err
      );
      log.warn({ toolId, reason: err }, "Tool execution denied by permission check");
      return {
        toolId,
        serverId: tool.serverId,
        status: "denied",
        content: null,
        durationMs: Date.now() - startTime,
        error: err,
        traceId: record.traceId,
        approvalPrompt: permCheck.approvalPrompt,
      };
    }

    // 3. Ensure Client is Connected
    let client = clientManager.getClient(tool.serverId);
    if (!client) {
      log.info({ serverId: tool.serverId }, "Server not connected, auto-connecting on demand");
      try {
        client = await clientManager.connectServer(serverState);
      } catch (connErr: unknown) {
        const err = `Failed to connect to child server '${tool.serverId}': ${
          connErr instanceof Error ? connErr.message : String(connErr)
        }`;
        const record = executionHistory.recordExecution(
          toolId,
          tool.serverId,
          tool.originalName,
          truncatePayload(parameters) as Record<string, unknown>,
          undefined,
          "error",
          Date.now() - startTime,
          err
        );
        return {
          toolId,
          serverId: tool.serverId,
          status: "error",
          content: null,
          durationMs: Date.now() - startTime,
          error: err,
          traceId: record.traceId,
        };
      }
    }

    // 4. Execute with Active Timeout & Transport Cancellation
    const abortController = new AbortController();
    let timeoutHandle: NodeJS.Timeout | undefined;

    const timeoutPromise = new Promise<never>((_, reject) => {
      timeoutHandle = setTimeout(() => {
        abortController.abort(new Error(`Tool execution timed out after ${timeoutMs}ms`));
        reject(new Error(`Tool execution timed out after ${timeoutMs}ms`));
      }, timeoutMs);
    });

    try {
      const callPromise = client.callTool(
        {
          name: tool.originalName,
          arguments: parameters,
        },
        undefined,
        {
          signal: abortController.signal,
          timeout: timeoutMs,
        }
      );

      const rawResult = await Promise.race([callPromise, timeoutPromise]);
      if (timeoutHandle) clearTimeout(timeoutHandle);

      const durationMs = Date.now() - startTime;
      const sanitizedContent = sanitizeData(rawResult);

      // Validate and classify response against the official MCP specification
      const classification = classifyDownstreamResponse(rawResult);

      if (classification.kind !== "success") {
        const errorMessage = classification.errorMessage;

        const record = executionHistory.recordExecution(
          toolId,
          tool.serverId,
          tool.originalName,
          truncatePayload(parameters) as Record<string, unknown>,
          truncatePayload(sanitizedContent),
          "error",
          durationMs,
          errorMessage
        );

        log.warn(
          { toolId, durationMs, error: errorMessage, kind: classification.kind, traceId: record.traceId },
          classification.kind === "tool_error"
            ? "Downstream tool reported execution error (isError: true)"
            : "Downstream server returned an invalid or malformed MCP response"
        );

        return {
          toolId,
          serverId: tool.serverId,
          status: "error",
          content: sanitizedContent,
          durationMs,
          error: errorMessage,
          traceId: record.traceId,
        };
      }

      const record = executionHistory.recordExecution(
        toolId,
        tool.serverId,
        tool.originalName,
        truncatePayload(parameters) as Record<string, unknown>,
        truncatePayload(sanitizedContent),
        "success",
        durationMs
      );

      log.info({ toolId, durationMs, traceId: record.traceId }, "Tool executed successfully");

      return {
        toolId,
        serverId: tool.serverId,
        status: "success",
        content: sanitizedContent,
        durationMs,
        traceId: record.traceId,
      };
    } catch (execErr: unknown) {
      if (timeoutHandle) clearTimeout(timeoutHandle);
      abortController.abort();

      const durationMs = Date.now() - startTime;
      const errorMessage = execErr instanceof Error ? execErr.message : String(execErr);

      const record = executionHistory.recordExecution(
        toolId,
        tool.serverId,
        tool.originalName,
        truncatePayload(parameters) as Record<string, unknown>,
        undefined,
        "error",
        durationMs,
        errorMessage
      );

      log.error({ toolId, durationMs, error: errorMessage, traceId: record.traceId }, "Tool execution failed");

      return {
        toolId,
        serverId: tool.serverId,
        status: "error",
        content: null,
        durationMs,
        error: errorMessage,
        traceId: record.traceId,
      };
    }
  }
}

export const executionEngine = new ToolExecutionEngine();
