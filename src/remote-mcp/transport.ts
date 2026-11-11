import express, { Request, Response, Router } from "express";
import crypto from "node:crypto";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { remoteTokenManager } from "./token-manager.js";
import { remoteSessionManager, RemoteMcpSession } from "./session-manager.js";
import { createRemoteMcpServer } from "./server-factory.js";
import { createChildLogger } from "../logger.js";

const log = createChildLogger("remote-transport");

function extractBearerToken(req: Request): string | null {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.toLowerCase().startsWith("bearer ")) {
    return authHeader.substring(7).trim();
  }
  const customHeader = req.headers["x-omnimcp-token"];
  if (typeof customHeader === "string" && customHeader.trim()) {
    return customHeader.trim();
  }
  return null;
}

export function createRemoteMcpRouter(): Router {
  const router = express.Router();

  // All /mcp methods (POST, GET, DELETE) share this unified handler
  router.all("/", async (req: Request, res: Response): Promise<void> => {
    // 1. Authenticate Request
    const rawToken = extractBearerToken(req);
    if (!rawToken) {
      log.warn({ path: req.path, method: req.method }, "Rejecting unauthenticated MCP request");
      res.status(401).json({
        jsonrpc: "2.0",
        error: {
          code: -32000,
          message: "Unauthorized: Missing agent authentication credentials. Supply 'Authorization: Bearer <agent_token>'.",
        },
        id: null,
      });
      return;
    }

    // 2. Check for Mcp-Session-Id header
    const rawSessionId = req.headers["mcp-session-id"];
    const sessionId = typeof rawSessionId === "string" ? rawSessionId.trim() : undefined;

    const tokenRecord = remoteTokenManager.resolveToken(rawToken);
    if (!tokenRecord) {
      if (sessionId) {
        await remoteSessionManager.deleteSession(sessionId);
      }
      log.warn({ path: req.path, method: req.method }, "Rejecting invalid or revoked agent token");
      res.status(401).json({
        jsonrpc: "2.0",
        error: {
          code: -32000,
          message: "Unauthorized: Invalid or revoked agent token.",
        },
        id: null,
      });
      return;
    }

    if (sessionId) {
      // Session-bound request: tools/call, tools/list, GET SSE, DELETE
      const session = remoteSessionManager.getSession(sessionId);
      if (!session) {
        log.warn({ sessionId }, "MCP request referencing unknown or expired session");
        res.status(404).json({
          jsonrpc: "2.0",
          error: {
            code: -32001,
            message: `Session '${sessionId}' not found or has expired.`,
          },
          id: null,
        });
        return;
      }

      // Mandatory Security Check: Strict session ownership verification
      const isOwner = remoteSessionManager.verifySessionOwnership(sessionId, tokenRecord.tokenHash);
      if (!isOwner) {
        log.warn(
          {
            sessionId,
            requestingPrincipal: tokenRecord.principalId,
            sessionPrincipal: session.principalId,
          },
          "Cross-session access rejected: Authenticated token does not own this session"
        );
        res.status(403).json({
          jsonrpc: "2.0",
          error: {
            code: -32002,
            message: "Forbidden: You do not have permission to access this MCP session.",
          },
          id: null,
        });
        return;
      }

      // Valid session owner - touch activity timestamp
      remoteSessionManager.touchSession(sessionId);

      try {
        await session.transport.handleRequest(req, res, req.body);
        if (req.method === "DELETE") {
          await remoteSessionManager.deleteSession(sessionId);
        }
      } catch (err: unknown) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        log.error({ sessionId, error: errorMsg }, "Error handling MCP session request");
        if (!res.headersSent) {
          res.status(500).json({
            jsonrpc: "2.0",
            error: {
              code: -32603,
              message: `Internal error: ${errorMsg}`,
            },
            id: null,
          });
        }
      }
      return;
    }

    // 3. No Mcp-Session-Id header present
    // Check if this is an MCP initialize request
    const isInit =
      req.method === "POST" &&
      ((req.body && req.body.method === "initialize") ||
        (Array.isArray(req.body) && req.body.some((m: any) => m && m.method === "initialize")));

    if (isInit) {
      // Allocate a new cryptographically isolated session
      const newSessionId = crypto.randomUUID();
      const sessionContext = {
        sessionId: newSessionId,
        principalId: tokenRecord.principalId,
        assignedProfileId: tokenRecord.assignedProfileId,
      };

      log.info(
        {
          sessionId: newSessionId,
          principalId: tokenRecord.principalId,
          profileId: tokenRecord.assignedProfileId,
        },
        "Initializing new remote MCP session with bound profile"
      );

      const server = createRemoteMcpServer(sessionContext);
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => newSessionId,
        onsessionclosed: async (closedId) => {
          await remoteSessionManager.deleteSession(closedId);
        },
      });

      try {
        await server.connect(transport);

        const session: RemoteMcpSession = {
          sessionId: newSessionId,
          tokenHash: tokenRecord.tokenHash,
          principalId: tokenRecord.principalId,
          assignedProfileId: tokenRecord.assignedProfileId,
          createdAt: Date.now(),
          lastActivityAt: Date.now(),
          transport,
          server,
        };

        remoteSessionManager.registerSession(session);
        await transport.handleRequest(req, res, req.body);
      } catch (err: unknown) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        log.error({ sessionId: newSessionId, error: errorMsg }, "Error during MCP session initialization");
        await remoteSessionManager.deleteSession(newSessionId);
        if (!res.headersSent) {
          res.status(500).json({
            jsonrpc: "2.0",
            error: {
              code: -32603,
              message: `Initialization failed: ${errorMsg}`,
            },
            id: null,
          });
        }
      }
      return;
    }

    // Non-initialization request without Mcp-Session-Id header
    log.warn({ method: req.method }, "Rejecting non-initialization request missing Mcp-Session-Id");
    res.status(400).json({
      jsonrpc: "2.0",
      error: {
        code: -32600,
        message: "Bad Request: Mcp-Session-Id header is required for non-initialization requests.",
      },
      id: null,
    });
  });

  return router;
}
