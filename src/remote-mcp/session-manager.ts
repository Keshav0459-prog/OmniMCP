import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { createChildLogger } from "../logger.js";

const log = createChildLogger("remote-session-manager");

export interface RemoteMcpSession {
  sessionId: string;
  tokenHash: string;
  principalId: string;
  assignedProfileId: string;
  createdAt: number;
  lastActivityAt: number;
  transport: StreamableHTTPServerTransport;
  server: Server;
}

export class RemoteSessionManager {
  private sessions = new Map<string, RemoteMcpSession>();
  private defaultMaxIdleMs = 30 * 60 * 1000; // 30 minutes idle timeout

  public registerSession(session: RemoteMcpSession): void {
    this.sessions.set(session.sessionId, session);
    log.info(
      { sessionId: session.sessionId, principalId: session.principalId, profileId: session.assignedProfileId },
      "Registered new remote MCP session"
    );
  }

  public getSession(sessionId: string): RemoteMcpSession | undefined {
    return this.sessions.get(sessionId);
  }

  public touchSession(sessionId: string): void {
    const s = this.sessions.get(sessionId);
    if (s) {
      s.lastActivityAt = Date.now();
    }
  }

  public verifySessionOwnership(sessionId: string, tokenHash: string): boolean {
    const s = this.sessions.get(sessionId);
    if (!s) return false;
    return s.tokenHash === tokenHash;
  }

  public async deleteSession(sessionId: string): Promise<boolean> {
    const s = this.sessions.get(sessionId);
    if (!s) return false;

    this.sessions.delete(sessionId);
    try {
      await s.transport.close();
      await s.server.close();
    } catch (err) {
      log.warn({ sessionId, error: err }, "Error while closing remote MCP session transport/server");
    }

    log.info({ sessionId, principalId: s.principalId }, "Terminated remote MCP session");
    return true;
  }

  public async cleanupExpiredSessions(maxIdleMs = this.defaultMaxIdleMs): Promise<number> {
    const now = Date.now();
    let cleaned = 0;
    for (const [sessionId, session] of this.sessions.entries()) {
      if (now - session.lastActivityAt > maxIdleMs) {
        log.info({ sessionId, principalId: session.principalId }, "Expiring idle remote MCP session");
        await this.deleteSession(sessionId);
        cleaned++;
      }
    }
    return cleaned;
  }

  public getActiveSessionsCount(): number {
    return this.sessions.size;
  }

  public getActiveSessions(): Array<Omit<RemoteMcpSession, "transport" | "server" | "tokenHash">> {
    return Array.from(this.sessions.values()).map((s) => ({
      sessionId: s.sessionId,
      principalId: s.principalId,
      assignedProfileId: s.assignedProfileId,
      createdAt: s.createdAt,
      lastActivityAt: s.lastActivityAt,
    }));
  }

  public async clearAllForTesting(): Promise<void> {
    for (const sessionId of Array.from(this.sessions.keys())) {
      await this.deleteSession(sessionId);
    }
    this.sessions.clear();
  }
}

export const remoteSessionManager = new RemoteSessionManager();
