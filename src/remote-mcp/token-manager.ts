import crypto from "node:crypto";
import { createChildLogger } from "../logger.js";
import { dbManager, DatabaseManager } from "../db.js";

const log = createChildLogger("remote-token-manager");

export interface AgentTokenRecord {
  id: string;
  tokenHash: string; // SHA-256 hash of the raw token (raw token is NEVER persisted)
  tokenPrefix: string; // e.g. "omnimcp_agent_a1b2••••" (first 18 chars for display identification)
  principalId: string;
  assignedProfileId: string; // Mandatory explicit profile assignment (e.g. "developer", "readonly")
  name: string;
  isRevoked: boolean;
  createdAt: number;
  expiresAt: number | null;
  lastUsedAt: number | null;
  revokedAt: number | null;
}

export function hashToken(token: string): string {
  return crypto.createHash("sha256").update(token.trim()).digest("hex");
}

export class RemoteTokenManager {
  private db: DatabaseManager;
  // In-memory token cache: maps SHA-256(rawToken) -> AgentTokenRecord
  private tokens = new Map<string, AgentTokenRecord>();
  private initialized = false;

  constructor(customDb?: DatabaseManager) {
    this.db = customDb || dbManager;
    this.init();
  }

  public init(): void {
    if (this.initialized) return;
    this.initialized = true;

    // 1. Load persisted tokens from SQLite
    try {
      const persisted = this.db.listAgentTokens();
      for (const tok of persisted) {
        this.tokens.set(tok.tokenHash, tok);
      }
      log.info({ count: persisted.length }, "Loaded persisted agent tokens from SQLite");
    } catch (err) {
      log.warn({ error: err }, "Could not load persisted agent tokens from SQLite");
    }

    // 2. Pre-seed tokens from environment variables without overwriting persisted tokens
    this.initializeFromEnv();
  }

  public initializeFromEnv(): void {
    // 1. Check multi-agent tokens configuration
    const multiTokensEnv = process.env.OMNIMCP_AGENT_TOKENS;
    if (multiTokensEnv && multiTokensEnv.trim()) {
      try {
        if (multiTokensEnv.trim().startsWith("{")) {
          const parsed = JSON.parse(multiTokensEnv);
          for (const [principal, config] of Object.entries(parsed)) {
            if (typeof config === "object" && config !== null) {
              const rawTok = (config as any).token;
              const profile = (config as any).profile || "developer";
              if (typeof rawTok === "string" && rawTok.trim() && rawTok.trim() !== "your_agent_token_here") {
                this.registerConfiguredToken(rawTok.trim(), principal, profile, `Env Agent (${principal})`);
              }
            } else if (typeof config === "string" && config.trim() && config.trim() !== "your_agent_token_here") {
              this.registerConfiguredToken(config.trim(), principal, "developer", `Env Agent (${principal})`);
            }
          }
        }
      } catch (err) {
        log.warn({ error: err }, "Could not parse JSON in OMNIMCP_AGENT_TOKENS");
      }
    }

    // 2. Check standard master agent token
    const masterToken = process.env.OMNIMCP_AGENT_TOKEN || process.env.OMNIMCP_AUTH_TOKEN;
    if (masterToken && masterToken.trim() && masterToken.trim() !== "your_agent_token_here") {
      const assignedProfile = process.env.OMNIMCP_DEFAULT_AGENT_PROFILE || "developer";
      this.registerConfiguredToken(
        masterToken.trim(),
        "master_agent_principal",
        assignedProfile,
        "Master Agent Token (Configured in .env)"
      );
    }
  }

  private registerConfiguredToken(
    rawToken: string,
    principalId: string,
    assignedProfileId: string,
    name: string
  ): AgentTokenRecord {
    const tokenHash = hashToken(rawToken);

    // If token already exists in memory/SQLite, do not overwrite (respect persistent state like revocation)
    const existing = this.tokens.get(tokenHash) || this.db.getAgentTokenByHash(tokenHash);
    if (existing) {
      this.tokens.set(tokenHash, existing);
      return existing;
    }

    const record: AgentTokenRecord = {
      id: "tok_" + crypto.randomBytes(8).toString("hex"),
      tokenHash,
      tokenPrefix: rawToken.substring(0, Math.min(rawToken.length, 18)) + "••••",
      principalId,
      assignedProfileId,
      name,
      isRevoked: false,
      createdAt: Date.now(),
      expiresAt: null,
      lastUsedAt: null,
      revokedAt: null,
    };

    try {
      this.db.upsertAgentToken(record);
    } catch (err) {
      log.warn({ error: err }, "Failed to persist env-configured agent token to SQLite; retaining in-memory");
    }

    this.tokens.set(tokenHash, record);
    log.info(
      { tokenId: record.id, principalId, assignedProfileId, name },
      "Registered static agent credential with explicit profile assignment"
    );
    return record;
  }

  public createToken(input: {
    principalId: string;
    assignedProfileId: string;
    name?: string;
    expiresAt?: number | null;
  }): { rawToken: string; record: AgentTokenRecord } {
    if (!input.principalId || !input.principalId.trim()) {
      throw new Error("principalId is required to create an agent token.");
    }
    if (!input.assignedProfileId || !input.assignedProfileId.trim()) {
      throw new Error("Mandatory security requirement: Every agent token must have an explicit assignedProfileId.");
    }

    // Verify profile exists in database
    const profile = this.db.getProfile(input.assignedProfileId.trim());
    if (!profile) {
      throw new Error(`Cannot assign non-existent profile '${input.assignedProfileId}'.`);
    }

    // Generate 256 bits of CSPRNG entropy
    const rawToken = "omnimcp_agent_" + crypto.randomBytes(32).toString("hex");
    const tokenHash = hashToken(rawToken);

    const record: AgentTokenRecord = {
      id: "tok_" + crypto.randomBytes(8).toString("hex"),
      tokenHash,
      tokenPrefix: rawToken.substring(0, 18) + "••••",
      principalId: input.principalId.trim(),
      assignedProfileId: input.assignedProfileId.trim(),
      name: input.name?.trim() || `Agent (${input.principalId.trim()})`,
      isRevoked: false,
      createdAt: Date.now(),
      expiresAt: input.expiresAt || null,
      lastUsedAt: null,
      revokedAt: null,
    };

    // Persist to SQLite
    this.db.upsertAgentToken(record);

    // Update in-memory cache
    this.tokens.set(tokenHash, record);

    log.info(
      { tokenId: record.id, principalId: record.principalId, profileId: record.assignedProfileId },
      "Created and persisted new secure agent token with bound profile"
    );

    return { rawToken, record };
  }

  public resolveToken(rawToken: string | undefined): AgentTokenRecord | null {
    if (!rawToken || typeof rawToken !== "string") return null;
    const trimmed = rawToken.trim();
    if (!trimmed || trimmed === "your_agent_token_here") return null;

    const tokenHash = hashToken(trimmed);

    // Check memory cache or SQLite
    let record = this.tokens.get(tokenHash);
    if (!record) {
      record = this.db.getAgentTokenByHash(tokenHash) || undefined;
      if (record) {
        this.tokens.set(tokenHash, record);
      }
    }

    if (!record) return null;

    // Check revocation
    if (record.isRevoked) {
      log.warn({ tokenId: record.id, principalId: record.principalId }, "Authentication attempt with revoked token");
      return null;
    }

    // Check expiration
    if (record.expiresAt && Date.now() > record.expiresAt) {
      log.warn(
        { tokenId: record.id, principalId: record.principalId, expiresAt: record.expiresAt },
        "Authentication attempt with expired token"
      );
      return null;
    }

    // Update last used timestamp
    const now = Date.now();
    record.lastUsedAt = now;
    try {
      this.db.updateAgentTokenLastUsed(tokenHash, now);
    } catch (err) {
      log.warn({ error: err }, "Failed to update last_used_at in SQLite");
    }

    return record;
  }

  public revokeToken(tokenIdOrHash: string): boolean {
    const revokedAt = Date.now();
    let found = false;

    // Update in SQLite
    const dbRevoked = this.db.revokeAgentToken(tokenIdOrHash, revokedAt);
    if (dbRevoked) found = true;

    // Update in-memory cache
    for (const [hash, record] of this.tokens.entries()) {
      if (record.id === tokenIdOrHash || hash === tokenIdOrHash) {
        record.isRevoked = true;
        record.revokedAt = revokedAt;
        found = true;
        log.warn(
          { tokenId: record.id, principalId: record.principalId },
          "Agent token revoked. Access terminated immediately."
        );
      }
    }

    return found;
  }

  public rotateToken(tokenId: string): { newRawToken: string; newRecord: AgentTokenRecord } | null {
    let target = this.db.getAgentTokenById(tokenId);
    if (!target) {
      for (const record of this.tokens.values()) {
        if (record.id === tokenId) {
          target = record;
          break;
        }
      }
    }

    if (!target) return null;

    // Revoke old token
    this.revokeToken(target.id);

    // Issue new token with exact same permissions
    const created = this.createToken({
      principalId: target.principalId,
      assignedProfileId: target.assignedProfileId,
      name: `${target.name} (Rotated)`,
    });

    return {
      newRawToken: created.rawToken,
      newRecord: created.record,
    };
  }

  public listTokens(): Omit<AgentTokenRecord, "tokenHash">[] {
    const records = this.db.listAgentTokens();
    // Return sanitized records, completely omitting tokenHash
    return records.map(({ tokenHash: _, ...safe }) => safe);
  }

  public clearAllForTesting(): void {
    this.tokens.clear();
    this.initialized = false;
  }
}

export const remoteTokenManager = new RemoteTokenManager();
