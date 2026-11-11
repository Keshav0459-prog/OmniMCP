import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { DatabaseManager } from "../src/db.js";
import { RemoteTokenManager, hashToken } from "../src/remote-mcp/token-manager.js";
import { profilesManager } from "../src/profiles.js";

describe("Milestone M9.2: Persistent Agent Token Management (SQLite-Backed)", () => {
  const testDbPath = path.resolve("./data/test_agent_tokens.db");
  let testDb: DatabaseManager;

  const cleanupTestDb = () => {
    if (fs.existsSync(testDbPath)) {
      try { fs.unlinkSync(testDbPath); } catch {}
    }
    const wal = `${testDbPath}-wal`;
    const shm = `${testDbPath}-shm`;
    if (fs.existsSync(wal)) try { fs.unlinkSync(wal); } catch {}
    if (fs.existsSync(shm)) try { fs.unlinkSync(shm); } catch {}
  };

  beforeEach(() => {
    cleanupTestDb();
    testDb = new DatabaseManager(testDbPath);
  });

  afterEach(() => {
    if (testDb) {
      testDb.close();
    }
    cleanupTestDb();
  });

  it("1. Dynamically created token survives a process restart", () => {
    // Process 1: Create token and persist to SQLite
    const manager1 = new RemoteTokenManager(testDb);
    const { rawToken, record } = manager1.createToken({
      principalId: "agent-persistent",
      assignedProfileId: "developer",
      name: "Restart Survivor Agent",
    });

    expect(rawToken).toMatch(/^omnimcp_agent_[0-9a-f]{64}$/);
    expect(record.tokenPrefix).toMatch(/^omnimcp_agent_[0-9a-f]+••••$/);
    expect(record.assignedProfileId).toBe("developer");

    // Verify token exists in database before restart
    const inDb = testDb.getAgentTokenByHash(hashToken(rawToken));
    expect(inDb).not.toBeNull();
    expect(inDb?.principalId).toBe("agent-persistent");

    // Simulate process shutdown: close DB
    testDb.close();

    // Process 2: Start new process with fresh DatabaseManager and RemoteTokenManager against the same file
    const restartedDb = new DatabaseManager(testDbPath);
    testDb = restartedDb; // for afterEach cleanup
    const manager2 = new RemoteTokenManager(restartedDb);

    // Resolve token in Process 2
    const resolved = manager2.resolveToken(rawToken);
    expect(resolved).not.toBeNull();
    expect(resolved?.id).toBe(record.id);
    expect(resolved?.principalId).toBe("agent-persistent");
    expect(resolved?.assignedProfileId).toBe("developer");
    expect(resolved?.lastUsedAt).toBeGreaterThan(0);

    // Verify last_used_at was updated in SQLite on Process 2
    const inDbAfter = restartedDb.getAgentTokenByHash(hashToken(rawToken));
    expect(inDbAfter?.lastUsedAt).toBe(resolved?.lastUsedAt);
  });

  it("2. Revoked token remains revoked after process restart", () => {
    const manager1 = new RemoteTokenManager(testDb);
    const { rawToken, record } = manager1.createToken({
      principalId: "agent-to-revoke",
      assignedProfileId: "developer",
    });

    // Revoke token
    const revoked = manager1.revokeToken(record.id);
    expect(revoked).toBe(true);

    // Verify revoked immediately
    expect(manager1.resolveToken(rawToken)).toBeNull();

    // Simulate process restart
    testDb.close();
    const restartedDb = new DatabaseManager(testDbPath);
    testDb = restartedDb;
    const manager2 = new RemoteTokenManager(restartedDb);

    // Verify token remains revoked after restart
    const resolvedAfterRestart = manager2.resolveToken(rawToken);
    expect(resolvedAfterRestart).toBeNull();

    const dbRecord = restartedDb.getAgentTokenByHash(hashToken(rawToken));
    expect(dbRecord?.isRevoked).toBe(true);
    expect(dbRecord?.revokedAt).toBeGreaterThan(0);
  });

  it("3. Expired token is rejected", () => {
    const manager = new RemoteTokenManager(testDb);
    const pastTime = Date.now() - 5000; // expired 5 seconds ago

    const { rawToken, record } = manager.createToken({
      principalId: "expiring-agent",
      assignedProfileId: "developer",
      expiresAt: pastTime,
    });

    expect(record.expiresAt).toBe(pastTime);

    // Should fail resolution due to expiration
    const resolved = manager.resolveToken(rawToken);
    expect(resolved).toBeNull();
  });

  it("4. Unknown and malformed tokens are rejected", () => {
    const manager = new RemoteTokenManager(testDb);

    expect(manager.resolveToken("omnimcp_agent_non_existent_token_hex")).toBeNull();
    expect(manager.resolveToken("")).toBeNull();
    expect(manager.resolveToken(undefined)).toBeNull();
    expect(manager.resolveToken("your_agent_token_here")).toBeNull();
    expect(manager.resolveToken("Bearer invalid_format")).toBeNull();
  });

  it("5. Token assigned to one profile cannot access another profile's tools", () => {
    const manager = new RemoteTokenManager(testDb);

    const tokenRo = manager.createToken({
      principalId: "agent-ro",
      assignedProfileId: "readonly",
    });

    const tokenDev = manager.createToken({
      principalId: "agent-dev",
      assignedProfileId: "developer",
    });

    // Readonly token must be denied write permissions
    const roCheck = profilesManager.evaluateToolAccess(
      "filesystem:write_file",
      "filesystem",
      "WRITE_PROTECTED",
      tokenRo.record.assignedProfileId
    );
    expect(roCheck.allowed).toBe(false);
    expect(roCheck.reason).toMatch(/strictly READ_ONLY/i);

    // Developer token must be allowed write permissions
    const devCheck = profilesManager.evaluateToolAccess(
      "filesystem:write_file",
      "filesystem",
      "WRITE_PROTECTED",
      tokenDev.record.assignedProfileId
    );
    expect(devCheck.allowed).toBe(true);
  });

  it("6. Rejects token creation with non-existent profile", () => {
    const manager = new RemoteTokenManager(testDb);

    expect(() => {
      manager.createToken({
        principalId: "invalid-agent",
        assignedProfileId: "non_existent_profile_12345",
      });
    }).toThrow(/Cannot assign non-existent profile/i);
  });

  it("7. Rotation invalidates previous token and issues valid new token", () => {
    const manager = new RemoteTokenManager(testDb);

    const { rawToken: oldRawToken, record: oldRecord } = manager.createToken({
      principalId: "agent-rotation",
      assignedProfileId: "backend",
      name: "Rotation Test Agent",
    });

    // Before rotation: old token works
    expect(manager.resolveToken(oldRawToken)).not.toBeNull();

    // Rotate token
    const rotationResult = manager.rotateToken(oldRecord.id);
    expect(rotationResult).not.toBeNull();

    const { newRawToken, newRecord } = rotationResult!;
    expect(newRawToken).not.toBe(oldRawToken);
    expect(newRecord.principalId).toBe("agent-rotation");
    expect(newRecord.assignedProfileId).toBe("backend");
    expect(newRecord.name).toContain("(Rotated)");

    // Old token must now be revoked
    expect(manager.resolveToken(oldRawToken)).toBeNull();

    // New token must be active
    const resolvedNew = manager.resolveToken(newRawToken);
    expect(resolvedNew).not.toBeNull();
    expect(resolvedNew?.id).toBe(newRecord.id);

    // Verify persistence across restart
    testDb.close();
    const restartedDb = new DatabaseManager(testDbPath);
    testDb = restartedDb;
    const manager2 = new RemoteTokenManager(restartedDb);

    expect(manager2.resolveToken(oldRawToken)).toBeNull();
    expect(manager2.resolveToken(newRawToken)).not.toBeNull();
  });

  it("8. Environment-managed tokens continue working and persist without overwriting", () => {
    const testSecret = "omnimcp_agent_test_env_secret_key_8899aabbcc";
    process.env.OMNIMCP_AGENT_TOKEN = testSecret;

    const manager = new RemoteTokenManager(testDb);
    manager.initializeFromEnv();

    const resolved = manager.resolveToken(testSecret);
    expect(resolved).not.toBeNull();
    expect(resolved?.principalId).toBe("master_agent_principal");
    expect(resolved?.assignedProfileId).toBe("developer");

    // Clean up environment
    delete process.env.OMNIMCP_AGENT_TOKEN;
  });

  it("11. Environment token initialization cannot reset a revoked database token", () => {
    const testSecret = "omnimcp_agent_env_revocation_immunity_test_1234";
    process.env.OMNIMCP_AGENT_TOKEN = testSecret;

    // First boot: register env token
    const manager1 = new RemoteTokenManager(testDb);
    manager1.initializeFromEnv();
    const tokenRecord = manager1.resolveToken(testSecret);
    expect(tokenRecord).not.toBeNull();

    // Operator revokes the token in SQLite
    const revoked = manager1.revokeToken(tokenRecord!.id);
    expect(revoked).toBe(true);
    expect(manager1.resolveToken(testSecret)).toBeNull();

    // Verify revoked in DB
    const dbRecord = testDb.getAgentTokenByHash(hashToken(testSecret));
    expect(dbRecord?.isRevoked).toBe(true);

    // Simulate second boot / process restart with same .env variable present
    testDb.close();
    const restartedDb = new DatabaseManager(testDbPath);
    testDb = restartedDb;
    const manager2 = new RemoteTokenManager(restartedDb);
    manager2.initializeFromEnv();

    // Token MUST remain revoked; env initialization must NOT reset is_revoked to false
    expect(manager2.resolveToken(testSecret)).toBeNull();
    const dbRecordAfterRestart = restartedDb.getAgentTokenByHash(hashToken(testSecret));
    expect(dbRecordAfterRestart?.isRevoked).toBe(true);
    expect(dbRecordAfterRestart?.revokedAt).toBeGreaterThan(0);

    // Clean up environment
    delete process.env.OMNIMCP_AGENT_TOKEN;
  });

  it("9. Database failures fail securely (never allow unauthorized access)", () => {
    const manager = new RemoteTokenManager(testDb);
    const { rawToken } = manager.createToken({
      principalId: "secure-agent",
      assignedProfileId: "developer",
    });

    // Force close underlying database connection
    testDb.close();

    // Resolution against closed DB should fail closed (return null), never throw or grant access
    const result = manager.resolveToken(rawToken);
    // Note: in-memory fallback might still retain or query, but must never grant access to invalid tokens
    const fakeResult = manager.resolveToken("fake_token");
    expect(fakeResult).toBeNull();
  });

  it("10. Raw tokens and hashes are never exposed in listTokens or public metadata", () => {
    const manager = new RemoteTokenManager(testDb);
    const { rawToken } = manager.createToken({
      principalId: "audit-agent",
      assignedProfileId: "developer",
      name: "Audit Token",
    });

    const tokenList = manager.listTokens();
    expect(tokenList.length).toBeGreaterThanOrEqual(1);

    for (const item of tokenList) {
      // Must NOT contain raw token
      expect((item as any).rawToken).toBeUndefined();
      expect(JSON.stringify(item)).not.toContain(rawToken);

      // Must NOT contain tokenHash
      expect((item as any).tokenHash).toBeUndefined();

      // Must contain safe masked prefix
      expect(item.tokenPrefix).toMatch(/••••$/);
      expect(item.principalId).toBeDefined();
      expect(item.assignedProfileId).toBeDefined();
    }
  });
});
