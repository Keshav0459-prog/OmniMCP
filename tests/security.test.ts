import { describe, it, expect, vi } from "vitest";
import dns from "node:dns";
import { CredentialVault, sanitizeData, validateRemoteServerUrl, validateRemoteServerUrlAsync } from "../src/security.js";
import { buildChildEnvironment } from "../src/client-manager.js";

describe("Security & Vault", () => {
  it("should encrypt and decrypt credentials with AES-256-GCM", () => {
    const vault = new CredentialVault();
    const secret = "ghp_super_secret_github_personal_access_token_123456";

    const encrypted = vault.encrypt(secret);
    expect(encrypted).not.toBe(secret);
    expect(encrypted.split(":").length).toBe(3);

    const decrypted = vault.decrypt(encrypted);
    expect(decrypted).toBe(secret);
  });

  it("should enforce valid 32-byte hex key in production", () => {
    const originalEnv = process.env.NODE_ENV;
    try {
      process.env.NODE_ENV = "production";
      delete process.env.OMNIMCP_ENCRYPTION_KEY;

      expect(() => new CredentialVault()).toThrow("FATAL SECURITY CONFIGURATION");

      // Valid 64-hex character (32-byte) key should succeed
      const validKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
      const prodVault = new CredentialVault(validKey);
      const encrypted = prodVault.encrypt("prod_secret");
      expect(prodVault.decrypt(encrypted)).toBe("prod_secret");
    } finally {
      process.env.NODE_ENV = originalEnv;
    }
  });

  it("should sanitize tokens and secrets from strings", () => {
    const str = "Using token ghp_1234567890abcdef1234567890abcdef1234 to authenticate";
    const sanitized = sanitizeData(str);
    expect(sanitized).not.toContain("ghp_1234567890abcdef1234567890abcdef1234");
    expect(sanitized).toContain("[REDACTED_SECRET]");
  });

  it("should sanitize secrets from nested objects", () => {
    const payload = {
      user: "antigravity",
      config: {
        githubToken: "ghp_1234567890abcdef1234567890abcdef1234",
        apiKey: "sk-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijkl",
        normalField: "visible-value",
      },
    };

    const sanitized = sanitizeData(payload);
    expect(sanitized.config.githubToken).toBe("[REDACTED_SECRET]");
    expect(sanitized.config.apiKey).toBe("[REDACTED_SECRET]");
    expect(sanitized.config.normalField).toBe("visible-value");
  });

  it("should enforce SSRF protection on remote server URLs (sync)", () => {
    expect(validateRemoteServerUrl("http://127.0.0.1:8080").valid).toBe(false);
    expect(validateRemoteServerUrl("http://localhost:3000").valid).toBe(false);
    expect(validateRemoteServerUrl("http://169.254.169.254/latest/meta-data").valid).toBe(false);
    expect(validateRemoteServerUrl("http://metadata.google.internal").valid).toBe(false);
    expect(validateRemoteServerUrl("http://192.168.1.1").valid).toBe(false);
    expect(validateRemoteServerUrl("http://10.0.0.1").valid).toBe(false);
    expect(validateRemoteServerUrl("http://[::1]:8080").valid).toBe(false);
    expect(validateRemoteServerUrl("http://user:pass@example.com").valid).toBe(false);

    // Public valid URLs
    expect(validateRemoteServerUrl("https://api.github.com").valid).toBe(true);
    expect(validateRemoteServerUrl("https://mcp.context7.com").valid).toBe(true);
  });

  it("should enforce async SSRF protection with DNS resolution and rebinding check", async () => {
    const localCheck = await validateRemoteServerUrlAsync("http://127.0.0.1:8080");
    expect(localCheck.valid).toBe(false);

    const metadataCheck = await validateRemoteServerUrlAsync("http://169.254.169.254");
    expect(metadataCheck.valid).toBe(false);

    const privateCheck = await validateRemoteServerUrlAsync("http://10.255.0.1");
    expect(privateCheck.valid).toBe(false);

    // Public IP check (offline-friendly)
    const publicIpCheck = await validateRemoteServerUrlAsync("http://8.8.8.8");
    expect(publicIpCheck.valid).toBe(true);

    // Mock DNS rebinding attack: hostname looks benign but resolves to private IP
    vi.spyOn(dns.promises, "lookup").mockResolvedValueOnce([
      { address: "192.168.1.100", family: 4 },
    ] as any);
    const rebindCheck = await validateRemoteServerUrlAsync("https://legit-looking-domain.com");
    expect(rebindCheck.valid).toBe(false);
    expect(rebindCheck.reason).toContain("private/reserved network");
  });

  it("should enforce child environment hygiene and strip gateway secrets via buildChildEnvironment", () => {
    const originalEncryptionKey = process.env.OMNIMCP_ENCRYPTION_KEY;
    const originalAuthToken = process.env.OMNIMCP_AUTH_TOKEN;
    const originalDbUrl = process.env.DATABASE_URL;

    try {
      process.env.OMNIMCP_ENCRYPTION_KEY = "super-secret-key-that-must-never-leak";
      process.env.OMNIMCP_AUTH_TOKEN = "super-secret-auth-token-that-must-never-leak";
      process.env.DATABASE_URL = "file:./data/omnimcp.db";
      process.env.UNSAFE_HOST_LEAK_VAR = "leak-val-123";

      const childEnv = buildChildEnvironment({
        EXPLICIT_SERVER_VAR: "allowed_value",
      });

      expect(childEnv.OMNIMCP_ENCRYPTION_KEY).toBeUndefined();
      expect(childEnv.OMNIMCP_AUTH_TOKEN).toBeUndefined();
      expect(childEnv.DATABASE_URL).toBeUndefined();
      expect(childEnv.UNSAFE_HOST_LEAK_VAR).toBeUndefined();
      expect(childEnv.EXPLICIT_SERVER_VAR).toBe("allowed_value");
      expect(childEnv.PATH).toBeDefined();
    } finally {
      if (originalEncryptionKey !== undefined) {
        process.env.OMNIMCP_ENCRYPTION_KEY = originalEncryptionKey;
      } else {
        delete process.env.OMNIMCP_ENCRYPTION_KEY;
      }
      if (originalAuthToken !== undefined) {
        process.env.OMNIMCP_AUTH_TOKEN = originalAuthToken;
      } else {
        delete process.env.OMNIMCP_AUTH_TOKEN;
      }
      if (originalDbUrl !== undefined) {
        process.env.DATABASE_URL = originalDbUrl;
      } else {
        delete process.env.DATABASE_URL;
      }
      delete process.env.UNSAFE_HOST_LEAK_VAR;
    }
  });
});

