import { describe, it, expect } from "vitest";
import { spawn } from "node:child_process";
import { buildChildEnvironment, SAFE_SYSTEM_ENV_VARS } from "../src/client-manager.js";

describe("Real Child Process Environment Isolation (Integration)", () => {
  it("should spawn a real child process and prove gateway master keys and host secrets are absent", async () => {
    // 1. Inject simulated master secrets and arbitrary environment variables into current process
    const originalEnv = { ...process.env };
    try {
      process.env.OMNIMCP_ENCRYPTION_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
      process.env.OMNIMCP_AUTH_TOKEN = "master-auth-token-that-must-never-leak-to-children";
      process.env.DATABASE_URL = "file:./data/omnimcp.db";
      process.env.ARBITRARY_HOST_SECRET = "untrusted-secret-token-leak";
      process.env.AWS_SECRET_ACCESS_KEY = "mock_aws_secret_access_key_placeholder";
      process.env.STRIPE_SECRET_KEY = "mock_stripe_secret_key_placeholder";

      // 2. Build child environment using the actual production function
      const customServerEnv = {
        GITHUB_PERSONAL_ACCESS_TOKEN: "mock_explicit_gh_token_for_this_server",
        TARGET_WORKSPACE_DIR: "C:\\OmniMCP",
      };

      const childEnv = buildChildEnvironment(customServerEnv);

      // 3. Spawn a real harmless Node.js child process that prints its actual process.env
      const script = "console.log(JSON.stringify(process.env));";
      const child = spawn(process.execPath, ["-e", script], {
        env: childEnv,
        stdio: ["ignore", "pipe", "pipe"],
      });

      let stdout = "";
      let stderr = "";

      child.stdout.on("data", (chunk) => {
        stdout += chunk.toString();
      });

      child.stderr.on("data", (chunk) => {
        stderr += chunk.toString();
      });

      const exitCode = await new Promise<number>((resolve) => {
        child.on("close", (code) => resolve(code ?? 0));
      });

      expect(exitCode).toBe(0);
      expect(stderr).toBe("");

      const receivedChildEnv: Record<string, string> = JSON.parse(stdout);

      // 4. Critical Security Assertions: Gateway master secrets MUST be absent
      expect(receivedChildEnv.OMNIMCP_ENCRYPTION_KEY).toBeUndefined();
      expect(receivedChildEnv.OMNIMCP_AUTH_TOKEN).toBeUndefined();
      expect(receivedChildEnv.DATABASE_URL).toBeUndefined();

      // 5. Host arbitrary API keys and leaked variables MUST be absent
      expect(receivedChildEnv.ARBITRARY_HOST_SECRET).toBeUndefined();
      expect(receivedChildEnv.AWS_SECRET_ACCESS_KEY).toBeUndefined();
      expect(receivedChildEnv.STRIPE_SECRET_KEY).toBeUndefined();

      // 6. Explicitly declared custom server configuration MUST be present
      expect(receivedChildEnv.GITHUB_PERSONAL_ACCESS_TOKEN).toBe(
        "mock_explicit_gh_token_for_this_server"
      );
      expect(receivedChildEnv.TARGET_WORKSPACE_DIR).toBe("C:\\OmniMCP");

      // 7. Every other variable present in the child process MUST be in the allowlist
      const unexpectedKeys = Object.keys(receivedChildEnv).filter(
        (key) => !(key in customServerEnv) && !SAFE_SYSTEM_ENV_VARS.has(key.toUpperCase())
      );
      if (unexpectedKeys.length > 0) {
        console.error("Unexpected keys in child process environment:", unexpectedKeys);
      }
      expect(unexpectedKeys).toEqual([]);
    } finally {
      process.env = originalEnv;
    }
  });
});
