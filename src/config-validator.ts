import { createChildLogger } from "./logger.js";

const log = createChildLogger("config-validator");

export interface ConfigValidationResult {
  valid: boolean;
  warnings: string[];
  errors: string[];
}

export function validateEnvironment(): ConfigValidationResult {
  const isProd = process.env.NODE_ENV === "production";
  const warnings: string[] = [];
  const errors: string[] = [];

  // 1. Encryption Key
  const encKey = process.env.OMNIMCP_ENCRYPTION_KEY;
  if (!encKey) {
    if (isProd) {
      errors.push("OMNIMCP_ENCRYPTION_KEY is required in production (must be 64-char hex / 32-byte key).");
    } else {
      warnings.push("OMNIMCP_ENCRYPTION_KEY not set. Using ephemeral key; encrypted vault secrets will not persist across restarts.");
    }
  } else if (!/^[0-9a-fA-F]{64}$/.test(encKey)) {
    errors.push("OMNIMCP_ENCRYPTION_KEY must be a valid 64-character hexadecimal string.");
  }

  // 2. Operator Token
  const opToken = process.env.OMNIMCP_OPERATOR_TOKEN;
  if (!opToken) {
    if (isProd) {
      errors.push("OMNIMCP_OPERATOR_TOKEN is mandatory in production to secure administrative APIs.");
    } else {
      warnings.push("OMNIMCP_OPERATOR_TOKEN is not configured; using fallback development token.");
    }
  } else if (isProd && (opToken === "omnimcp_operator_2026" || opToken === "operator_token_here")) {
    errors.push("OMNIMCP_OPERATOR_TOKEN is using an insecure default placeholder in production.");
  }

  // 3. Agent Token
  const agentToken = process.env.OMNIMCP_AGENT_TOKEN || process.env.OMNIMCP_AUTH_TOKEN;
  if (!agentToken && isProd) {
    warnings.push("OMNIMCP_AGENT_TOKEN is not set. MCP client agents will need dynamic session tokens.");
  }

  // 4. Port configuration
  const port = process.env.PORT;
  if (port && (isNaN(Number(port)) || Number(port) <= 0 || Number(port) > 65535)) {
    errors.push(`Invalid PORT value '${port}'. Must be a number between 1 and 65535.`);
  }

  const result: ConfigValidationResult = {
    valid: errors.length === 0,
    warnings,
    errors,
  };

  for (const w of warnings) {
    log.warn({ warning: w }, `Configuration Warning: ${w}`);
  }

  for (const e of errors) {
    log.error({ error: e }, `Configuration Error: ${e}`);
  }

  return result;
}

