import pino from "pino";

// Determine default log level (keep terminal clean in HTTP/Dashboard mode)
const isHttpOnly = (process.argv.includes("--http") || process.argv.includes("dashboard") || process.argv.includes("dev")) && !process.argv.includes("--stdio");
const defaultLevel = isHttpOnly ? (process.env.DEBUG ? "info" : "warn") : (process.env.LOG_LEVEL || "info");

// Ensure all logger output goes to stderr so stdout remains clean for MCP JSON-RPC transport
export const logger = pino(
  {
    level: defaultLevel,
    timestamp: pino.stdTimeFunctions.isoTime,
    redact: {
      paths: [
        "*.password",
        "*.token",
        "*.accessToken",
        "*.secret",
        "*.authorization",
        "*.apiKey",
        "headers.authorization",
        "env.GITHUB_PERSONAL_ACCESS_TOKEN",
        "env.SUPABASE_SERVICE_ROLE_KEY",
        "env.SENTRY_AUTH_TOKEN",
        "parameters.token",
        "parameters.password",
      ],
      censor: "[REDACTED_SECRET]",
    },
    formatters: {
      level: (label) => ({ level: label }),
    },
  },
  pino.destination({ dest: 2, sync: true }) // file descriptor 2 is process.stderr
);

export function createChildLogger(module: string) {
  return logger.child({ module });
}
