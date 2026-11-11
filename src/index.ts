import "dotenv/config";
import path from "node:path";
import { fileURLToPath } from "node:url";
import dotenv from "dotenv";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, "..");

// Always load .env from OmniMCP root regardless of execution cwd
dotenv.config({ path: path.join(projectRoot, ".env") });

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { OmniMCPGatewayServer } from "./gateway-server.js";
import { createHttpGateway, stopSessionCleanupTimer } from "./http-gateway.js";
import { clientManager } from "./client-manager.js";
import { healthMonitor } from "./health.js";
import { dbManager } from "./db.js";
import { logger } from "./logger.js";
import { validateEnvironment } from "./config-validator.js";
import http from "node:http";

import { spawn } from "node:child_process";
import fs from "node:fs";

function openInChrome(url: string) {
  try {
    if (process.platform === "win32") {
      // Try Chrome directly first (most reliable from agent/sandbox context)
      const chromePaths = [
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
        `${process.env.LOCALAPPDATA}\\Google\\Chrome\\Application\\chrome.exe`,
      ];
      for (const chromePath of chromePaths) {
        if (fs.existsSync(chromePath)) {
          const child = spawn(chromePath, [url], { detached: true, stdio: "ignore" });
          child.unref();
          logger.info({ chromePath }, "Opened Chrome browser");
          return;
        }
      }
      // Fallback: use explorer.exe to open in default browser
      const child = spawn("explorer.exe", [url], { detached: true, stdio: "ignore" });
      child.unref();
      logger.info("Opened default browser via explorer.exe");
      return;
    }

    if (process.platform === "darwin") {
      spawn("open", ["-a", "Google Chrome", url], { detached: true, stdio: "ignore" }).unref();
      return;
    }

    if (process.platform === "linux") {
      spawn("xdg-open", [url], { detached: true, stdio: "ignore" }).unref();
      return;
    }
  } catch (err) {
    logger.warn({ error: err }, "Could not auto-launch browser window");
  }
}

async function main() {
  // Validate production configuration
  const validation = validateEnvironment();
  if (!validation.valid && process.env.NODE_ENV === "production") {
    console.error("\n❌ FATAL: OmniMCP production configuration validation failed:");
    for (const err of validation.errors) {
      console.error(`   - ${err}`);
    }
    logger.fatal({ errors: validation.errors }, "Aborting startup due to invalid production configuration.");
    process.exit(1);
  }

  const isHttpMode = process.argv.includes("--http") || process.env.ENABLE_HTTP === "true" || process.env.NODE_ENV === "production";
  const isAllMode = process.argv.includes("--all");
  const isStdioMode = process.argv.includes("--stdio") || (!isHttpMode && !isAllMode);

  if (isStdioMode) {
    logger.info("Initializing OmniMCP Centralized Gateway...");
  }

  const gateway = new OmniMCPGatewayServer();
  const server = gateway.getServer();

  let httpServer: http.Server | null = null;

  // 1. HTTP Gateway & Dashboard (bind immediately so container healthcheck passes instantly)
  if (isHttpMode || isAllMode) {
    const port = Number(process.env.PORT) || 3000;
    const host = process.env.HOST || (process.env.NODE_ENV === "production" ? "0.0.0.0" : "127.0.0.1");
    const app = createHttpGateway(gateway);
    httpServer = app.listen(port, host, () => {
      const url = `http://${host === "127.0.0.1" ? "localhost" : host}:${port}`;
      if (!isStdioMode) {
        console.log(`\n  \x1b[32m✔\x1b[0m OmniMCP Dashboard is running!`);
        console.log(`  \x1b[36m➜\x1b[0m \x1b[1mLocal:\x1b[0m   \x1b[4m${url}\x1b[0m`);
        console.log(`  \x1b[90m➜  Opening in Google Chrome... (Press Ctrl+C to stop)\x1b[0m\n`);
      } else {
        logger.info({ port, host }, `OmniMCP Dashboard running at ${url}`);
      }
      const shouldOpenBrowser =
        process.env.NO_BROWSER_OPEN !== "true" &&
        process.env.NODE_ENV !== "production" &&
        (process.argv.includes("--open") || isHttpMode);

      if (shouldOpenBrowser) {
        openInChrome(url);
      }
    });
  }

  // 2. Connect STDIO Server Transport (for Antigravity)
  if (isStdioMode || isAllMode) {
    await gateway.initializeDefaultServers();
    const transport = new StdioServerTransport();
    await server.connect(transport);
    logger.info("OmniMCP Gateway listening on STDIO for Google Antigravity");
  } else {
    // 3. In pure HTTP mode (e.g. Voroa cloud), auto-connect remote HTTP MCP endpoints (e.g. Google Stitch)
    // Downstream local stdio subprocesses connect on-demand or via the dashboard to preserve container CPU/RAM.
    setTimeout(() => {
      gateway.initializeDefaultServers({ remoteOnly: true }).catch((err) => {
        logger.warn({ error: err }, "Error during downstream servers initialization");
      });
    }, 1500);
  }

  // Clean shutdown handlers
  const cleanup = async () => {
    if (!isStdioMode) {
      console.log(`\n  \x1b[33m➜\x1b[0m OmniMCP Dashboard stopped.\n`);
    } else {
      logger.info("Shutting down OmniMCP Gateway...");
    }
    try {
      stopSessionCleanupTimer();
      healthMonitor.stop();
      if (httpServer) {
        httpServer.close();
      }
      await clientManager.disconnectAll();
      await server.close();
      dbManager.close();
    } catch (err) {
      logger.error({ error: err }, "Error during shutdown");
    }
    process.exit(0);
  };

  process.on("SIGINT", cleanup);
  process.on("SIGTERM", cleanup);
}

process.on("unhandledRejection", (reason) => {
  console.error("FATAL: Unhandled Promise Rejection:", reason);
  logger.fatal({ error: reason }, "Unhandled Promise Rejection");
});

process.on("uncaughtException", (error) => {
  console.error("FATAL: Uncaught Exception:", error);
  logger.fatal({ error }, "Uncaught Exception");
  process.exit(1);
});

main().catch((err) => {
  console.error("FATAL: Error starting OmniMCP Gateway:", err);
  logger.fatal({ error: err }, "Fatal error starting OmniMCP Gateway");
  process.exit(1);
});
