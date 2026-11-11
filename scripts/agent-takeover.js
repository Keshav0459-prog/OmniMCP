import { chromium } from "playwright";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import dotenv from "dotenv";
import { OmniMCPGatewayServer } from "../dist/gateway-server.js";
import { createHttpGateway } from "../dist/http-gateway.js";
import { clientManager } from "../dist/client-manager.js";
import { serverRegistry } from "../dist/registry.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, "..");

dotenv.config({ path: path.join(rootDir, ".env") });

async function isPortInUse(port) {
  return new Promise((resolve) => {
    const req = http.get(`http://127.0.0.1:${port}/api/servers`, (res) => {
      resolve(true);
    });
    req.on("error", () => resolve(false));
    req.setTimeout(1000, () => {
      req.destroy();
      resolve(false);
    });
  });
}

async function main() {
  const port = Number(process.env.PORT) || 3000;
  console.log(`\n========================================`);
  console.log(`🤖 ANTIGRAVITY AUTONOMOUS AGENT TAKEOVER`);
  console.log(`========================================\n`);

  let serverInstance = null;
  const inUse = await isPortInUse(port);

  if (!inUse) {
    console.log(`[Agent] Initializing OmniMCP Centralized Gateway on port ${port}...`);
    const gateway = new OmniMCPGatewayServer();
    await gateway.initializeDefaultServers();

    // Auto-connect configured servers so the fleet is live
    for (const s of serverRegistry.getAllServers()) {
      if (s.status !== "connected") {
        try {
          await clientManager.connectServer(s);
        } catch {}
      }
    }

    const app = createHttpGateway(gateway);
    serverInstance = http.createServer(app);
    await new Promise((resolve) => serverInstance.listen(port, resolve));
    console.log(`[Agent] Gateway server started and ready at http://localhost:${port}`);
  } else {
    console.log(`[Agent] Detected running server at http://localhost:${port}`);
  }

  console.log(`[Agent] Launching visible Chrome browser session (Headed Mode)...`);
  const browser = await chromium.launch({
    channel: "chrome",
    headless: false, // User sees the browser window pop up
    slowMo: 600,     // Human-like speed so user can see every action
    args: ["--start-maximized"],
  });

  const context = await browser.newContext({
    viewport: null, // Full window
  });

  const page = await context.newPage();
  console.log(`[Agent] Navigating to http://localhost:${port}...`);
  await page.goto(`http://localhost:${port}`, { waitUntil: "networkidle" });
  await page.waitForTimeout(1000);

  console.log(`[Agent] Step 1: Inspecting Dashboard Overview & Fleet Cards...`);
  await page.waitForSelector("#overview-servers-list");
  await page.waitForTimeout(1500);

  console.log(`[Agent] Step 2: Navigating to Connected Server Fleet...`);
  await page.click("#nav-connected");
  await page.waitForTimeout(1500);

  console.log(`[Agent] Step 3: Navigating to Tool Explorer and filtering tools...`);
  await page.click("#nav-tools");
  await page.waitForTimeout(1000);
  await page.fill("#tool-search-input", "github");
  await page.waitForTimeout(1500);
  await page.fill("#tool-search-input", "read");
  await page.waitForTimeout(1500);
  await page.fill("#tool-search-input", "");
  await page.waitForTimeout(1000);

  console.log(`[Agent] Step 4: Activating Smart Router with natural language task...`);
  await page.click("#nav-router");
  await page.waitForTimeout(1000);
  const taskPrompt = "Build a responsive UI with shadcn, query supabase database, and test with playwright";
  await page.fill("#router-query-input", taskPrompt);
  await page.waitForTimeout(800);
  console.log(`[Agent] Triggering Capability Matcher...`);
  await page.click("button:has-text('Match Capabilities')");
  await page.waitForTimeout(2500);

  console.log(`[Agent] Step 5: Checking Permissions Matrix & Rate Limits...`);
  await page.click("#nav-permissions");
  await page.waitForTimeout(1500);

  console.log(`[Agent] Step 6: Checking Execution Audit Logs...`);
  await page.click("#nav-history");
  await page.waitForTimeout(1500);

  console.log(`[Agent] Step 7: Returning to Dashboard Overview...`);
  await page.click("#nav-overview");
  await page.waitForTimeout(1000);

  console.log(`\n======================================================`);
  console.log(`✅ [Agent] Autonomous UI verification cycle completed!`);
  console.log(`🌐 Browser window is left active for user control.`);
  console.log(`======================================================\n`);

  // Keep script alive so browser stays open for user
  await new Promise(() => {});
}

main().catch((err) => {
  console.error("Agent takeover error:", err);
  process.exit(1);
});

