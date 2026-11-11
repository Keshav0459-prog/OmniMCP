import { chromium } from "playwright";
import http from "node:http";
import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import { OmniMCPGatewayServer } from "../dist/gateway-server.js";
import { createHttpGateway } from "../dist/http-gateway.js";
import { clientManager } from "../dist/client-manager.js";
import { healthMonitor } from "../dist/health.js";
import { serverRegistry } from "../dist/registry.js";
import dotenv from "dotenv";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, "..");

dotenv.config({ path: path.join(rootDir, ".env") });

const screenshotsDir = path.join(rootDir, "assets", "screenshots");
if (!fs.existsSync(screenshotsDir)) {
  fs.mkdirSync(screenshotsDir, { recursive: true });
}

async function main() {
  console.log("Starting OmniMCP Gateway server for screenshot capture...");
  const gateway = new OmniMCPGatewayServer();
  await gateway.initializeDefaultServers();

  // Connect all remaining servers for full visual showcase
  const allServers = serverRegistry.getAllServers();
  for (const s of allServers) {
    if (s.status !== "connected") {
      try {
        console.log(`Connecting downstream server: ${s.id}...`);
        await clientManager.connectServer(s);
      } catch (e) {
        console.warn(`Could not connect ${s.id}:`, e.message);
      }
    }
  }

  const port = 3000;
  const app = createHttpGateway(gateway);
  const server = http.createServer(app);

  await new Promise((resolve) => server.listen(port, resolve));
  console.log(`Server listening on http://localhost:${port}`);

  console.log("Launching headless Chrome...");
  const browser = await chromium.launch({
    channel: "chrome",
    headless: true,
  });

  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    deviceScaleFactor: 2, // HiDPI / Retina quality
  });

  const page = await context.newPage();
  const authToken = process.env.OMNIMCP_AUTH_TOKEN || "";
  const targetUrl = authToken ? `http://localhost:${port}?token=${authToken}` : `http://localhost:${port}`;
  await page.goto(targetUrl, { waitUntil: "networkidle" });
  await page.waitForTimeout(2000); // Allow frontend animations and data fetch to settle

  // 1. Overview view
  console.log("Capturing 1/5: Overview...");
  await page.screenshot({
    path: path.join(screenshotsDir, "dashboard-overview.png"),
    fullPage: false,
  });

  // 2. Connected Fleet view
  console.log("Capturing 2/5: Connected Fleet...");
  await page.click("#nav-connected");
  await page.waitForTimeout(600);
  await page.screenshot({
    path: path.join(screenshotsDir, "connected-fleet.png"),
    fullPage: false,
  });

  // 3. Tool Explorer view
  console.log("Capturing 3/5: Tool Explorer...");
  await page.click("#nav-tools");
  await page.waitForTimeout(600);
  await page.screenshot({
    path: path.join(screenshotsDir, "tool-explorer.png"),
    fullPage: false,
  });

  // 4. Smart Router view
  console.log("Capturing 4/6: Smart Router...");
  await page.click("#nav-router");
  await page.waitForTimeout(600);
  await page.fill("#router-query-input", "Build a dashboard with shadcn components, query database with supabase, and test with playwright");
  await page.click("button:has-text('Match Capabilities')");
  await page.waitForTimeout(1000);
  await page.screenshot({
    path: path.join(screenshotsDir, "smart-router.png"),
    fullPage: false,
  });

  // 5. Audit History view
  console.log("Capturing 5/6: Audit History...");
  await page.click("#nav-history");
  await page.waitForTimeout(600);
  await page.screenshot({
    path: path.join(screenshotsDir, "audit-history.png"),
    fullPage: false,
  });

  // 6. Permissions Matrix view
  console.log("Capturing 6/6: Permissions Matrix...");
  await page.click("#nav-permissions");
  await page.waitForTimeout(600);
  await page.screenshot({
    path: path.join(screenshotsDir, "permissions-matrix.png"),
    fullPage: false,
  });

  console.log("All screenshots captured successfully!");

  await browser.close();
  healthMonitor.stop();
  await clientManager.disconnectAll();
  server.close();
  process.exit(0);
}

main().catch((err) => {
  console.error("Screenshot capture failed:", err);
  process.exit(1);
});
