import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { ServerConfig } from "./types.js";
import { serverRegistry } from "./registry.js";
import { createChildLogger } from "./logger.js";
import path from "node:path";
import { fileURLToPath } from "node:url";

const log = createChildLogger("client-manager");

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const omnimcpRoot = path.resolve(__dirname, "..");

// Allowlisted standard system environment variables needed for basic process execution
export const SAFE_SYSTEM_ENV_VARS = new Set([
  "PATH",
  "PATHEXT",
  "SYSTEMROOT",
  "SYSTEMDRIVE",
  "TEMP",
  "TMP",
  "USERPROFILE",
  "HOMEDRIVE",
  "HOMEPATH",
  "APPDATA",
  "LOCALAPPDATA",
  "NODE_ENV",
  "LANG",
  "LC_ALL",
  "SHELL",
  "COMSPEC",
  "TERM",
  "PROGRAMFILES",
  "PROGRAMFILES(X86)",
  "COMMONPROGRAMFILES",
  "ALLUSERSPROFILE",
  "PUBLIC",
  "OS",
  "NUMBER_OF_PROCESSORS",
  "PROCESSOR_ARCHITECTURE",
  "WINDIR",
  "USER",
  "USERNAME",
  "USERDOMAIN",
  "LOGONSERVER",
  // Essential Linux / Unix container environment variables
  "HOME",
  "LOGNAME",
  "NODE_PATH",
]);

// Banned reserved gateway secrets and sensitive host credentials that must NEVER be passed to child processes
export const BANNED_RESERVED_SECRETS = new Set([
  "OMNIMCP_ENCRYPTION_KEY",
  "OMNIMCP_AUTH_TOKEN",
  "OMNIMCP_AGENT_TOKEN",
  "OMNIMCP_OPERATOR_TOKEN",
  "DATABASE_URL",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_SESSION_TOKEN",
  "STRIPE_SECRET_KEY",
  "STITCH_API_KEY",
]);

/**
 * Constructs a minimal, allowlisted environment for child MCP processes.
 * Ensures internal gateway master keys and arbitrary host environment variables are never leaked.
 * Rejects any customEnv attempts to override or inject reserved gateway secrets.
 */
export function buildChildEnvironment(customEnv?: Record<string, string>): Record<string, string> {
  const childEnv: Record<string, string> = {};

  // 1. Inherit only safe system execution variables from host
  for (const [k, v] of Object.entries(process.env)) {
    const upper = k.toUpperCase();
    if (typeof v === "string" && SAFE_SYSTEM_ENV_VARS.has(upper) && !BANNED_RESERVED_SECRETS.has(upper)) {
      childEnv[k] = v;
    }
  }

  // 2. Inject explicit server-specific configuration, rejecting any attempt to override reserved secrets
  if (customEnv) {
    for (const [k, v] of Object.entries(customEnv)) {
      const upper = k.toUpperCase();
      if (typeof v === "string" && !BANNED_RESERVED_SECRETS.has(upper)) {
        childEnv[k] = v;
      }
    }
  }

  // 3. Absolute defense-in-depth: explicitly delete all banned secrets regardless of case
  for (const banned of BANNED_RESERVED_SECRETS) {
    delete childEnv[banned];
    delete childEnv[banned.toLowerCase()];
  }

  return childEnv;
}

export class ClientManager {
  private activeClients: Map<string, Client> = new Map();
  private activeTransports: Map<string, Transport> = new Map();

  public async connectServer(config: ServerConfig): Promise<Client> {
    const existing = this.activeClients.get(config.id);
    if (existing) {
      log.info({ serverId: config.id }, "Server already connected");
      return existing;
    }

    serverRegistry.updateStatus(config.id, "connecting");
    const startTime = Date.now();

    try {
      if (config.transport === "stdio") {
        if (!config.command) {
          throw new Error(`Server '${config.id}' does not have a command configured for stdio transport.`);
        }

        log.info(
          { serverId: config.id, command: config.command, args: config.args },
          "Spawning downstream stdio MCP server"
        );

        // Least-Privilege Environment Hygiene:
        // Never leak gateway internal master keys (OMNIMCP_ENCRYPTION_KEY, OMNIMCP_AUTH_TOKEN, DATABASE_URL)
        // or arbitrary host secrets into this child process.
        const childEnv = buildChildEnvironment(config.env);

        let stderrBuffer = "";
        const transport = new StdioClientTransport({
          command: config.command,
          args: config.args || [],
          env: childEnv,
          cwd: config.cwd || omnimcpRoot,
          stderr: "pipe",
        });

        // Actively drain stderr to prevent OS pipe buffers from stalling child process
        if (transport.stderr) {
          transport.stderr.on("data", (chunk: Buffer) => {
            stderrBuffer += chunk.toString("utf8");
            if (stderrBuffer.length > 4096) {
              stderrBuffer = stderrBuffer.slice(-4096);
            }
          });
        }

        // Monitor transport crash / close lifecycle events
        transport.onclose = () => {
          log.warn(
            { serverId: config.id, stderr: stderrBuffer.trim() || undefined },
            "Child MCP server transport closed unexpectedly"
          );
          this.activeClients.delete(config.id);
          this.activeTransports.delete(config.id);
          serverRegistry.updateStatus(config.id, "disconnected");
        };

        const client = new Client(
          {
            name: `omnimcp-host-${config.id}`,
            version: "1.0.0",
          },
          {
            capabilities: {
              roots: {
                listChanged: true,
              },
            },
          }
        );

        // Resilient connection timeout (45s default to allow heavy child processes like Sentry/Octokit to initialize schemas on cloud containers)
        const connectTimeoutMs = Number(process.env.MCP_CONNECT_TIMEOUT_MS) || 45000;
        try {
          await Promise.race([
            client.connect(transport),
            new Promise((_, reject) =>
              setTimeout(
                () =>
                  reject(
                    new Error(
                      `MCP server '${config.id}' connection timed out after ${connectTimeoutMs}ms`
                    )
                  ),
                connectTimeoutMs
              )
            ),
          ]);
        } catch (err: any) {
          try {
            await transport.close();
          } catch {}
          const detail = stderrBuffer.trim() ? ` (stderr: ${stderrBuffer.trim().slice(0, 200)})` : "";
          log.error(
            { serverId: config.id, err: err.message, stderr: stderrBuffer.trim() || undefined },
            "Failed to connect to downstream MCP server"
          );
          throw new Error(`${err.message}${detail}`);
        }
        const latencyMs = Date.now() - startTime;

        this.activeClients.set(config.id, client);
        this.activeTransports.set(config.id, transport);

        // Fetch tool count to update registry
        const toolsResult = await client.listTools();
        const toolCount = toolsResult.tools?.length || 0;

        serverRegistry.updateStatus(config.id, "connected", undefined, toolCount, latencyMs);
        log.info(
          { serverId: config.id, toolCount, latencyMs },
          "Downstream MCP server connected successfully"
        );

        return client;
      } else if (config.transport === "http" || config.transport === "sse") {
        if (!config.url) {
          throw new Error(`Remote server '${config.id}' does not have a URL configured.`);
        }

        // Validate URL against SSRF, cloud metadata, and DNS rebinding attacks
        await serverRegistry.validateRemoteUrl(config);

        log.info(
          { serverId: config.id, url: config.url, transport: config.transport },
          "Connecting to downstream remote MCP server"
        );

        const targetUrl = new URL(config.url);
        const headers: Record<string, string> = {
          "User-Agent": "OmniMCP-Gateway/1.0.0",
          ...(config.headers || {}),
        };

        // Downstream Authentication Resolver:
        // For Google Stitch or any server targeted to stitch.googleapis.com
        if (config.id === "stitch" || targetUrl.hostname.includes("stitch.googleapis.com")) {
          const apiKey = process.env.STITCH_API_KEY;
          if (!apiKey) {
            throw new Error(
              "Google Stitch integration requires STITCH_API_KEY environment variable. Configure STITCH_API_KEY in your server environment."
            );
          }
          headers["X-Goog-Api-Key"] = apiKey;
        }

        let transport: Transport;
        if (config.transport === "http") {
          transport = new StreamableHTTPClientTransport(targetUrl, {
            requestInit: {
              headers,
            },
          });
        } else {
          transport = new SSEClientTransport(targetUrl, {
            requestInit: {
              headers,
            },
          });
        }

        // Monitor transport crash / close lifecycle events
        transport.onclose = () => {
          log.warn({ serverId: config.id }, "Remote MCP transport connection closed");
          this.activeClients.delete(config.id);
          this.activeTransports.delete(config.id);
          serverRegistry.updateStatus(config.id, "disconnected");
        };

        if ("onerror" in transport) {
          (transport as any).onerror = (err: Error) => {
            log.error({ serverId: config.id, error: err.message }, "Remote MCP transport reported error");
          };
        }

        const client = new Client(
          {
            name: `omnimcp-host-${config.id}`,
            version: "1.0.0",
          },
          {
            capabilities: {
              roots: {
                listChanged: true,
              },
            },
          }
        );

        await client.connect(transport);
        const latencyMs = Date.now() - startTime;

        this.activeClients.set(config.id, client);
        this.activeTransports.set(config.id, transport);

        // Fetch tool count to update registry
        const toolsResult = await client.listTools();
        const toolCount = toolsResult.tools?.length || 0;

        serverRegistry.updateStatus(config.id, "connected", undefined, toolCount, latencyMs);
        log.info(
          { serverId: config.id, toolCount, latencyMs },
          "Downstream remote MCP server connected successfully"
        );

        return client;
      } else {
        throw new Error(`Transport '${config.transport}' is not recognized.`);
      }
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      serverRegistry.updateStatus(config.id, "error", errorMessage);
      log.error({ serverId: config.id, error: errorMessage }, "Failed to connect to downstream MCP server");
      throw err;
    }
  }

  public async disconnectServer(serverId: string): Promise<void> {
    const client = this.activeClients.get(serverId);
    const transport = this.activeTransports.get(serverId);

    if (client) {
      try {
        await client.close();
      } catch (err) {
        log.warn({ serverId, error: err }, "Error closing MCP client");
      }
      this.activeClients.delete(serverId);
    }

    if (transport) {
      try {
        await transport.close();
      } catch (err) {
        log.warn({ serverId, error: err }, "Error closing transport");
      }
      this.activeTransports.delete(serverId);
    }

    serverRegistry.updateStatus(serverId, "disconnected", undefined, 0);
    log.info({ serverId }, "Downstream MCP server disconnected");
  }

  public getClient(serverId: string): Client | undefined {
    return this.activeClients.get(serverId);
  }

  public isConnected(serverId: string): boolean {
    return this.activeClients.has(serverId);
  }

  public async disconnectAll(): Promise<void> {
    const ids = Array.from(this.activeClients.keys());
    for (const id of ids) {
      await this.disconnectServer(id);
    }
  }
}

export const clientManager = new ClientManager();
