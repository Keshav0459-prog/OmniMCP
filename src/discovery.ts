import { DiscoveredTool, PermissionLevel } from "./types.js";
import { clientManager } from "./client-manager.js";
import { serverRegistry } from "./registry.js";
import { permissionManager } from "./permissions.js";
import { createChildLogger } from "./logger.js";

const log = createChildLogger("discovery");

export class ToolDiscoveryEngine {
  private toolCache: Map<string, DiscoveredTool> = new Map();

  /**
   * Discovers and indexes all tools from a specific connected server.
   */
  public async discoverServerTools(serverId: string): Promise<DiscoveredTool[]> {
    const client = clientManager.getClient(serverId);
    const serverState = serverRegistry.getServer(serverId);

    if (!client || !serverState) {
      log.warn({ serverId }, "Cannot discover tools for unconnected or unknown server");
      return [];
    }

    try {
      const response = await client.listTools();
      const rawTools = response.tools || [];
      const discovered: DiscoveredTool[] = [];

      for (const raw of rawTools) {
        const namespacedId = `${serverId}:${raw.name}`;
        const classification = permissionManager.classifyTool(raw.name, raw.description);

        const tool: DiscoveredTool = {
          id: namespacedId,
          originalName: raw.name,
          serverId,
          serverName: serverState.name,
          description: raw.description || `Tool '${raw.name}' provided by ${serverState.name}`,
          inputSchema: (raw.inputSchema as Record<string, unknown>) || { type: "object", properties: {} },
          permissionLevel: classification.level,
          requiresApproval: classification.requiresApproval,
        };

        this.toolCache.set(namespacedId, tool);
        discovered.push(tool);
      }

      serverRegistry.updateStatus(serverId, "connected", undefined, discovered.length);
      log.info({ serverId, toolCount: discovered.length }, "Discovered and indexed tools");
      return discovered;
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      log.error({ serverId, error: errorMessage }, "Failed to discover tools for server");
      return [];
    }
  }

  /**
   * Refreshes tool discovery across all currently connected servers.
   */
  public async refreshAll(): Promise<void> {
    const connectedServers = serverRegistry.getConnectedServers();
    for (const server of connectedServers) {
      await this.discoverServerTools(server.id);
    }
  }

  /**
   * Removes cached tools when a server is disconnected.
   */
  public unregisterServerTools(serverId: string): void {
    for (const [id, tool] of this.toolCache.entries()) {
      if (tool.serverId === serverId) {
        this.toolCache.delete(id);
      }
    }
    log.info({ serverId }, "Evicted tools from discovery cache");
  }

  /**
   * Manually registers a tool in the discovery cache (useful for testing or direct tool registration).
   */
  public registerTool(tool: DiscoveredTool): void {
    this.toolCache.set(tool.id, tool);
  }

  /**
   * Gets a specific tool by its namespaced ID (e.g. "filesystem:read_file").
   */
  public getTool(toolId: string): DiscoveredTool | undefined {
    return this.toolCache.get(toolId);
  }

  /**
   * Gets all currently discovered tools.
   */
  public getAllTools(): DiscoveredTool[] {
    return Array.from(this.toolCache.values());
  }

  /**
   * Searches tools by query text, server ID, and permission level.
   */
  public searchTools(query: string, serverId?: string, permissionLevel?: PermissionLevel): DiscoveredTool[] {
    const q = query.toLowerCase().trim();
    const all = this.getAllTools();

    return all.filter((tool) => {
      if (serverId && tool.serverId !== serverId) {
        return false;
      }
      if (permissionLevel && tool.permissionLevel !== permissionLevel) {
        return false;
      }
      if (!q) {
        return true;
      }

      const idMatch = tool.id.toLowerCase().includes(q);
      const nameMatch = tool.originalName.toLowerCase().includes(q);
      const descMatch = tool.description.toLowerCase().includes(q);
      const serverMatch = tool.serverName.toLowerCase().includes(q);

      return idMatch || nameMatch || descMatch || serverMatch;
    });
  }
}

export const discoveryEngine = new ToolDiscoveryEngine();

