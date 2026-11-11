import { dbManager } from "./db.js";
import { 
  ProfileWithDetails, 
  CreateProfileSchema, 
  UpdateProfileSchema,
} from "./types.js";
import { createChildLogger } from "./logger.js";
import crypto from "node:crypto";

const log = createChildLogger("profiles");

export class ProfilesManager {
  public listProfiles(): ProfileWithDetails[] {
    return dbManager.listProfiles();
  }

  public getProfile(id: string): ProfileWithDetails | null {
    return dbManager.getProfile(id);
  }

  public getActiveProfile(): ProfileWithDetails | null {
    return dbManager.getActiveProfile();
  }

  public setActiveProfile(id: string): ProfileWithDetails | null {
    const profile = dbManager.getProfile(id);
    if (!profile) {
      log.warn({ profileId: id }, "Attempted to activate non-existent profile");
      return null;
    }
    const updated = dbManager.setActiveProfile(id);
    if (updated) {
      log.info({ profileId: id, name: updated.name }, "Active MCP operating profile switched");
    }
    return updated;
  }

  public createProfile(input: {
    name: string;
    description?: string;
    isDefault?: boolean;
    integrations?: string[];
  }): ProfileWithDetails {
    const validated = CreateProfileSchema.parse(input);
    const id = validated.name.toLowerCase().replace(/[^a-z0-9_-]/g, "_") + "_" + crypto.randomBytes(3).toString("hex");

    const created = dbManager.upsertProfile({
      id,
      name: validated.name,
      description: validated.description || "",
      isDefault: validated.isDefault,
      isActive: false,
      integrations: validated.integrations,
      toolPolicies: {},
    });

    log.info({ profileId: id, name: created.name }, "Created new MCP operating profile");
    return created;
  }

  public updateProfile(
    id: string,
    input: {
      name?: string;
      description?: string;
      isDefault?: boolean;
      integrations?: string[];
      toolPolicies?: Record<string, { enabled: boolean; requiresApproval?: boolean }>;
    }
  ): ProfileWithDetails | null {
    const existing = dbManager.getProfile(id);
    if (!existing) return null;

    const validated = UpdateProfileSchema.parse(input);

    const updated = dbManager.upsertProfile({
      id,
      name: validated.name !== undefined ? validated.name : existing.name,
      description: validated.description !== undefined ? validated.description : existing.description,
      isDefault: validated.isDefault !== undefined ? validated.isDefault : existing.isDefault,
      isActive: existing.isActive,
      integrations: validated.integrations !== undefined ? validated.integrations : existing.integrations,
      toolPolicies: validated.toolPolicies !== undefined ? validated.toolPolicies : existing.toolPolicies,
    });

    log.info({ profileId: id, name: updated.name }, "Updated MCP operating profile");
    return updated;
  }

  public duplicateProfile(sourceId: string, newName?: string): ProfileWithDetails | null {
    const source = dbManager.getProfile(sourceId);
    if (!source) return null;

    const name = newName || `${source.name} (Copy)`;
    const id = name.toLowerCase().replace(/[^a-z0-9_-]/g, "_") + "_" + crypto.randomBytes(3).toString("hex");

    const duplicated = dbManager.upsertProfile({
      id,
      name,
      description: `Duplicated from ${source.name}. ${source.description}`,
      isDefault: false,
      isActive: false,
      integrations: [...source.integrations],
      toolPolicies: { ...source.toolPolicies },
    });

    log.info({ sourceId, newId: id, name: duplicated.name }, "Duplicated MCP operating profile");
    return duplicated;
  }

  public deleteProfile(id: string): boolean {
    const profile = dbManager.getProfile(id);
    if (!profile) return false;
    if (profile.isDefault) {
      log.warn({ profileId: id }, "Cannot delete default operating profile");
      return false;
    }

    const wasActive = profile.isActive;
    const deleted = dbManager.deleteProfile(id);
    if (deleted && wasActive) {
      // Revert to default profile
      const profiles = dbManager.listProfiles();
      const defaultProf = profiles.find((p) => p.isDefault) || profiles[0];
      if (defaultProf) {
        dbManager.setActiveProfile(defaultProf.id);
      }
    }
    log.info({ profileId: id }, "Deleted MCP operating profile");
    return deleted;
  }

  /**
   * Evaluates whether a tool is allowed under the given profile context or active profile.
   * - If profileContext is provided (e.g. from an isolated remote session), strictly evaluates against that profile.
   * - If profileContext is a string, looks up the profile by ID. If non-existent, denies access.
   * - If profileContext is omitted, defaults to evaluating against the global active profile (local STDIO mode).
   * - Restricts tools if the parent server integration is disabled in the profile.
   * - Enforces granular tool-level policy overrides (enable/disable, approval override).
   * - Enforces strict read-only boundary when profile is 'readonly'.
   */
  public evaluateToolAccess(
    toolId: string,
    serverId: string,
    permissionLevel?: string,
    profileContext?: string | ProfileWithDetails
  ): {
    allowed: boolean;
    reason?: string;
    requiresApprovalOverride?: boolean;
  } {
    let effectiveProfile: ProfileWithDetails | null = null;

    if (profileContext) {
      if (typeof profileContext === "string") {
        effectiveProfile = this.getProfile(profileContext);
        if (!effectiveProfile) {
          return {
            allowed: false,
            reason: `Execution denied: Assigned profile '${profileContext}' does not exist or has been deleted.`,
          };
        }
      } else {
        effectiveProfile = profileContext;
      }
    } else {
      effectiveProfile = this.getActiveProfile();
    }

    if (!effectiveProfile) {
      return { allowed: true };
    }

    // 1. Enforce strict Read-Only boundary on read-only profiles
    if (effectiveProfile.id === "readonly" && permissionLevel && permissionLevel !== "READ_ONLY") {
      return {
        allowed: false,
        reason: `Operation prohibited: Tool '${toolId}' requires '${permissionLevel}' permissions, but bound profile '${effectiveProfile.name}' is strictly READ_ONLY.`,
      };
    }

    // 2. Check if the parent integration is enabled in this profile
    const integrationEnabled = effectiveProfile.integrations.includes(serverId);
    if (!integrationEnabled) {
      return {
        allowed: false,
        reason: `Server '${serverId}' is disabled in active profile '${effectiveProfile.name}'`,
      };
    }

    // 3. Check tool-specific policy override if defined
    const toolPolicy = effectiveProfile.toolPolicies[toolId];
    if (toolPolicy) {
      if (!toolPolicy.enabled) {
        return {
          allowed: false,
          reason: `Tool '${toolId}' is explicitly disabled in active profile '${effectiveProfile.name}'`,
        };
      }
      return {
        allowed: true,
        requiresApprovalOverride: toolPolicy.requiresApproval,
      };
    }

    return { allowed: true };
  }
}

export const profilesManager = new ProfilesManager();

