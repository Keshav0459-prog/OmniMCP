import { z } from "zod";

export type TransportType = "stdio" | "http" | "sse";

export type ServerStatus = "disconnected" | "connecting" | "connected" | "error";

export type PermissionLevel = "READ_ONLY" | "WRITE_PROTECTED" | "DESTRUCTIVE_ADMIN";

export interface ServerConfig {
  id: string;
  name: string;
  description: string;
  category: "core" | "development" | "browser" | "database" | "observability" | "custom";
  transport: TransportType;
  enabled: boolean;
  autoConnect: boolean;
  
  // STDIO options
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  cwd?: string;
  
  // HTTP / SSE options
  url?: string;
  headers?: Record<string, string>;
  
  // Security
  allowedPermissions?: PermissionLevel[];
  requiresApprovalForDestructive?: boolean;
}

export interface ServerState extends ServerConfig {
  status: ServerStatus;
  error?: string;
  lastConnectedAt?: string;
  latencyMs?: number;
  toolCount: number;
}

export interface DiscoveredTool {
  id: string; // namespaced: e.g. "filesystem:read_file"
  originalName: string;
  serverId: string;
  serverName: string;
  description: string;
  inputSchema: Record<string, unknown>;
  permissionLevel: PermissionLevel;
  requiresApproval: boolean;
}

export interface ExecutionRecord {
  id: string;
  traceId: string;
  toolId: string;
  serverId: string;
  originalToolName: string;
  inputParameters: Record<string, unknown>;
  outputResult?: unknown;
  status: "success" | "error" | "denied";
  durationMs: number;
  timestamp: string;
  error?: string;
}

export type ApprovalEventType =
  | "approval_requested"
  | "approval_approved"
  | "approval_rejected"
  | "approval_expired"
  | "approval_consumed"
  | "approval_failed";

export interface ApprovalAuditEvent {
  id: string;
  requestId: string;
  eventType: ApprovalEventType;
  toolId: string;
  serverId: string;
  paramsHash: string;
  operatorIdentity?: string;
  traceId?: string;
  timestamp: string;
  status: string;
  details?: Record<string, unknown>;
}

export interface ProjectContext {
  gatewayVersion: string;
  activeServers: {
    id: string;
    name: string;
    status: ServerStatus;
    toolCount: number;
    latencyMs?: number;
  }[];
  totalDiscoveredTools: number;
  toolsByServer: Record<string, string[]>;
  securityPolicy: {
    leastPrivilegeEnforced: boolean;
    encryptedVaultActive: boolean;
    requireDestructiveApproval: boolean;
  };
}

export interface AgentTokenRecord {
  id: string;
  tokenHash: string; // SHA-256 hash of the raw token (raw token is NEVER persisted)
  tokenPrefix: string; // e.g. "omnimcp_agent_a1b2••••" (first 18 chars for display identification)
  principalId: string;
  assignedProfileId: string; // Mandatory explicit profile assignment (e.g. "developer", "readonly")
  name: string;
  isRevoked: boolean;
  createdAt: number;
  expiresAt: number | null;
  lastUsedAt: number | null;
  revokedAt: number | null;
}

// Zod Schemas for Gateway Tool Arguments
export const SearchServersSchema = z.object({
  query: z.string().optional().describe("Search query for server name or description"),
  category: z.string().optional().describe("Filter by category (e.g. core, development, browser, database, observability)"),
  status: z.enum(["connected", "disconnected", "error", "all"]).optional().describe("Filter by connection status"),
});

export const ServerStatusSchema = z.object({
  server_id: z.string().describe("ID of the registered server (e.g. filesystem, github, context7)"),
});

export const SearchToolsSchema = z.object({
  query: z.string().describe("Search query matching tool name, tags or capabilities"),
  server_id: z.string().optional().describe("Filter tools by specific server ID"),
  permission_level: z.enum(["READ_ONLY", "WRITE_PROTECTED", "DESTRUCTIVE_ADMIN"]).optional().describe("Filter by permission level"),
});

export const ToolDetailsSchema = z.object({
  tool_id: z.string().describe("Namespaced tool ID (e.g. 'filesystem:read_file' or 'github:create_issue')"),
});

export const ConnectServerSchema = z.object({
  server_id: z.string().describe("ID of the server to connect"),
  allowed_directories: z.array(z.string()).optional().describe("Optional path overrides for filesystem server"),
});

export const DisconnectServerSchema = z.object({
  server_id: z.string().describe("ID of the server to disconnect"),
});

export const CallToolSchema = z.object({
  tool_id: z.string().describe("Namespaced tool ID (e.g. 'filesystem:read_file' or 'github:search_repositories')"),
  parameters: z.record(z.string(), z.unknown()).default({}).describe("JSON arguments to supply to the child tool"),
  confirm_sensitive: z.boolean().optional().describe("Explicit user/agent confirmation if this operation is classified as destructive or write-protected"),
});

export const ExecutionHistorySchema = z.object({
  limit: z.number().int().min(1).max(100).optional().default(20).describe("Maximum number of recent executions to retrieve"),
  server_id: z.string().optional().describe("Filter history by server ID"),
  status: z.enum(["success", "error", "denied"]).optional().describe("Filter history by execution status"),
});

export const ProjectContextSchema = z.object({
  cwd: z.string().optional().describe("Current working directory context"),
});

// ==============================================================================
// Profiles Engine Types & Schemas
// ==============================================================================

export interface Profile {
  id: string;
  name: string;
  description: string;
  isDefault: boolean;
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface ProfileIntegration {
  id: string;
  profileId: string;
  serverId: string;
  enabled: boolean;
  createdAt: string;
}

export interface ProfileToolPolicy {
  id: string;
  profileId: string;
  toolId: string;
  enabled: boolean;
  requiresApproval?: boolean;
  createdAt: string;
}

export interface ProfileWithDetails extends Profile {
  integrations: string[]; // serverIds
  toolPolicies: Record<string, { enabled: boolean; requiresApproval?: boolean }>;
}

export const CreateProfileSchema = z.object({
  name: z.string().min(1).max(64),
  description: z.string().max(256).default(""),
  isDefault: z.boolean().default(false),
  integrations: z.array(z.string()).default([]),
});

export const UpdateProfileSchema = z.object({
  name: z.string().min(1).max(64).optional(),
  description: z.string().max(256).optional(),
  isDefault: z.boolean().optional(),
  integrations: z.array(z.string()).optional(),
  toolPolicies: z.record(z.string(), z.object({
    enabled: z.boolean(),
    requiresApproval: z.boolean().optional(),
  })).optional(),
});

// ==============================================================================
// Projects & Kanban Types & Schemas
// ==============================================================================

export type TaskStatus = "BACKLOG" | "TODO" | "IN_PROGRESS" | "REVIEW" | "DONE";
export type TaskPriority = "LOW" | "MEDIUM" | "HIGH" | "URGENT";

export interface Project {
  id: string;
  name: string;
  description?: string;
  color?: string;
  createdAt: string;
  updatedAt: string;
}

export interface TaskChecklistItem {
  id: string;
  text: string;
  completed: boolean;
}

export interface Task {
  id: string;
  projectId?: string;
  title: string;
  description?: string;
  status: TaskStatus;
  priority: TaskPriority;
  assignee?: string;
  dueDate?: string;
  profileId?: string;
  integrationId?: string;
  labels: string[];
  checklist: TaskChecklistItem[];
  position: number;
  createdAt: string;
  updatedAt: string;
}

export const CreateTaskSchema = z.object({
  projectId: z.string().optional(),
  title: z.string().min(1).max(256),
  description: z.string().max(4096).optional(),
  status: z.enum(["BACKLOG", "TODO", "IN_PROGRESS", "REVIEW", "DONE"]).default("TODO"),
  priority: z.enum(["LOW", "MEDIUM", "HIGH", "URGENT"]).default("MEDIUM"),
  assignee: z.string().optional(),
  dueDate: z.string().optional(),
  profileId: z.string().optional(),
  integrationId: z.string().optional(),
  labels: z.array(z.string()).default([]),
  checklist: z.array(z.object({
    id: z.string(),
    text: z.string(),
    completed: z.boolean(),
  })).default([]),
  position: z.number().int().default(0),
});

export const UpdateTaskSchema = z.object({
  projectId: z.string().optional().nullable(),
  title: z.string().min(1).max(256).optional(),
  description: z.string().max(4096).optional().nullable(),
  status: z.enum(["BACKLOG", "TODO", "IN_PROGRESS", "REVIEW", "DONE"]).optional(),
  priority: z.enum(["LOW", "MEDIUM", "HIGH", "URGENT"]).optional(),
  assignee: z.string().optional().nullable(),
  dueDate: z.string().optional().nullable(),
  profileId: z.string().optional().nullable(),
  integrationId: z.string().optional().nullable(),
  labels: z.array(z.string()).optional(),
  checklist: z.array(z.object({
    id: z.string(),
    text: z.string(),
    completed: z.boolean(),
  })).optional(),
  position: z.number().int().optional(),
});


