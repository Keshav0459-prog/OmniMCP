import { DiscoveredTool, ServerState } from "./types.js";
import { serverRegistry } from "./registry.js";
import { discoveryEngine } from "./discovery.js";
import { executionEngine, ExecutionResult } from "./executor.js";
import { createChildLogger } from "./logger.js";

const log = createChildLogger("router");

export interface RoutingTaskStep {
  id: string;
  toolId: string;
  parameters: Record<string, unknown>;
  dependsOn?: string[]; // step IDs that must complete before this step
  confirmSensitive?: boolean;
}

export interface RoutingPlan {
  task: string;
  requiredServers: string[];
  steps: RoutingTaskStep[];
  estimatedPermissionTier: "READ_ONLY" | "WRITE_PROTECTED" | "DESTRUCTIVE_ADMIN";
}

export interface RoutingExecutionSummary {
  task: string;
  success: boolean;
  totalDurationMs: number;
  completedSteps: number;
  failedSteps: number;
  stepResults: Record<string, ExecutionResult>;
  error?: string;
}

export class SmartRoutingEngine {
  /**
   * Matches keywords in a task description to relevant MCP servers and capabilities.
   */
  public matchCapabilities(taskDescription: string): {
    matchedServers: ServerState[];
    recommendedTools: DiscoveredTool[];
  } {
    const text = taskDescription.toLowerCase();
    const matchedServers = new Set<ServerState>();
    const recommendedTools: DiscoveredTool[] = [];

    // Keyword mapping to server categories
    const categoryTriggers: Record<string, string[]> = {
      filesystem: ["file", "folder", "directory", "read", "write", "workspace", "codebase", "package.json"],
      github: ["git", "github", "repo", "repository", "pull request", "pr", "issue", "branch", "commit"],
      context7: ["docs", "documentation", "library", "framework", "api reference", "package docs", "context7"],
      playwright: ["browser", "e2e", "scrape", "test", "screenshot", "navigate", "dom", "ui"],
      supabase: ["database", "postgres", "sql", "table", "supabase", "auth", "storage"],
      shadcn: ["shadcn", "component", "button", "dialog", "tailwind", "radix", "ui component"],
      sentry: ["sentry", "error", "exception", "crash", "observability", "telemetry", "tracing"],
    };

    for (const [serverId, triggers] of Object.entries(categoryTriggers)) {
      if (triggers.some((trigger) => text.includes(trigger))) {
        const s = serverRegistry.getServer(serverId);
        if (s) {
          matchedServers.add(s);
        }
      }
    }

    // If nothing specific matched, include core filesystem by default
    if (matchedServers.size === 0) {
      const fsServer = serverRegistry.getServer("filesystem");
      if (fsServer) matchedServers.add(fsServer);
    }

    // Find recommended tools from matched servers
    for (const server of matchedServers) {
      const tools = discoveryEngine.getAllTools().filter((t) => t.serverId === server.id);
      recommendedTools.push(...tools);
    }

    log.info(
      { task: taskDescription, matchedCount: matchedServers.size, toolsFound: recommendedTools.length },
      "Smart routing capability matching complete"
    );

    return {
      matchedServers: Array.from(matchedServers),
      recommendedTools,
    };
  }

  /**
   * Validates a routing plan DAG upfront.
   * Rejects duplicate step IDs, non-existent dependencies, self-dependencies, and circular dependency loops.
   */
  public validatePlan(plan: RoutingPlan): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!plan || !Array.isArray(plan.steps) || plan.steps.length === 0) {
      return { valid: false, errors: ["Plan must contain at least one step in 'steps' array."] };
    }

    const stepIds = new Set<string>();
    for (const step of plan.steps) {
      if (!step.id || step.id.trim() === "") {
        errors.push("Step is missing required 'id'.");
      } else if (stepIds.has(step.id)) {
        errors.push(`Duplicate step ID detected: '${step.id}'. Step IDs must be unique.`);
      } else {
        stepIds.add(step.id);
      }

      if (!step.toolId || !step.toolId.includes(":")) {
        errors.push(`Invalid toolId '${step.toolId}' in step '${step.id}'. Expected namespaced format 'server:tool'.`);
      }
    }

    // Check dependency validity
    for (const step of plan.steps) {
      if (step.dependsOn && Array.isArray(step.dependsOn)) {
        for (const depId of step.dependsOn) {
          if (depId === step.id) {
            errors.push(`Self-referencing dependency detected: step '${step.id}' cannot depend on itself.`);
          } else if (!stepIds.has(depId)) {
            errors.push(`Unresolved dependency: step '${step.id}' depends on non-existent step '${depId}'.`);
          }
        }
      }
    }

    // Cycle detection using Kahn's algorithm
    if (errors.length === 0) {
      const inDegree = new Map<string, number>();
      const adjList = new Map<string, string[]>();

      for (const step of plan.steps) {
        inDegree.set(step.id, (step.dependsOn || []).length);
        adjList.set(step.id, []);
      }

      for (const step of plan.steps) {
        for (const depId of step.dependsOn || []) {
          adjList.get(depId)?.push(step.id);
        }
      }

      const queue: string[] = [];
      for (const [id, deg] of inDegree.entries()) {
        if (deg === 0) {
          queue.push(id);
        }
      }

      let visitedCount = 0;
      while (queue.length > 0) {
        const curr = queue.shift()!;
        visitedCount++;

        for (const neighbor of adjList.get(curr) || []) {
          const newDeg = (inDegree.get(neighbor) || 1) - 1;
          inDegree.set(neighbor, newDeg);
          if (newDeg === 0) {
            queue.push(neighbor);
          }
        }
      }

      if (visitedCount !== plan.steps.length) {
        errors.push("Circular dependency detected in execution plan DAG. Steps form a cyclic loop.");
      }
    }

    return { valid: errors.length === 0, errors };
  }

  /**
   * Executes a multi-step routing plan with topological dependency resolution.
   * Steps without dependencies execute concurrently; dependent steps execute sequentially.
   */
  public async executePlan(plan: RoutingPlan): Promise<RoutingExecutionSummary> {
    const startTime = Date.now();

    // 1. Validate DAG plan integrity upfront
    const validation = this.validatePlan(plan);
    if (!validation.valid) {
      log.warn({ task: plan.task, errors: validation.errors }, "Routing plan rejected due to DAG validation errors");
      return {
        task: plan.task || "unnamed_task",
        success: false,
        totalDurationMs: 0,
        completedSteps: 0,
        failedSteps: plan.steps?.length || 0,
        stepResults: {},
        error: `DAG Validation Failed: ${validation.errors.join("; ")}`,
      };
    }

    const stepResults: Record<string, ExecutionResult> = {};
    const pendingSteps = new Map<string, RoutingTaskStep>(plan.steps.map((s) => [s.id, s]));
    let failed = false;
    let failureReason: string | undefined;

    log.info({ task: plan.task, stepCount: plan.steps.length }, "Executing smart routing plan");

    while (pendingSteps.size > 0 && !failed) {
      // Find all steps whose dependencies have succeeded
      const readySteps: RoutingTaskStep[] = [];

      for (const step of pendingSteps.values()) {
        const deps = step.dependsOn || [];
        const depsSatisfied = deps.every((depId) => stepResults[depId] && stepResults[depId].status === "success");

        if (depsSatisfied) {
          readySteps.push(step);
        }
      }

      if (readySteps.length === 0) {
        failed = true;
        failureReason = "Deadlock or unresolved dependency in smart routing plan.";
        log.error({ remaining: Array.from(pendingSteps.keys()) }, failureReason);
        break;
      }

      // Execute ready steps concurrently
      const executions = readySteps.map(async (step) => {
        pendingSteps.delete(step.id);
        const res = await executionEngine.executeTool(step.toolId, step.parameters, {
          confirmSensitive: step.confirmSensitive,
        });
        stepResults[step.id] = res;

        if (res.status !== "success") {
          failed = true;
          failureReason = `Step '${step.id}' (${step.toolId}) failed: ${res.error}`;
        }
      });

      await Promise.all(executions);
    }

    const completed = Object.values(stepResults).filter((r) => r.status === "success").length;
    const failedCount = Object.values(stepResults).filter((r) => r.status !== "success").length;

    return {
      task: plan.task,
      success: !failed,
      totalDurationMs: Date.now() - startTime,
      completedSteps: completed,
      failedSteps: failedCount,
      stepResults,
      error: failureReason,
    };
  }
}

export const smartRouter = new SmartRoutingEngine();
