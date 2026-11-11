import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { smartRouter } from "../src/router.js";
import { clientManager } from "../src/client-manager.js";
import { serverRegistry } from "../src/registry.js";
import { discoveryEngine } from "../src/discovery.js";

describe("SmartRoutingEngine", () => {
  beforeAll(async () => {
    const fsConfig = serverRegistry.getServer("filesystem")!;
    await clientManager.connectServer(fsConfig);
    await discoveryEngine.discoverServerTools("filesystem");
  }, 20000);

  afterAll(async () => {
    await clientManager.disconnectAll();
  });

  it("should match capabilities based on natural language task description", () => {
    const match1 = smartRouter.matchCapabilities("I need to inspect package.json and write a test file");
    expect(match1.matchedServers.some((s) => s.id === "filesystem")).toBe(true);

    const match2 = smartRouter.matchCapabilities("Query documentation for react libraries");
    expect(match2.matchedServers.some((s) => s.id === "context7")).toBe(true);
  });

  it("should execute multi-step plan with dependency resolution", async () => {
    const plan = {
      task: "Inspect directories then read text file",
      requiredServers: ["filesystem"],
      estimatedPermissionTier: "READ_ONLY" as const,
      steps: [
        {
          id: "step1",
          toolId: "filesystem:list_allowed_directories",
          parameters: {},
        },
        {
          id: "step2",
          toolId: "filesystem:list_directory",
          parameters: { path: process.cwd() },
          dependsOn: ["step1"],
        },
      ],
    };

    const summary = await smartRouter.executePlan(plan);
    expect(summary.success).toBe(true);
    expect(summary.completedSteps).toBe(2);
    expect(summary.stepResults["step1"].status).toBe("success");
    expect(summary.stepResults["step2"].status).toBe("success");
  });

  describe("DAG Validation", () => {
    it("should reject plans with circular dependencies", () => {
      const cyclicPlan = {
        task: "Cyclic task",
        requiredServers: ["filesystem"],
        estimatedPermissionTier: "READ_ONLY" as const,
        steps: [
          { id: "stepA", toolId: "filesystem:list_directory", parameters: {}, dependsOn: ["stepB"] },
          { id: "stepB", toolId: "filesystem:read_file", parameters: {}, dependsOn: ["stepA"] },
        ],
      };

      const result = smartRouter.validatePlan(cyclicPlan);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes("Circular dependency"))).toBe(true);
    });

    it("should reject plans with duplicate step IDs", () => {
      const dupPlan = {
        task: "Duplicate task",
        requiredServers: ["filesystem"],
        estimatedPermissionTier: "READ_ONLY" as const,
        steps: [
          { id: "step1", toolId: "filesystem:list_directory", parameters: {} },
          { id: "step1", toolId: "filesystem:read_file", parameters: {} },
        ],
      };

      const result = smartRouter.validatePlan(dupPlan);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes("Duplicate step ID"))).toBe(true);
    });

    it("should reject plans with self-referencing or missing dependencies", () => {
      const selfRefPlan = {
        task: "Self ref task",
        requiredServers: ["filesystem"],
        estimatedPermissionTier: "READ_ONLY" as const,
        steps: [
          { id: "step1", toolId: "filesystem:list_directory", parameters: {}, dependsOn: ["step1"] },
        ],
      };

      const selfResult = smartRouter.validatePlan(selfRefPlan);
      expect(selfResult.valid).toBe(false);
      expect(selfResult.errors.some((e) => e.includes("cannot depend on itself"))).toBe(true);

      const missingDepPlan = {
        task: "Missing dep task",
        requiredServers: ["filesystem"],
        estimatedPermissionTier: "READ_ONLY" as const,
        steps: [
          { id: "step1", toolId: "filesystem:list_directory", parameters: {}, dependsOn: ["non_existent_step"] },
        ],
      };

      const missingResult = smartRouter.validatePlan(missingDepPlan);
      expect(missingResult.valid).toBe(false);
      expect(missingResult.errors.some((e) => e.includes("non-existent step"))).toBe(true);
    });
  });
});

