import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { DatabaseManager } from "../src/db.js";
import fs from "node:fs";
import path from "node:path";

describe("DatabaseManager: Profiles & Kanban (Milestone 1)", () => {
  const testDbPath = path.resolve("./data/test_profiles_kanban.db");
  let db: DatabaseManager;

  beforeEach(() => {
    if (fs.existsSync(testDbPath)) {
      try { fs.unlinkSync(testDbPath); } catch {}
    }
    db = new DatabaseManager(testDbPath);
  });

  afterEach(() => {
    db.close();
    if (fs.existsSync(testDbPath)) {
      try { fs.unlinkSync(testDbPath); } catch {}
    }
    const walPath = `${testDbPath}-wal`;
    const shmPath = `${testDbPath}-shm`;
    if (fs.existsSync(walPath)) try { fs.unlinkSync(walPath); } catch {}
    if (fs.existsSync(shmPath)) try { fs.unlinkSync(shmPath); } catch {}
  });

  describe("Profiles Engine Persistence", () => {
    it("should auto-seed default profiles on first migration", () => {
      const profiles = db.listProfiles();
      assert.ok(profiles.length >= 4);

      const dev = profiles.find((p) => p.id === "developer");
      assert.ok(dev);
      assert.equal(dev.name, "Developer");
      assert.equal(dev.isDefault, true);
      assert.equal(dev.isActive, true);
      assert.ok(dev.integrations.includes("filesystem"));
      assert.ok(dev.integrations.includes("github"));

      const backend = profiles.find((p) => p.id === "backend");
      assert.ok(backend?.integrations.includes("supabase"));
      assert.ok(backend?.integrations.includes("sentry"));
    });

    it("should allow creating a custom profile and retrieving it", () => {
      const custom = db.upsertProfile({
        id: "custom_ml",
        name: "ML & Data",
        description: "Custom data science profile",
        isDefault: false,
        isActive: false,
        integrations: ["filesystem", "supabase"],
        toolPolicies: {
          "filesystem:write_file": { enabled: false },
          "supabase:execute_sql": { enabled: true, requiresApproval: true },
        },
      });

      assert.equal(custom.id, "custom_ml");
      assert.equal(custom.name, "ML & Data");
      assert.deepEqual(custom.integrations, ["filesystem", "supabase"]);
      assert.equal(custom.toolPolicies["filesystem:write_file"].enabled, false);
      assert.equal(custom.toolPolicies["supabase:execute_sql"].requiresApproval, true);

      const fetched = db.getProfile("custom_ml");
      assert.equal(fetched?.name, "ML & Data");
    });

    it("should switch active profile atomically", () => {
      assert.equal(db.getActiveProfile()?.id, "developer");

      const activated = db.setActiveProfile("backend");
      assert.equal(activated?.id, "backend");
      assert.equal(activated?.isActive, true);

      const dev = db.getProfile("developer");
      assert.equal(dev?.isActive, false);
    });

    it("should reject deletion of the default profile", () => {
      const deleted = db.deleteProfile("developer");
      assert.equal(deleted, false);
      assert.ok(db.getProfile("developer") !== null);
    });

    it("should allow deleting custom non-default profiles", () => {
      db.upsertProfile({
        id: "temp_profile",
        name: "Temporary Profile",
        description: "To be deleted",
        integrations: ["filesystem"],
      });

      assert.ok(db.getProfile("temp_profile") !== null);
      const deleted = db.deleteProfile("temp_profile");
      assert.equal(deleted, true);
      assert.equal(db.getProfile("temp_profile"), null);
    });
  });

  describe("Kanban Projects & Tasks Persistence", () => {
    it("should create, list, and delete projects", () => {
      const p1 = db.upsertProject({
        id: "proj_core",
        name: "Core Gateway",
        description: "Infrastructure gateway improvements",
        color: "#38bdf8",
      });

      assert.equal(p1.name, "Core Gateway");
      assert.equal(p1.color, "#38bdf8");

      const projects = db.listProjects();
      assert.ok(projects.some((p) => p.id === "proj_core"));

      const deleted = db.deleteProject("proj_core");
      assert.equal(deleted, true);
      assert.equal(db.getProject("proj_core"), null);
    });

    it("should create tasks, manage checklists, and update status", () => {
      const task = db.upsertTask({
        id: "task_1",
        title: "Implement Streamable HTTP MCP",
        description: "Add spec-compliant HTTP transport",
        status: "TODO",
        priority: "HIGH",
        profileId: "developer",
        integrationId: "filesystem",
        labels: ["mcp", "transport"],
        checklist: [
          { id: "c1", text: "Read MCP spec", completed: true },
          { id: "c2", text: "Implement handler", completed: false },
        ],
        position: 0,
      });

      assert.equal(task.title, "Implement Streamable HTTP MCP");
      assert.equal(task.status, "TODO");
      assert.equal(task.priority, "HIGH");
      assert.equal(task.checklist.length, 2);

      // Move task to IN_PROGRESS
      const moved = db.updateTaskStatus("task_1", "IN_PROGRESS", 1);
      assert.equal(moved?.status, "IN_PROGRESS");
      assert.equal(moved?.position, 1);

      // Filter tasks by status
      const inProgress = db.listTasks({ status: "IN_PROGRESS" });
      assert.ok(inProgress.some((t) => t.id === "task_1"));

      // Filter tasks by profile
      const devTasks = db.listTasks({ profileId: "developer" });
      assert.ok(devTasks.some((t) => t.id === "task_1"));

      // Delete task
      const deleted = db.deleteTask("task_1");
      assert.equal(deleted, true);
      assert.equal(db.getTask("task_1"), null);
    });
  });
});
