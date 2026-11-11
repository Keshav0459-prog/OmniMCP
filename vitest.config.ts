import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    testTimeout: 20000,
    hookTimeout: 20000,
    fileParallelism: false,
    exclude: [
      "**/node_modules/**",
      "**/dist/**",
      "tests/db_profiles_kanban.test.ts",
      "tests/profiles_engine.test.ts",
    ],
  },
});

