import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

export default defineConfig({
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
      // `server-only` is resolved by Next's own bundler, not npm, so vitest
      // cannot find it and any module declaring it fails at transform time.
      // See the stub for why a no-op is the right substitute here.
      "server-only": fileURLToPath(new URL("./src/test/server-only-stub.ts", import.meta.url)),
    },
  },
  test: {
    // jsdom, not node: the storage layer's retry path listens for `online` /
    // custom window events, which is precisely the behaviour under test.
    environment: "jsdom",
    // Only src/** — the PGlite suites under scripts/ are separate CI steps and
    // are not vitest tests.
    include: ["src/**/*.{test,spec}.ts"],
  },
});
