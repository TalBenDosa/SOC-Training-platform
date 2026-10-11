import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

export default defineConfig({
  // tsconfig keeps JSX as-is for Next ("preserve"); tests that render a real
  // component (.tsx) need the transformer (oxc in Vite 8) to compile it.
  oxc: { jsx: { runtime: "automatic" } },
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
    // Registry-wide content checks (every scenario / pack / the client import
    // graph) take 3–6 s each and tipped over the 5 s default under a full parallel
    // run; a real hang still fails, just later.
    testTimeout: 20_000,
  },
});
