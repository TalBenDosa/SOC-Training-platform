/**
 * Test-time stand-in for the `server-only` import.
 *
 * `server-only` is not an installed dependency — Next.js resolves it inside its
 * own bundler as a poison pill that fails the build if a Client Component pulls
 * in a server module. Vitest has no such resolution, so importing any module
 * that declares `import "server-only"` (e.g. src/lib/rooms/grading.ts) fails at
 * transform time. vitest.config.ts aliases the specifier here.
 *
 * Deliberately a no-op: the guarantee it enforces is a BUILD-time one, and
 * `next build` still enforces it for real. Stubbing it in tests removes the
 * import error without weakening anything the tests are meant to prove.
 */
export {};
