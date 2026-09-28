/**
 * Pure readiness rule behind useProgressSnapshot (kept free of React / auth
 * imports so it is unit-testable). See useProgressSnapshot.ts for the #1 root cause.
 */
export interface ProgressReadyInput {
  authEnabled: boolean;
  authLoading: boolean;
  userId: string | null;
  hydrated: boolean;
}

/** Pure readiness rule (unit-tested). */
export function isProgressReady({ authEnabled, authLoading, userId, hydrated }: ProgressReadyInput): boolean {
  if (!authEnabled) return true;   // no auth backend → localStorage is the source
  if (authLoading) return false;   // don't know yet whether to read local or remote
  if (!userId) return true;        // guest → localStorage is the source
  return hydrated;                 // signed in → only the hydrated remote cache
}
