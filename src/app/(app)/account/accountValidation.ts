/**
 * Validation for the self-service Account edits (FB-011).
 *
 * Imported by BOTH the Account page (instant, friendly feedback) and the
 * /api/account routes (the rule that actually holds). Keeping one copy means
 * the form can never accept something the server then rejects with a
 * different message, or vice versa. Pure functions, no I/O — unit-tested in
 * accountValidation.test.ts.
 *
 * The handle rules deliberately mirror the database's own
 * `public.handle_available()` (migration 0006) and the signup form, so a
 * handle chosen here obeys exactly the same contract as one chosen at signup.
 */

export type Validation<T> = { ok: true; value: T } | { ok: false; error: string };

/** Full-name length bounds. 60 matches the signup form and trigger 0009's cap. */
export const FULL_NAME_MIN = 2;
export const FULL_NAME_MAX = 60;

/** Handle format — identical to signup's HANDLE_RE and handle_available(). */
export const HANDLE_RE = /^[a-z0-9_]{3,20}$/;

/** Names that would be confusing or misleading to hold — same list as 0006. */
export const RESERVED_HANDLES: ReadonlySet<string> = new Set([
  "admin", "administrator", "root", "system", "support",
  "moderator", "staff", "security", "hackthesoc", "soc",
]);

/** Password bounds. 8 matches signup + /update-password; 72 is bcrypt's byte cap. */
export const PASSWORD_MIN = 8;
export const PASSWORD_MAX_BYTES = 72;

/**
 * Characters that must never appear in a name shown to other people:
 *  - C0/C1 control characters (newlines, tabs, NUL, escape sequences…)
 *  - zero-width characters and the BOM (invisible padding → look-alike names)
 *  - bidi embedding/override/isolate controls and LRM/RLM, which can visually
 *    reverse text ("Trojan Source"-style spoofing on the leaderboard/certificates).
 * Ordinary Hebrew/Arabic letters are unaffected — only the invisible controls.
 */
// eslint-disable-next-line no-control-regex
const FORBIDDEN_CHARS = /[\u0000-\u001F\u007F-\u009F​-‏‪-‮⁠-⁩﻿]/;

export function hasForbiddenChars(s: string): boolean {
  return FORBIDDEN_CHARS.test(s);
}

/** Length in user-perceived code points, so "שלום" counts 4, not UTF-16 units. */
function codePointLength(s: string): number {
  return Array.from(s).length;
}

/**
 * Full name (stored in profiles.display_name — printed on rank certificates).
 * Trims, collapses runs of spaces, rejects control/invisible characters and
 * strings with no letter at all ("!!!", "123").
 */
export function validateFullName(raw: unknown): Validation<string> {
  if (typeof raw !== "string") return { ok: false, error: "Enter your name." };
  if (hasForbiddenChars(raw)) {
    return { ok: false, error: "Your name contains invisible or control characters. Please retype it." };
  }
  const value = raw.trim().replace(/ {2,}/g, " ");
  const len = codePointLength(value);
  if (len < FULL_NAME_MIN) return { ok: false, error: `Name must be at least ${FULL_NAME_MIN} characters.` };
  if (len > FULL_NAME_MAX) return { ok: false, error: `Name must be at most ${FULL_NAME_MAX} characters.` };
  if (!/\p{L}/u.test(value)) return { ok: false, error: "Name must contain at least one letter." };
  return { ok: true, value };
}

/** Normalise a handle the way the database does: lower(trim(x)). */
export function normaliseHandle(raw: string): string {
  return raw.trim().toLowerCase();
}

/**
 * Handle (profiles.handle — the public nickname on the leaderboard/Topbar).
 * Format + reserved-name check only; availability is a server-side lookup.
 */
export function validateHandle(raw: unknown): Validation<string> {
  if (typeof raw !== "string") return { ok: false, error: "Enter a handle." };
  const value = normaliseHandle(raw);
  if (value.length < 3 || value.length > 20) {
    return { ok: false, error: "Handle must be 3–20 characters." };
  }
  if (!HANDLE_RE.test(value)) {
    return { ok: false, error: "Use only lowercase letters, numbers and underscores." };
  }
  if (RESERVED_HANDLES.has(value)) {
    return { ok: false, error: `"${value}" is reserved. Pick another handle.` };
  }
  return { ok: true, value };
}

function utf8Bytes(s: string): number {
  return new TextEncoder().encode(s).length;
}

/**
 * New-password rules for the signed-in change flow. Strength matches signup and
 * the reset flow (min 8); the extra checks are ones only this flow can make:
 * the confirmation must match, and the new password must differ from the one
 * just re-entered as "current".
 */
export function validatePasswordChange(input: {
  current: unknown;
  next: unknown;
  confirm: unknown;
}): Validation<{ current: string; next: string }> {
  const { current, next, confirm } = input;
  if (typeof current !== "string" || current.length === 0) {
    return { ok: false, error: "Enter your current password." };
  }
  if (typeof next !== "string" || next.length < PASSWORD_MIN) {
    return { ok: false, error: `New password must be at least ${PASSWORD_MIN} characters.` };
  }
  if (utf8Bytes(next) > PASSWORD_MAX_BYTES) {
    return { ok: false, error: `New password is too long (max ${PASSWORD_MAX_BYTES} bytes).` };
  }
  if (typeof confirm !== "string" || confirm !== next) {
    return { ok: false, error: "The new password and its confirmation don't match." };
  }
  if (next === current) {
    return { ok: false, error: "The new password must be different from your current one." };
  }
  return { ok: true, value: { current, next } };
}
