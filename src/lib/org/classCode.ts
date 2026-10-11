import "server-only";
/**
 * Org affiliation codes (קוד שיוך) — shared constants + generation.
 * The model lives in supabase/migrations/0028_org_codes.sql; this file keeps
 * the API routes for org admins and the super-admin from drifting apart on the
 * numbers or the alphabet.
 */
import { randomInt } from "node:crypto";
import type { SupabaseClient } from "@supabase/supabase-js";

/** A code is usable for 24 hours from generation. */
export const CODE_TTL_HOURS = 24;
/** …and an org admin may generate one per 24 hours (super-admin exempt). */
export const GENERATE_COOLDOWN_HOURS = 24;
/** The affiliation a code grants lasts 100 days before renewal is required. */
export const AFFILIATION_DAYS = 100;

/**
 * 8 chars, no O/0/I/1/L — this code is read off a projector or a WhatsApp
 * screenshot and typed by hand, so every character must be unambiguous in
 * both directions.
 */
const ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
export function newCodeString(): string {
  let out = "";
  for (let i = 0; i < 8; i++) out += ALPHABET[randomInt(ALPHABET.length)];
  return out;
}

export interface ActiveCode {
  code: string;
  created_at: string;
  expires_at: string;
}

/** The org's currently-live code, or null. At most one exists by construction. */
export async function getActiveCode(admin: SupabaseClient, orgId: string): Promise<ActiveCode | null> {
  const { data } = await admin
    .from("org_codes")
    .select("code, created_at, expires_at")
    .eq("org_id", orgId)
    .gt("expires_at", new Date().toISOString())
    .order("created_at", { ascending: false })
    .limit(1)
    .maybeSingle();
  return data ?? null;
}

/** Thrown when an org admin is still inside the one-generation-per-24h window. */
export class CodeCooldownError extends Error {
  constructor() { super("A code was already generated in the last 24 hours."); }
}

/**
 * Generate a fresh code for an org. The cooldown check, revoke-previous (the
 * spec is one live code per org — a student typing yesterday's code gets
 * "invalid", not a quiet second door) and the insert run as ONE locked step in
 * the database (issue_org_code, 0080): as three separate calls, a double click
 * produced two live codes. Uniqueness collisions are retried — with a 31^8
 * space they are theoretical, but an unhandled 23505 would fail a teacher
 * mid-lesson.
 *
 * `cooldownHours` > 0 enforces the org admin's one-per-24h rule atomically; the
 * super-admin passes 0.
 */
export async function generateCode(
  admin: SupabaseClient,
  orgId: string,
  createdBy: string,
  opts: { cooldownHours?: number } = {},
): Promise<ActiveCode> {
  const expiresAt = new Date(Date.now() + CODE_TTL_HOURS * 3600_000).toISOString();
  for (let attempt = 0; attempt < 3; attempt++) {
    const { data, error } = await admin.rpc("issue_org_code", {
      p_org: orgId, p_created_by: createdBy, p_code: newCodeString(),
      p_expires_at: expiresAt, p_cooldown_hours: opts.cooldownHours ?? 0,
    });
    const row = (Array.isArray(data) ? data[0] : data) as ActiveCode | undefined;
    if (!error && row) return row;
    if (error?.message?.includes("code_cooldown")) throw new CodeCooldownError();
    if (error && error.code !== "23505") throw new Error(error.message);
  }
  throw new Error("Could not generate a unique code.");
}

/**
 * When this org's admin may next generate (ISO), based on the most recent
 * generation — including expired ones, or the cooldown would reset the moment
 * a code lapses. Null = may generate now.
 */
export async function nextGenerateAt(admin: SupabaseClient, orgId: string): Promise<string | null> {
  const { data } = await admin
    .from("org_codes")
    .select("created_at")
    .eq("org_id", orgId)
    .order("created_at", { ascending: false })
    .limit(1)
    .maybeSingle();
  if (!data) return null;
  const next = new Date(data.created_at).getTime() + GENERATE_COOLDOWN_HOURS * 3600_000;
  return next > Date.now() ? new Date(next).toISOString() : null;
}
