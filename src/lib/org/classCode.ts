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

/**
 * Generate a fresh code for an org: expire whatever is live, insert the new
 * one. Uniqueness collisions are retried — with a 31^8 space they are
 * theoretical, but a retry loop costs three lines and an unhandled 23505
 * would fail a teacher mid-lesson.
 */
export async function generateCode(
  admin: SupabaseClient,
  orgId: string,
  createdBy: string,
): Promise<ActiveCode> {
  const nowIso = new Date().toISOString();
  // Revoke-previous: the spec is one live code per org, and a student typing
  // yesterday's code should get "invalid", not a quiet second door.
  await admin.from("org_codes").update({ expires_at: nowIso })
    .eq("org_id", orgId).gt("expires_at", nowIso);

  const expiresAt = new Date(Date.now() + CODE_TTL_HOURS * 3600_000).toISOString();
  for (let attempt = 0; attempt < 3; attempt++) {
    const { data, error } = await admin
      .from("org_codes")
      .insert({ org_id: orgId, code: newCodeString(), created_by: createdBy, expires_at: expiresAt })
      .select("code, created_at, expires_at")
      .single();
    if (!error && data) return data;
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
