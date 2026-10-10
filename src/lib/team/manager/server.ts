/** Server-side loading for the SOC-Manager director and manager-state routes (service role). */
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Ev } from "@/lib/team/types";
import { pageAll } from "@/lib/team/report/serverReport";
import { COMPANY_ASSETS } from "@/lib/sim/companyProfilesMeta";
import type { Member, Difficulty } from "./state";
import type { CardAnswerKey } from "./director";
import type { QuestionKey } from "./questions";

export interface ManagerSession {
  id: string; org_id: string; status: string; schema_version: number | null;
  company_id: string; difficulty: Difficulty;
}

export async function loadSession(admin: SupabaseClient, id: string): Promise<ManagerSession | null> {
  const { data } = await admin.from("team_sessions").select("id, org_id, status, schema_version, company_id, difficulty").eq("id", id).maybeSingle();
  return (data as ManagerSession | null) ?? null;
}

export async function loadRoster(admin: SupabaseClient, sessionId: string): Promise<Member[]> {
  const { data: mem, error } = await admin.from("team_session_members").select("user_id, role, status").eq("session_id", sessionId);
  if (error || !mem?.length) return [];
  const { data: profs } = await admin.from("profiles").select("id, handle, display_name").in("id", mem.map(m => m.user_id));
  const pmap = new Map((profs ?? []).map(p => [p.id as string, p as { handle?: string; display_name?: string }]));
  return mem.map(m => {
    const p = pmap.get(m.user_id);
    return { user_id: m.user_id, role: m.role, status: m.status, name: p?.display_name || p?.handle || "a teammate" };
  });
}

/** Every session event except the raw feed (the director reads team actions, not log lines). */
export async function loadTeamEvents(admin: SupabaseClient, sessionId: string): Promise<Ev[]> {
  return pageAll<Ev>((from, to) => admin.from("session_events")
    .select("seq, type, actor_id, role, payload, occurred_at").eq("session_id", sessionId).neq("type", "feed.event")
    .order("seq").range(from, to));
}

/** The feed logs the team acted on (so a card can name the log and its host), without the whole feed. */
export async function loadReferencedFeed(admin: SupabaseClient, sessionId: string, teamEvents: Ev[]): Promise<Ev[]> {
  const ids = [...new Set(teamEvents.map(e => (e.payload as { event_id?: unknown } | null)?.event_id).filter((x): x is string => typeof x === "string" && !!x))].slice(0, 200);
  if (!ids.length) return [];
  const { data } = await admin.from("session_events").select("seq, type, actor_id, role, payload, occurred_at")
    .eq("session_id", sessionId).eq("type", "feed.event").in("payload->>id", ids);
  return (data as Ev[] | null) ?? [];
}

export interface DecisionInject { id: string; fired_seq: number | null; body: Record<string, unknown>; expected_action: CardAnswerKey }
export interface QuestionInject { id: string; fired_seq: number | null; body: Record<string, unknown>; expected_action: QuestionKey }
export async function loadQuestionInjects(admin: SupabaseClient, sessionId: string): Promise<QuestionInject[]> {
  const { data } = await admin.from("session_injects").select("id, fired_seq, body, expected_action")
    .eq("session_id", sessionId).eq("channel", "inject").eq("status", "fired").eq("body->>kind", "question").order("fired_seq");
  return (data as QuestionInject[] | null) ?? [];
}
export async function loadDecisionInjects(admin: SupabaseClient, sessionId: string): Promise<DecisionInject[]> {
  const { data } = await admin.from("session_injects").select("id, fired_seq, body, expected_action")
    .eq("session_id", sessionId).eq("channel", "inject").eq("status", "fired").eq("body->>kind", "decision").order("fired_seq");
  return (data as DecisionInject[] | null) ?? [];
}

/** The company's critical hosts (domain controller, primary file server). */
export function criticalHostsOf(companyId: string): string[] {
  const a = COMPANY_ASSETS[companyId];
  return a ? [a.dc, a.fileServer].filter(Boolean) : [];
}
