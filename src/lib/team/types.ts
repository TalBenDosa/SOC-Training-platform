// lapsed (staff view only): the member's access to the organisation expired — they can't act or mark ready.
export interface RosterMember { user_id: string; role: string; status: string; name: string; handle: string | null; lapsed?: boolean }
// schema_version ≥ 2: server-side lifecycle/presence, answer key off the wire (migration 0071).
// stack: the security products the session runs on — only the categories that differ from the company (QA L3).
export interface SessionMeta { id: string; company_id: string; difficulty: string; status: string; org_id: string; schema_version?: number; stack?: Record<string, string>;
  /** The organization the exercise runs as (its English name = domain); null on Live-SOC-company sessions. */
  tenant?: { name: string; domain: string; netbios: string; brand: string } | null;
  env?: { platforms: string[]; industry: string } | null }
export interface Me { id: string; is_staff: boolean; role: string | null }
export interface Ev { seq: number; type: string; actor_id: string | null; role: string | null; payload: Record<string, unknown>; occurred_at?: string }
export type Ioc = { type: string; value: string; source: "picked" | "manual" };

// Shared working-scope shape (T2 sets, T3 confirms) — G-10.
export type ScopeState = { hosts: string[]; users: string[]; techniques: string[]; confirmed: boolean; by: string | null } | null;
