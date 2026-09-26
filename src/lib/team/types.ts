export interface RosterMember { user_id: string; role: string; status: string; name: string; handle: string | null }
// schema_version ≥ 2: server-side lifecycle/presence, answer key off the wire (migration 0071).
export interface SessionMeta { id: string; company_id: string; difficulty: string; status: string; org_id: string; schema_version?: number }
export interface Me { id: string; is_staff: boolean; role: string | null }
export interface Ev { seq: number; type: string; actor_id: string | null; role: string | null; payload: Record<string, unknown>; occurred_at?: string }
export type Ioc = { type: string; value: string; source: "picked" | "manual" };

// Shared working-scope shape (T2 sets, T3 confirms) — G-10.
export type ScopeState = { hosts: string[]; users: string[]; techniques: string[]; confirmed: boolean; by: string | null } | null;
