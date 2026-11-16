/**
 * Tier-3 case work (team training): the scope register, sweeps, the containment-readiness
 * verdict, and the "phase / next step" the Tier-3 status bar shows.
 *
 * PURE and client-safe: everything is derived from the session events the player can see.
 * The register is shared by every Tier-3 in the session (one technical truth per shift).
 * Spec: research/t3-manager/T3-INTERFACE-SPEC.md (stages A and B).
 *
 * Events (migration 0112, Tier-3 only, running):
 *   t3.scan          { indicator, kind, hosts: [{host, count, first_ms, last_ms}], rows }
 *   t3.scope.entity  { entity, entity_kind: "host"|"account", state, confidence?, reason?, cites?: number[] }
 *   t3.readiness     { verdict: "ready"|"not_ready"|"unknown", blockers: string[], reason }
 * A Tier-3 host_status finding (forensic.finding) also moves a host: compromised => confirmed,
 * not_compromised => cleared, so the evidence the analyst already wrote counts as a citation.
 */
import type { Ev } from "./types";
import { asStr, hostKey } from "./format";

export type EntityKind = "host" | "account";
export type EntityState = "suspected" | "confirmed" | "cleared" | "cannot_check";
export type Confidence = "low" | "moderate" | "high";
export type IndicatorKind = "ip" | "hash" | "domain" | "process" | "account" | "text";
export type Verdict = "ready" | "not_ready" | "unknown";

export const STATE_LABEL: Record<EntityState, string> = {
  suspected: "Suspected", confirmed: "Confirmed", cleared: "Cleared", cannot_check: "Cannot check",
};

export interface RegisterEntry {
  key: string;              // hostKey / lowercased account
  entity: string;           // as first written
  kind: EntityKind;
  state: EntityState;
  confidence: Confidence | null;
  reason: string;
  /** Seqs of the scans and findings that back the current state. */
  cites: number[];
  by: string | null;
  seq: number;              // last change
  atMs: number | null;
  /** Where the latest state came from. */
  source: "register" | "finding";
}

export interface ScanHit { host: string; count: number; first_ms: number | null; last_ms: number | null }
export interface ScanRecord { seq: number; by: string | null; atMs: number | null; indicator: string; kind: IndicatorKind; hosts: ScanHit[]; rows: number }

const msOf = (e: Ev) => (e.occurred_at ? Date.parse(e.occurred_at) : NaN);
const num = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? v : typeof v === "string" && /^\d+$/.test(v) ? Number(v) : null);
const isState = (v: unknown): v is EntityState => v === "suspected" || v === "confirmed" || v === "cleared" || v === "cannot_check";
const isConf = (v: unknown): v is Confidence => v === "low" || v === "moderate" || v === "high";
export const entityKey = (entity: string, kind: EntityKind) => (kind === "host" ? hostKey(entity) : entity.trim().toLowerCase());

// ── indicators and sweeps ───────────────────────────────────────────────────

/** Recognise what an indicator is, so the sweep and the report can name it. */
export function indicatorKind(raw: string): IndicatorKind {
  const s = raw.trim();
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s) || /^[0-9a-f:]{6,}$/i.test(s) && s.includes(":")) return "ip";
  if (/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(s)) return "hash";
  if (/\.(exe|dll|ps1|bat|cmd|vbs|js|hta|scr|msi|lnk)$/i.test(s)) return "process";
  if (/@/.test(s) || /\\/.test(s)) return "account";
  if (/^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(s)) return "domain";
  return "text";
}

/**
 * Sweep the feed the team can see for one indicator: every host whose logs mention it, with how
 * often and when. Matching is a case-insensitive substring over the log's public fields, the
 * same text an analyst would search in the SIEM. At least 3 characters.
 */
export function sweepFeed(feed: Ev[], indicator: string): { hosts: ScanHit[]; rows: number } {
  const q = indicator.trim().toLowerCase();
  if (q.length < 3) return { hosts: [], rows: 0 };
  const byHost = new Map<string, ScanHit>();
  let rows = 0;
  for (const fe of feed) {
    const p = (fe.payload ?? {}) as Record<string, unknown>;
    let text: string;
    try { text = JSON.stringify(p).toLowerCase(); } catch { continue; }
    if (!text.includes(q)) continue;
    rows++;
    const host = asStr(p.hostname).trim();
    if (!host) continue;
    const k = hostKey(host);
    const t = msOf(fe);
    const cur = byHost.get(k) ?? { host, count: 0, first_ms: null, last_ms: null };
    cur.count++;
    if (Number.isFinite(t)) {
      cur.first_ms = cur.first_ms == null ? t : Math.min(cur.first_ms, t);
      cur.last_ms = cur.last_ms == null ? t : Math.max(cur.last_ms, t);
    }
    byHost.set(k, cur);
  }
  return { hosts: [...byHost.values()].sort((a, b) => b.count - a.count || a.host.localeCompare(b.host)), rows };
}

export function scansOf(events: Ev[]): ScanRecord[] {
  return events.filter(e => e.type === "t3.scan").map(e => {
    const p = (e.payload ?? {}) as Record<string, unknown>;
    const hosts = (Array.isArray(p.hosts) ? p.hosts : []).map(h => {
      const o = (h ?? {}) as Record<string, unknown>;
      return { host: asStr(o.host), count: num(o.count) ?? 0, first_ms: num(o.first_ms), last_ms: num(o.last_ms) };
    }).filter(h => h.host);
    const ind = asStr(p.indicator);
    return { seq: e.seq, by: e.actor_id, atMs: Number.isFinite(msOf(e)) ? msOf(e) : null, indicator: ind, kind: (asStr(p.kind) || indicatorKind(ind)) as IndicatorKind, hosts, rows: num(p.rows) ?? 0 };
  });
}

// ── the register ────────────────────────────────────────────────────────────

/** The shared scope register: the latest state of every host and account, in first-seen order. */
export function buildRegister(events: Ev[]): RegisterEntry[] {
  const out = new Map<string, RegisterEntry>();
  for (const e of events) {
    const p = (e.payload ?? {}) as Record<string, unknown>;
    const at = Number.isFinite(msOf(e)) ? msOf(e) : null;
    if (e.type === "t3.scope.entity") {
      const entity = asStr(p.entity).trim();
      const kind: EntityKind = p.entity_kind === "account" ? "account" : "host";
      if (!entity) continue;
      const key = entityKey(entity, kind);
      if (p.state === "removed") { out.delete(key); continue; }
      if (!isState(p.state)) continue;
      const prev = out.get(key);
      const cites = (Array.isArray(p.cites) ? p.cites : []).map(num).filter((x): x is number => x != null);
      out.set(key, {
        key, entity: prev?.entity ?? entity, kind, state: p.state,
        confidence: isConf(p.confidence) ? p.confidence : null, reason: asStr(p.reason).slice(0, 400),
        cites, by: e.actor_id, seq: e.seq, atMs: at, source: "register",
      });
    } else if (e.type === "forensic.finding" && p.kind === "host_status") {
      const host = asStr(p.host).trim();
      if (!host) continue;
      const state: EntityState | null = p.status === "compromised" ? "confirmed" : p.status === "not_compromised" ? "cleared" : null;
      if (!state) continue;
      const key = entityKey(host, "host");
      const prev = out.get(key);
      out.set(key, {
        key, entity: prev?.entity ?? host, kind: "host", state,
        confidence: isConf(p.confidence) ? p.confidence : null, reason: asStr(p.summary).slice(0, 400),
        cites: [e.seq], by: e.actor_id, seq: e.seq, atMs: at, source: "finding",
      });
    }
  }
  return [...out.values()];
}

/** Why a state change cannot be saved yet (empty = allowed). Confirming and clearing need evidence. */
export function stateChangeProblem(next: EntityState, cites: number[], reason: string): string | null {
  const r = reason.trim();
  if (next === "confirmed" && !cites.length) return "Confirming needs evidence: cite a finding or a sweep that shows the host.";
  if (next === "cleared" && !cites.length && r.length < 10) return "Clearing needs evidence: cite a finding, or say why in at least 10 characters (e.g. the change ticket).";
  if (next === "cannot_check" && r.length < 5) return "Say why it cannot be checked (e.g. no EDR on this host).";
  return null;
}

// ── readiness, phase, next step ─────────────────────────────────────────────

export interface Blocker { id: string; text: string; severity: "block" | "warn"; entity?: string }

/**
 * What stands between the team and a safe containment, derived from the register:
 * suspected entities, hosts in scope with no memory capture, no sweep at all yet,
 * and (as a warning) hosts nobody can check.
 */
export function readinessBlockers(events: Ev[], register = buildRegister(events), scans = scansOf(events)): Blocker[] {
  const out: Blocker[] = [];
  const collected = new Set(events.filter(e => e.type === "forensic.collected" && (e.payload as { kind?: unknown }).kind !== "triage")
    .map(e => hostKey(asStr((e.payload as { host?: unknown }).host))));
  for (const r of register) {
    if (r.state === "suspected") out.push({ id: `sus:${r.key}`, text: `${r.entity} is still suspected`, severity: "block", entity: r.entity });
    if (r.kind === "host" && r.state === "confirmed" && !collected.has(r.key)) out.push({ id: `mem:${r.key}`, text: `No memory capture from ${r.entity}`, severity: "block", entity: r.entity });
    if (r.state === "cannot_check") out.push({ id: `blind:${r.key}`, text: `${r.entity} cannot be checked: say so in the verdict`, severity: "warn", entity: r.entity });
  }
  if (register.some(r => r.state === "confirmed") && !scans.length) out.push({ id: "noscan", text: "No sweep yet: sweep an indicator from the confirmed host across all hosts", severity: "block" });
  if (!register.length) out.push({ id: "empty", text: "Nothing in scope yet", severity: "block" });
  return out;
}

export interface ReadinessRecord { seq: number; by: string | null; atMs: number | null; verdict: Verdict; blockers: string[]; reason: string }
export function readinessOf(events: Ev[]): ReadinessRecord[] {
  return events.filter(e => e.type === "t3.readiness").map(e => {
    const p = (e.payload ?? {}) as Record<string, unknown>;
    const v = p.verdict === "ready" || p.verdict === "not_ready" ? p.verdict : "unknown";
    return { seq: e.seq, by: e.actor_id, atMs: Number.isFinite(msOf(e)) ? msOf(e) : null, verdict: v, blockers: (Array.isArray(p.blockers) ? p.blockers : []).map(asStr).filter(Boolean), reason: asStr(p.reason) };
  });
}

export type Phase = "waiting" | "collecting" | "scoping" | "verdict" | "signed";
export const PHASE_LABEL: Record<Phase, string> = {
  waiting: "Waiting for a case", collecting: "Collecting evidence", scoping: "Scoping", verdict: "Ready to sign", signed: "Verdict signed",
};
export const PHASE_ORDER: Phase[] = ["collecting", "scoping", "verdict", "signed"];

export interface NextStep { phase: Phase; text: string; target: "inbox" | "case" | "evidence" | "readiness" | "report" | null; host?: string }

/**
 * The one thing the Tier-3 should do now. `pendingHandoffs` = hand-offs from Tier-2 not taken yet.
 * A verdict signed before the register last changed no longer counts: the case moved on.
 */
export function nextStep(events: Ev[], opts: { pendingHandoffs?: number } = {}): NextStep {
  const register = buildRegister(events);
  const scans = scansOf(events);
  const blockers = readinessBlockers(events, register, scans);
  const verdicts = readinessOf(events);
  const lastVerdict = verdicts[verdicts.length - 1];
  const lastChange = Math.max(0, ...register.map(r => r.seq), ...scans.map(s => s.seq));
  const signedFresh = !!lastVerdict && lastVerdict.seq > lastChange;
  if (!register.length) {
    if (opts.pendingHandoffs) return { phase: "waiting", text: `Take the hand-off waiting in your inbox (${opts.pendingHandoffs})`, target: "inbox" };
    return { phase: "waiting", text: "No case yet: answer your inbox, or sweep an indicator from the feed", target: "case" };
  }
  const mem = blockers.find(b => b.id.startsWith("mem:"));
  if (mem) return { phase: "collecting", text: `Collect memory on ${mem.entity} before anyone kills a process`, target: "evidence", host: mem.entity };
  if (blockers.some(b => b.id === "noscan")) return { phase: "scoping", text: "Sweep an indicator from the confirmed host across all hosts", target: "case" };
  const sus = register.filter(r => r.state === "suspected");
  if (sus.length) return { phase: "scoping", text: `Resolve ${sus.length} suspected ${sus.length === 1 ? "entity" : "entities"}: confirm with evidence or clear`, target: "case" };
  if (!signedFresh) return { phase: "verdict", text: "Sign containment readiness for the SOC Manager", target: "readiness" };
  return { phase: "signed", text: "Keep the manager updated: report what changed and what is still unknown", target: "report" };
}

/** The draft for the report to the SOC Manager, written from the register. */
export function reportDraft(events: Ev[]): { summary: string; ready: Verdict | null; why: string } {
  const register = buildRegister(events);
  const scans = scansOf(events);
  const conf = register.filter(r => r.state === "confirmed").map(r => r.entity);
  const sus = register.filter(r => r.state === "suspected").map(r => r.entity);
  const blind = register.filter(r => r.state === "cannot_check").map(r => r.entity);
  const cleared = register.filter(r => r.state === "cleared").map(r => r.entity);
  const parts: string[] = [];
  if (conf.length) parts.push(`Confirmed compromised: ${conf.join(", ")}.`);
  if (cleared.length) parts.push(`Cleared: ${cleared.join(", ")}.`);
  if (scans.length) parts.push(`Swept ${scans.length} indicator${scans.length === 1 ? "" : "s"} (${scans.slice(-3).map(s => s.indicator).join(", ")}).`);
  if (sus.length) parts.push(`Not yet known: ${sus.join(", ")} still suspected.`);
  if (blind.length) parts.push(`Cannot check: ${blind.join(", ")}.`);
  const last = readinessOf(events).pop();
  const blockers = readinessBlockers(events, register, scans).filter(b => b.severity === "block");
  return {
    summary: parts.join(" ").slice(0, 1500),
    ready: last ? last.verdict : null,
    why: last?.reason || (blockers.length ? blockers.map(b => b.text).join("; ").slice(0, 400) : ""),
  };
}

/** When the last report promised the next update (ms), or null. */
export function updateDueMs(events: Ev[], meId?: string | null): number | null {
  const reports = events.filter(e => e.type === "forensic.report" && (!meId || e.actor_id === meId));
  const last = reports[reports.length - 1];
  if (!last) return null;
  const at = msOf(last);
  const min = num((last.payload as { next_update_min?: unknown }).next_update_min);
  return Number.isFinite(at) && min ? at + min * 60_000 : null;
}
