/**
 * Hand-offs: what one analyst passes to the next (owner, 2026-11-08: "every escalation or case that
 * is opened must open with the full detail of what the analyst reported").
 *
 * Every place a hand-off lands (the Tier-2 escalation card, the case view, the Manager's
 * escalations, the Tier-3 elevation, containment and isolation approvals, the Sentinel incident)
 * builds one `Handoff` from the event that carried it, and renders it with the one shared
 * renderer (`HandoffDetail`), so the same fields show in the same order everywhere.
 *
 * Built only from what players wrote and attached, plus the log they escalated as they saw it in
 * the feed. Never the answer key: no expected verdict, no attack truth (the TEAM_ANSWER_FIELDS of a
 * feed payload are never read here).
 */
import type { Ev } from "./types";
import { asStr } from "./format";
import { withRebasedTime } from "@/lib/sim/rebaseTime";
import { escalationStates, scopeByIncident, type ContainmentRequest } from "./projections";
import type { IsolationRequest } from "./isolationApproval";

export type HandoffKind = "escalation" | "self_opened" | "elevation" | "containment" | "isolation" | "report";

/** One log that travels with a hand-off, reduced to the fields a receiver reads first. */
export interface HandoffLog {
  /** What the log is ("Encoded PowerShell on WS-FIN-2847"). */
  label: string;
  /** Feed position, when known. */
  seq?: number;
  /** Who attached it, for a log added to the case later. */
  addedBy?: string;
  /** Key fields, label to value, in display order. Empty values are left out. */
  fields: [string, string][];
  /** The raw record, as text, capped. Absent when the caller asked for no raw. */
  raw?: string;
}

/** Something that happened to the hand-off after it was sent: a bounce, a comment, a log added. */
export interface HandoffNote { label: string; by: string; at: string | null; text: string }

export interface Handoff {
  kind: HandoffKind;
  /** The sender's own one-line summary, in full. */
  summary: string;
  /** Who sent it (display name) and their seat. */
  from: string;
  fromRole: string;
  at: string | null;
  /** The sender's call on it (Tier-1 disposition, Tier-2 verdict): what a player chose, never the key. */
  verdict?: string;
  severity?: string;
  /** What the sender asks the receiver to do. */
  action?: string;
  confidence?: string;
  /** The sender's reasoning, always shown first. */
  reasoningLabel: string;
  reasoning: string;
  /** Further written sections (assessment, findings, recommendation...), in order. */
  sections: [string, string][];
  iocs: { type: string; value: string }[];
  /** Affected host, user, entity, target. */
  affected: [string, string][];
  /** Request parameters (containment type, criticality, blast radius, incident, case...). */
  params: [string, string][];
  logs: HandoffLog[];
  /** The images payload as sent (rendered with imagesOf by the UI). */
  images?: unknown;
  notes: HandoffNote[];
  /** Hand-offs this one builds on: the original escalation, the Tier-2 report. */
  related: Handoff[];
}

export type NameOf = (userId: string | null) => string;

const ROLE: Record<string, string> = {
  t1: "Tier-1", t2: "Tier-2", t3: "Tier-3", lead: "Incident Lead", mgr: "SOC Manager", de: "Detection Engineer", ti: "Threat Intel", instructor: "Exercise admin",
};
export const roleLabel = (r: string | null | undefined) => (r ? ROLE[r] ?? r : "analyst");

const VERDICT: Record<string, string> = {
  true_positive: "true positive", suspicious: "suspicious", benign: "benign", false_positive: "false positive", escalate: "escalate",
};
export const verdictLabel = (v: unknown) => VERDICT[asStr(v)] ?? asStr(v).replace(/_/g, " ");

export const KIND_LABEL: Record<HandoffKind, string> = {
  escalation: "Escalation", self_opened: "Case opened", elevation: "Elevation to Tier-3", containment: "Containment request", isolation: "Isolation request", report: "Tier-2 report",
};

const eidOf = (e: Ev) => String((e.payload as { event_id?: unknown } | null)?.event_id ?? "");
const defaultName: NameOf = () => "Analyst";
const s = (v: unknown) => asStr(v).trim();
const pairs = (rows: [string, string][]) => rows.filter(([, v]) => !!v);

/** A raw block as text, capped so a payload stays small. */
function rawText(raw: unknown, cap = 4000): string {
  if (raw == null || raw === "") return "";
  const t = typeof raw === "string" ? raw : JSON.stringify(raw, null, 2);
  return t.length > cap ? `${t.slice(0, cap)}…` : t;
}

/**
 * The log as the feed showed it: re-timed to when the row was released in this session (raw
 * timestamps moved by the same delta, as the feed does), so the hand-off's "Time" is the time the
 * feed showed, not the time authored in the template (2026-11-08 review: a January process time).
 */
export function asReleased(snap: Record<string, unknown> | null | undefined, releasedAt: string | null | undefined): Record<string, unknown> | null {
  if (!snap || typeof snap !== "object") return null;
  const at = s(releasedAt);
  if (!at || !Number.isFinite(Date.parse(at))) return snap;
  const ts = typeof snap.ts === "string" && Number.isFinite(Date.parse(snap.ts)) ? snap.ts : undefined;
  const raw = snap.raw && typeof snap.raw === "object" && !Array.isArray(snap.raw) ? snap.raw as Record<string, unknown> : undefined;
  const moved = withRebasedTime({ ts, raw }, at);
  return { ...snap, ts: moved.ts, ...(raw ? { raw: moved.raw } : {}) };
}

/** "2026-11-08 10:46:48 UTC" for an instant; any other text as it came. */
function utcStamp(ts: string): string {
  // A stamp with no zone is UTC, as the engine writes it (rebaseTime.ts).
  const ms = Date.parse(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?$/.test(ts) ? `${ts}Z` : ts);
  if (!ts || !Number.isFinite(ms)) return ts.replace("T", " ").slice(0, 19);
  return `${new Date(ms).toISOString().replace("T", " ").slice(0, 19)} UTC`;
}

/** The key fields of a log, from the feed payload (or the snapshot that travelled with a hand-off). */
export function handoffLog(snap: Record<string, unknown> | null | undefined, opts: { raw?: boolean; seq?: number; addedBy?: string } = {}): HandoffLog | null {
  if (!snap || typeof snap !== "object") return null;
  const user = snap.user as { email?: unknown; full_name?: unknown } | undefined;
  const proc = (snap.process ?? {}) as { name?: unknown; cmdline?: unknown };
  const file = (snap.file ?? {}) as { path?: unknown; name?: unknown; sha256?: unknown };
  const net = (snap.network ?? {}) as { domain?: unknown; url?: unknown };
  const dns = (snap.dns ?? {}) as { query?: unknown };
  const label = s(snap.description) || s(snap.event_type) || "log";
  const fields = pairs([
    ["Event", s(snap.description)],
    ["Type", s(snap.event_type)],
    ["Source", [s(snap.vendor), s(snap.source)].filter(Boolean).join(" · ")],
    // The instant the feed showed, with its zone (R4): the ISO clock digits are UTC, the feed's time
    // column is the viewer's local clock, so an unlabelled "10:46:48" read as two hours off the feed.
    ["Time", utcStamp(s(snap.ts))],
    ["Severity", s(snap.severity)],
    ["Host", s(snap.hostname)],
    ["User", s(snap.user_email) || s(user?.email) || s(user?.full_name)],
    ["Source IP", s(snap.src_ip)],
    ["Destination IP", s(snap.dst_ip)],
    ["Process", s(proc.name)],
    ["Command line", s(proc.cmdline)],
    ["File", s(file.path) || s(file.name)],
    ["SHA256", s(file.sha256)],
    ["Domain", s(net.domain) || s(dns.query)],
    ["URL", s(net.url)],
  ]);
  const raw = opts.raw === false ? "" : rawText(snap.raw);
  return { label, ...(opts.seq != null ? { seq: opts.seq } : {}), ...(opts.addedBy ? { addedBy: opts.addedBy } : {}), fields, ...(raw ? { raw } : {}) };
}

/**
 * The log that travels with an escalation: the full feed payload, with an oversized raw block
 * trimmed (the server caps an action at 16 KiB; the shared feed still has the whole log).
 */
export function escalationSnapshot(full: Record<string, unknown> | undefined): Record<string, unknown> | undefined {
  if (!full || JSON.stringify(full).length <= 8000) return full;
  const rawT = JSON.stringify(full.raw ?? "");
  const snap: Record<string, unknown> = { ...full, raw: rawT.length > 4000 ? `${rawT.slice(0, 4000)}…` : full.raw, snapshot_truncated: true };
  // Still too big (a huge description or nested block): keep the fields a receiver reads.
  if (JSON.stringify(snap).length > 10000) {
    const keep = ["id", "ts", "source", "vendor", "event_type", "severity", "hostname", "user_email", "user", "src_ip", "dst_ip", "process", "file", "network", "dns"];
    const out: Record<string, unknown> = { snapshot_truncated: true, raw: typeof snap.raw === "string" ? snap.raw : rawT.slice(0, 4000) };
    for (const k of keep) if (full[k] !== undefined) out[k] = full[k];
    out.description = s(full.description).slice(0, 1000);
    return out;
  }
  return snap;
}

function iocsOf(v: unknown): { type: string; value: string }[] {
  if (!Array.isArray(v)) return [];
  const out: { type: string; value: string }[] = [];
  for (const x of v) {
    const value = s((x as { value?: unknown })?.value);
    if (value && !out.some(o => o.value.toLowerCase() === value.toLowerCase())) out.push({ type: s((x as { type?: unknown }).type), value });
  }
  return out;
}

function feedIndex(events: Ev[]): Map<string, Ev> {
  const m = new Map<string, Ev>();
  for (const e of events) if (e.type === "feed.event") m.set(String((e.payload as { id?: unknown }).id ?? e.seq), e);
  return m;
}

export interface HandoffOptions { nameOf?: NameOf; raw?: boolean; related?: boolean }

/** A Tier-1 escalation (or a case a Tier-2 / Tier-3 opened): the escalation.requested event. */
export function escalationHandoff(req: Ev, events: Ev[], opts: HandoffOptions = {}): Handoff {
  const nameOf = opts.nameOf ?? defaultName;
  const p = (req.payload ?? {}) as Record<string, unknown>;
  const eid = eidOf(req);
  const snap = (p.snapshot && typeof p.snapshot === "object" ? p.snapshot : null) as Record<string, unknown> | null;
  const feed = feedIndex(events);
  const feedRow = feed.get(eid);
  const fromFeed = feedRow?.payload as Record<string, unknown> | undefined;
  // Timed as the feed showed the row: its release in this session, else the time sent with the request.
  const logPayload = asReleased(snap ?? fromFeed ?? null, feedRow?.occurred_at || s(p.log_time));
  const user = logPayload?.user as { email?: unknown } | undefined;
  // The sender's disposition: carried on the request since 2026-11-08, else their latest call before sending.
  let verdict = s(p.disposition);
  if (!verdict) {
    for (const e of events) {
      if (e.seq >= req.seq) break;
      if (e.type === "disposition.set" && eidOf(e) === eid) verdict = s((e.payload as { verdict?: unknown }).verdict);
    }
  }
  // Confidence shows only when the analyst set it (confidence_set): the escalation form has no
  // confidence picker, and a number it sent was its own default, not the analyst's call.
  const conf = p.confidence_set === true && typeof p.confidence === "number" ? `${Math.round((p.confidence as number) * 100)}%` : "";
  const host = s(p.hostname) || s(logPayload?.hostname);
  const userName = s(p.user_email) || s(logPayload?.user_email) || s(user?.email);
  const entity = s(p.entity);
  const sections = pairs([
    ["Assessment", s(p.assessment)],
    ["Isolation", p.recommend_isolation === true && host ? `Recommends isolating ${host}. The senior analyst decides.` : ""],
  ]);
  const logs: HandoffLog[] = [];
  const main = handoffLog(logPayload, { raw: opts.raw, seq: feedRow?.seq });
  if (main) logs.push(main);
  const notes: HandoffNote[] = [];
  const seenAdded = new Set<string>();
  // Earlier rounds of the same log (re-escalated after a bounce or a resolve).
  for (const e of events) {
    if (e.type !== "escalation.requested" || e.seq >= req.seq || eidOf(e) !== eid) continue;
    notes.push({ label: "Earlier escalation", by: nameOf(e.actor_id), at: e.occurred_at ?? null, text: s((e.payload as { summary?: unknown }).summary) || s((e.payload as { what?: unknown }).what) });
  }
  for (const e of events) {
    if (e.type === "escalation.bounced" && eidOf(e) === eid) {
      notes.push({ label: "Bounced back", by: nameOf(e.actor_id), at: e.occurred_at ?? null, text: s((e.payload as { reason?: unknown }).reason) });
    } else if (e.type === "evidence.pinned") {
      const ep = (e.payload ?? {}) as { case_event_id?: unknown; label?: unknown; summary?: unknown };
      const caseEid = s(ep.case_event_id);
      const logEid = eidOf(e);
      if (caseEid === eid && logEid && logEid !== eid && !seenAdded.has(logEid)) {
        // A log added to this case from the queue: it travels with the case, fields and all.
        seenAdded.add(logEid);
        const f = feed.get(logEid);
        const added = handoffLog(asReleased(f?.payload as Record<string, unknown> | undefined, f?.occurred_at), { raw: opts.raw, seq: f?.seq, addedBy: nameOf(e.actor_id) });
        if (added) logs.push(added);
        else notes.push({ label: "Log added to the case", by: nameOf(e.actor_id), at: e.occurred_at ?? null, text: s(ep.label) || s(ep.summary) || logEid });
      } else if (!caseEid && logEid === eid && e.seq > req.seq) {
        notes.push({ label: "Evidence pinned", by: nameOf(e.actor_id), at: e.occurred_at ?? null, text: s(ep.label) || s(ep.summary) });
      }
    } else if (e.type === "note.added" && eidOf(e) === eid) {
      notes.push({ label: "Comment", by: nameOf(e.actor_id), at: e.occurred_at ?? null, text: s((e.payload as { text?: unknown }).text) });
    }
  }
  return {
    kind: p.opened_by ? "self_opened" : "escalation",
    summary: s(p.summary) || s(p.what) || "Escalated alert",
    from: nameOf(req.actor_id), fromRole: roleLabel(req.role ?? (s(p.opened_by) || "t1")), at: req.occurred_at ?? null,
    verdict: verdict ? verdictLabel(verdict) : undefined,
    severity: s(p.severity) || undefined,
    action: s(p.requested_action).replace(/[-_]/g, " ") || undefined,
    confidence: p.low_confidence ? "low: a lead sent for a second look" : conf || undefined,
    reasoningLabel: "Observations", reasoning: s(p.observations) || s(p.why),
    sections,
    iocs: iocsOf(p.iocs),
    affected: pairs([["Host", host], ["User", userName], ["Entity", entity && entity !== host && entity !== userName && entity !== "the affected asset" ? entity : ""]]),
    params: [],
    logs, images: p.images, notes: notes.filter(n => n.text), related: [],
  };
}

/** The latest request of a case (one escalated log), when it is in view. */
function caseRequest(eid: string, events: Ev[]): Ev | null {
  if (!eid) return null;
  return escalationStates(events).get(eid)?.request ?? null;
}

function latestReport(eid: string, events: Ev[]): Ev | null {
  let r: Ev | null = null;
  for (const e of events) if (e.type === "report.submitted" && eidOf(e) === eid) r = e;
  return r;
}

/** A Tier-2 / Tier-3 incident report (report.submitted). */
export function reportHandoff(ev: Ev, events: Ev[], opts: HandoffOptions = {}): Handoff {
  const nameOf = opts.nameOf ?? defaultName;
  const p = (ev.payload ?? {}) as Record<string, unknown>;
  const inc = s(p.incident);
  const scopes = scopeByIncident(events);
  const sc = (inc ? scopes.get(inc) : undefined) ?? scopes.get("") ?? null;
  return {
    kind: "report", summary: s(p.summary) || "Incident report",
    from: nameOf(ev.actor_id), fromRole: roleLabel(ev.role), at: ev.occurred_at ?? null,
    verdict: s(p.verdict) ? verdictLabel(p.verdict) : undefined,
    reasoningLabel: "Findings", reasoning: s(p.findings),
    sections: pairs([["Recommendation", s(p.recommendation)]]),
    iocs: iocsOf(p.iocs), affected: [],
    params: pairs([
      ["Incident", inc],
      ["Scope", sc ? [sc.hosts.length ? `hosts ${sc.hosts.join(", ")}` : "", sc.users.length ? `users ${sc.users.join(", ")}` : "", sc.techniques.length ? `techniques ${sc.techniques.join(", ")}` : ""].filter(Boolean).join("; ") + (sc.confirmed ? " (confirmed by Tier-3)" : "") : ""],
    ]),
    logs: [], notes: [], related: [],
  };
}

/** The case behind a request, and its Tier-2 report, as related hand-offs. */
function caseRelated(eid: string, events: Ev[], opts: HandoffOptions): Handoff[] {
  if (opts.related === false) return [];
  const out: Handoff[] = [];
  const req = caseRequest(eid, events);
  if (req) out.push(escalationHandoff(req, events, { ...opts, related: false }));
  const rep = latestReport(eid, events);
  if (rep) out.push(reportHandoff(rep, events, opts));
  return out;
}

/** A Tier-2 to Tier-3 elevation (elevation.requested). */
export function elevationHandoff(ev: Ev, events: Ev[], opts: HandoffOptions = {}): Handoff {
  const nameOf = opts.nameOf ?? defaultName;
  const p = (ev.payload ?? {}) as Record<string, unknown>;
  const eid = eidOf(ev);
  const rawSnap = (p.snapshot && typeof p.snapshot === "object" ? p.snapshot : null) as Record<string, unknown> | null;
  const snap = asReleased(rawSnap, feedIndex(events).get(eid)?.occurred_at || s(p.log_time));
  const log = handoffLog(snap, { raw: opts.raw });
  const host = s(p.hostname) || s(snap?.hostname);
  const entity = s(p.entity);
  const origin = opts.related === false ? null : caseRequest(eid, events);
  return {
    kind: "elevation", summary: s(p.summary) || s(p.question) || s(p.reason) || "Elevated case",
    from: nameOf(ev.actor_id), fromRole: roleLabel(ev.role ?? "t2"), at: ev.occurred_at ?? null,
    verdict: s(p.t2_verdict) ? verdictLabel(p.t2_verdict) : undefined,
    severity: s(p.severity) || undefined,
    action: "hunt",
    reasoningLabel: "What to hunt", reasoning: s(p.hunt_ask) || s(p.question) || s(p.reason),
    sections: pairs([["Tier-2 findings", s(p.t2_findings)], ["Tier-2 recommendation", s(p.t2_recommendation)]]),
    iocs: iocsOf(p.iocs),
    affected: pairs([["Host", host], ["Entity", entity && entity !== host && entity !== "the affected asset" ? entity : ""]]),
    params: [],
    logs: log ? [log] : [], notes: [],
    related: origin ? [escalationHandoff(origin, events, { ...opts, related: false })] : [],
  };
}

const CONTAIN_VERB: Record<string, string> = { isolate_host: "Isolate host", disable_account: "Disable account", block_indicator: "Block indicator" };
const CRIT: Record<string, string> = { crown_jewel: "crown-jewel (domain controller / core system)", standard: "standard", low: "low (spare / test)" };

/** A containment request (containment.requested) with its case. */
export function containmentHandoff(c: ContainmentRequest, events: Ev[], opts: HandoffOptions = {}): Handoff {
  const nameOf = opts.nameOf ?? defaultName;
  const p = (c.request.payload ?? {}) as Record<string, unknown>;
  const type = s(p.containment_type) || "isolate_host";
  const target = s(p.target);
  const notes: HandoffNote[] = [];
  for (const e of events) {
    if (e.type !== "containment.advised" || Number((e.payload as { request_seq?: unknown }).request_seq) !== c.seq) continue;
    const ap = e.payload as { stance?: unknown; reason?: unknown };
    notes.push({ label: ap.stance === "object" ? "Objects" : "Supports", by: nameOf(e.actor_id), at: e.occurred_at ?? null, text: s(ap.reason) || (ap.stance === "object" ? "objects" : "supports") });
  }
  if (c.status === "denied" || c.status === "approved" || c.status === "executed") {
    notes.push({ label: c.status === "denied" ? "Denied" : "Approved", by: nameOf(c.decidedBy), at: null, text: c.decisionReason || (c.status === "denied" ? "denied" : "approved") });
  }
  return {
    kind: "containment", summary: `${CONTAIN_VERB[type] ?? type.replace(/_/g, " ")}: ${target || "target not named"}`,
    from: nameOf(c.request.actor_id), fromRole: roleLabel(c.request.role), at: c.request.occurred_at ?? null,
    action: (CONTAIN_VERB[type] ?? type).toLowerCase(),
    reasoningLabel: "Why", reasoning: s(p.reason),
    sections: [],
    iocs: [],
    affected: pairs([["Target", target]]),
    params: pairs([
      ["Asset criticality", CRIT[s(p.asset_criticality)] ?? s(p.asset_criticality)],
      ["What breaks if contained", s(p.blast_radius)],
      ["Business owner", s(p.business_owner)],
      ["Incident", s(p.incident)],
    ]),
    logs: [], notes: notes.filter(n => n.text), related: caseRelated(c.eid, events, opts),
  };
}

/** The case an isolation request is about: its `case`, else the latest escalation on that host. */
export function isolationCaseEid(r: IsolationRequest, events: Ev[], caseId?: string | null): string {
  const named = s(caseId);
  if (named && events.some(e => e.type === "escalation.requested" && eidOf(e) === named)) return named;
  const host = r.host.toLowerCase().split(".")[0];
  let best = "";
  for (const e of events) {
    if (e.type !== "escalation.requested") continue;
    const p = (e.payload ?? {}) as { hostname?: unknown; snapshot?: { hostname?: unknown } };
    const h = (s(p.hostname) || s(p.snapshot?.hostname)).toLowerCase().split(".")[0];
    if (h && h === host) best = eidOf(e);
  }
  return best;
}

/** An isolation request (isolation.requested), with the case it comes from. */
export function isolationHandoff(r: IsolationRequest, events: Ev[], opts: HandoffOptions = {}): Handoff {
  const nameOf = opts.nameOf ?? defaultName;
  const reqEv = events.find(e => e.seq === r.seq);
  const caseId = s((reqEv?.payload as { case?: unknown } | undefined)?.case);
  const eid = isolationCaseEid(r, events, caseId);
  const caseReq = eid ? caseRequest(eid, events) : null;
  const caseSummary = caseReq ? s((caseReq.payload as { summary?: unknown }).summary) || s((caseReq.payload as { what?: unknown }).what) : "";
  const notes: HandoffNote[] = [];
  if (r.state === "denied") notes.push({ label: "Denied", by: nameOf(r.answeredBy), at: r.answeredAt, text: r.denyReason || "denied" });
  if (r.state === "approved") notes.push({ label: "Approved", by: nameOf(r.answeredBy), at: r.answeredAt, text: "host isolated" });
  return {
    kind: "isolation", summary: `Isolate ${r.host}`,
    from: nameOf(r.requestedBy), fromRole: roleLabel(r.requesterRole), at: r.at,
    action: "isolate host",
    reasoningLabel: "Reason", reasoning: r.reason,
    sections: [], iocs: [],
    affected: pairs([["Host", r.host]]),
    params: pairs([["Incident", s(r.incident)], ["Case", caseSummary || caseId]]),
    logs: [], notes, related: eid ? caseRelated(eid, events, opts) : [],
  };
}

const when = (iso: string | null) => (iso ? iso.replace("T", " ").slice(0, 16) : "");

/** The hand-off as plain text (a Sentinel incident's description and first comment). */
export function handoffText(h: Handoff): string {
  const lines: string[] = [];
  lines.push(`${KIND_LABEL[h.kind]} ${h.kind === "self_opened" ? "by" : "from"} ${h.from} (${h.fromRole})${h.at ? ` at ${when(h.at)} UTC` : ""}`);
  lines.push(`Summary: ${h.summary}`);
  const calls = [h.verdict && `Verdict: ${h.verdict}`, h.severity && `Severity: ${h.severity}`, h.action && `Requested action: ${h.action}`, h.confidence && `Confidence: ${h.confidence}`].filter(Boolean);
  if (calls.length) lines.push(calls.join(" | "));
  if (h.reasoning) lines.push(`${h.reasoningLabel}: ${h.reasoning}`);
  for (const [k, v] of h.sections) lines.push(`${k}: ${v}`);
  if (h.iocs.length) lines.push(`Indicators (${h.iocs.length}): ${h.iocs.map(i => (i.type ? `${i.type}: ${i.value}` : i.value)).join(", ")}`);
  for (const [k, v] of h.affected) lines.push(`${k}: ${v}`);
  for (const [k, v] of h.params) lines.push(`${k}: ${v}`);
  for (const l of h.logs) {
    const f = new Map(l.fields);
    const bits = [f.get("Host"), f.get("User"), f.get("Time")].filter(Boolean).join(", ");
    lines.push(`${l.addedBy ? `Log added by ${l.addedBy}` : "Log"}: ${l.label}${bits ? ` (${bits})` : ""}`);
  }
  for (const n of h.notes) lines.push(`${n.label} (${n.by}): ${n.text}`);
  return lines.join("\n");
}
