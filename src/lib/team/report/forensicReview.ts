/**
 * Forensic review: Tier-3's forensic work graded against what really happened in the shift.
 *
 * Pure and deterministic (no LLM: research/t3-manager/T3-forensic-simulation-design.md §6).
 * computeReport() calls it with the REVEALED log (answers joined, served only after the shift
 * ended) plus the PUBLIC log the players saw. Every evidence item a Tier-3 analyst collected is
 * rebuilt from the public log exactly as the workbench showed it (same rows, same refs), so each
 * row a finding cites can be resolved to what it stands for (a process, a connection, an autorun
 * entry, a log) and checked against the truth.
 *
 * A finding is:
 *  - confirmed: right, and at least one cited row (from evidence taken before the finding) shows it;
 *  - guess:     right, but nothing cited shows it (counts half: a right call is not a proof);
 *  - wrong:     contradicts what happened;
 *  - ungraded:  free notes and honest "undetermined" host statuses.
 * Plus evidence preservation (memory captured before an attacker process was killed),
 * confidence calibration, and the reports to the SOC Manager (READY only when backed, the
 * promised next update delivered).
 */
import type { Ev, RosterMember } from "@/lib/team/types";
import type { TelemetryEvent } from "@/lib/sim/types";
import { hostKey } from "@/lib/team/format";
import { withRebasedTime } from "@/lib/sim/rebaseTime";
import { buildIocTruth, extractIocs, iocDigest, normalizeIoc } from "@/lib/edr/iocIntel";
import { buildEvidenceView, evidenceItems, forensicHosts, hostStateOf, type EvidenceItem, type EvidenceView, type FeedRow } from "@/lib/forensics/workbench";

export type FindingVerdict = "confirmed" | "guess" | "wrong" | "ungraded";
export interface FindingReview {
  seq: number; by: string | null; kind: string; host: string; status: string | null; summary: string;
  confidence: string; atS: number | null; cited: number; supportedBy: string | null; verdict: FindingVerdict; reason: string;
}
export interface ReportReview {
  seq: number; by: string | null; kind: string; readiness: string; atS: number | null;
  readinessCheck: "backed" | "premature" | "honest"; readinessNote: string; promiseKept: boolean | null;
}
export interface HostReview {
  host: string; attacked: boolean; attackLogs: number; evidence: number; firstEvidenceS: number | null;
  /** an attacker process on this host was killed through RTR: was memory captured first? */
  kill: { by: string | null; atS: number | null; preserved: boolean } | null;
  statusCalled: "compromised" | "not_compromised" | null; statusRight: boolean | null;
}
export interface UserForensics {
  evidence: number; findings: FindingReview[];
  graded: number; confirmed: number; guess: number; wrong: number; accPct: number | null; supportedPct: number | null;
  highTotal: number; highRight: number; calibrationPct: number | null;
  destructiveKills: number; preservedKills: number; preservationPct: number | null;
  reports: ReportReview[]; reportPoints: number | null;
}
export interface ForensicReview {
  perUser: Record<string, UserForensics>;
  hosts: HostReview[]; findings: FindingReview[]; reports: ReportReview[];
}
export interface ForensicReviewCtx {
  events: Ev[];                 // revealed log (answers joined)
  publicEvents?: Ev[] | null;   // what the players saw (views are rebuilt from it); falls back to `events`
  sessionId: string;
  attackIds: Set<string>;       // feed ids of attack logs
  roster: RosterMember[];
  endMs: number;
  relS: (t: number | null) => number | null;
}

const str = (v: unknown) => (typeof v === "string" ? v : typeof v === "number" ? String(v) : "");
const msOf = (e: Ev) => (e.occurred_at ? Date.parse(e.occurred_at) : NaN);
const pct = (n: number, d: number) => (d ? Math.round((n / d) * 100) : null);
const fidOf = (e: Ev) => str((e.payload as { id?: unknown }).id) || String(e.seq);
const isInternal = (ip: string) => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|0\.0\.0\.0)/.test(ip);
const PERSIST = /^T(1053|1547|1543|1546|1136|1098|1037|1574|1197|1505)/;
const LATERAL = /^T(1021|1570|1550|1563|1072|1210)/;
const EXFIL = /^T(1041|1048|1567|1020|1030|1537|1052)/;
const PERSIST_TYPES = /scheduled_task|service_install|registry_set|wmi|startup|autorun|persistence/i;
const EXFIL_TYPES = /exfil|upload|dlp|data_transfer|bulk_download/i;
const FILE_EXT = /\.(dll|exe|ps1|bat|cmd|iso|lnk|zip|rar|7z|txt|log|docx?|xlsx?|pptx?|pdf|js|vbs|hta|msi|tmp|dat|raw|csv|json|xml|evtx|pf|sys)$/i;

interface HostTruth {
  host: string; tp: TelemetryEvent[]; tpIds: Set<string>; pids: Set<number>; names: Set<string>;
  bad: Set<string>; text: string; persistence: boolean; lateral: boolean; exfil: boolean; firstMs: number | null; incident: string | null;
}

/** Indicators (IPs, domains) a finding names in its text. */
function indicatorsIn(text: string, hostNames: Set<string>): string[] {
  const out = new Set<string>();
  for (const m of text.matchAll(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g)) out.add(m[0]);
  for (const m of text.toLowerCase().matchAll(/\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.[a-z]{2,}\b/g)) {
    const d = m[0];
    if (FILE_EXT.test(d) || hostNames.has(hostKey(d)) || /^\d/.test(d.split(".").pop() ?? "")) continue;
    out.add(normalizeIoc("domain", d));
  }
  return [...out];
}

export function computeForensicReview(ctx: ForensicReviewCtx): ForensicReview | null {
  const { events, sessionId, attackIds, roster, endMs, relS } = ctx;
  const forensicTypes = new Set(["forensic.collected", "forensic.finding", "forensic.report"]);
  if (!events.some(e => forensicTypes.has(e.type))) return null;

  // ── truth (revealed feed) ──
  const feed = events.filter(e => e.type === "feed.event");
  const feedById = new Map(feed.map(e => [fidOf(e), e]));
  const iocTruth = buildIocTruth({ events: feed.map(e => {
    const p = e.payload as unknown as TelemetryEvent;
    return p.expected_verdict === ("benign" as TelemetryEvent["expected_verdict"]) ? { ...p, is_baseline: true } : p;
  }) });
  const isBad = (type: "ip" | "domain" | "hash", v: string) => { const t = iocTruth.entries[iocDigest(type, v)]; return !!t && (t.v === "malicious" || t.v === "suspicious"); };
  const globalBad = new Set<string>();
  for (const e of feed) {
    if (!attackIds.has(fidOf(e))) continue;
    for (const i of extractIocs(e.payload as unknown as TelemetryEvent)) if (i.type !== "hash" && isBad(i.type, i.value) && !(i.type === "ip" && isInternal(i.value))) globalBad.add(i.value);
  }
  const truthByHost = new Map<string, HostTruth>();
  for (const e of feed) {
    const p = e.payload as unknown as TelemetryEvent & { incident_id?: string };
    const h = str(p.hostname); const k = hostKey(h);
    if (!k || !attackIds.has(fidOf(e))) continue;
    let t = truthByHost.get(k);
    if (!t) { t = { host: h, tp: [], tpIds: new Set(), pids: new Set(), names: new Set(), bad: new Set(), text: "", persistence: false, lateral: false, exfil: false, firstMs: null, incident: null }; truthByHost.set(k, t); }
    t.tp.push(p); t.tpIds.add(fidOf(e));
    if (p.process?.pid) t.pids.add(Number(p.process.pid));
    if (p.process?.name) t.names.add(p.process.name.toLowerCase());
    for (const i of extractIocs(p)) if (i.type !== "hash" && isBad(i.type, i.value) && !(i.type === "ip" && isInternal(i.value))) t.bad.add(i.value);
    t.text += " " + JSON.stringify(p).toLowerCase();
    const tech = String(p.mitre_technique ?? "");
    if (PERSIST.test(tech) || PERSIST_TYPES.test(String(p.event_type ?? ""))) t.persistence = true;
    if (LATERAL.test(tech)) t.lateral = true;
    if (EXFIL.test(tech) || EXFIL_TYPES.test(String(p.event_type ?? ""))) t.exfil = true;
    const ms = msOf(e);
    if (Number.isFinite(ms) && (t.firstMs == null || ms < t.firstMs)) { t.firstMs = ms; t.incident = str(p.incident_id) || null; }
  }
  // lateral movement INTO a host shows on the source host's logs: mark hosts named there too
  for (const t of truthByHost.values()) if (t.lateral) for (const o of truthByHost.values()) if (o !== t && t.text.includes(hostKey(o.host))) o.lateral = true;
  // patient zero per incident = the host of the incident's earliest attack log
  const patientZero = new Map<string, string>();
  for (const [k, t] of truthByHost) {
    const inc = t.incident ?? "_"; const cur = patientZero.get(inc);
    if (!cur || (t.firstMs ?? Infinity) < (truthByHost.get(cur)!.firstMs ?? Infinity)) patientZero.set(inc, k);
  }
  const sessionHosts = new Set(feed.map(e => hostKey(str((e.payload as { hostname?: unknown }).hostname))).filter(Boolean));

  // ── evidence views rebuilt from the PUBLIC log (exactly what the workbench showed) ──
  const pub = (ctx.publicEvents?.length ? ctx.publicEvents : events).filter(e => e.type === "feed.event" && e.occurred_at);
  const rows: FeedRow[] = pub.map(e => ({ ev: withRebasedTime(e.payload as unknown as TelemetryEvent, e.occurred_at!), atMs: Date.parse(e.occurred_at!) }));
  const items = evidenceItems(events);
  const itemById = new Map(items.map(x => [x.id, x]));
  const views = new Map<string, EvidenceView | null>();
  const viewOf = (it: EvidenceItem) => {
    if (!views.has(it.id)) {
      try { views.set(it.id, buildEvidenceView({ feed: rows, host: it.host, evidenceId: it.id, kind: it.kind, snapshotMs: it.at, state: hostStateOf(events, it.host), sessionId })); }
      catch { views.set(it.id, null); }
    }
    return views.get(it.id) ?? null;
  };
  /** A cited ref → what the row stands for, its host and when the evidence was taken. */
  const resolve = (ref: string): { key: string; host: string; atMs: number } | null => {
    if (ref.startsWith("TL/")) {
      const fe = feedById.get(ref.slice(3)); if (!fe) return null;
      return { key: `ev:${ref.slice(3)}`, host: str((fe.payload as { hostname?: unknown }).hostname), atMs: msOf(fe) };
    }
    const m = ref.match(/^((?:MEM|TRI)-\d{3})\//); const it = m ? itemById.get(m[1]) : undefined; if (!it) return null;
    const v = viewOf(it); if (!v) return null;
    for (const t of v.tables) { const i = t.refs.indexOf(ref); if (i >= 0) return { key: t.keys?.[i] ?? "", host: it.host, atMs: it.at }; }
    return null;
  };
  const attackKey = (key: string, t: HostTruth | undefined): boolean => {
    if (!t) return false;
    const [kind, ...rest] = key.split(":"); const val = rest.join(":");
    if (kind === "pid") return t.pids.has(Number(val));
    if (kind === "ip") { const [ip, pidPart] = val.split("|pid:"); return t.bad.has(ip) || globalBad.has(ip) || t.pids.has(Number(pidPart)); }
    if (kind === "exe") return t.names.has(val.toLowerCase());
    if (kind === "ev") return t.tpIds.has(val);
    if (kind === "auto") {
      const [name, cmd] = val.split("|");
      const exe = (cmd ?? "").replace(/^"|"$/g, "").split(/["\s]/).filter(Boolean)[0]?.split(/[\\/]/).pop()?.toLowerCase() ?? "";
      return (name.length >= 3 && t.text.includes(name.toLowerCase())) || (exe.length >= 5 && !/^(svchost|rundll32|powershell|cmd|explorer)\.exe$/.test(exe) && t.text.includes(exe));
    }
    return false;
  };
  const c2Key = (key: string): boolean => {
    if (key.startsWith("ip:")) { const ip = key.slice(3).split("|")[0]; return globalBad.has(ip); }
    if (key.startsWith("ev:")) { const fe = feedById.get(key.slice(3)); return !!fe && attackIds.has(key.slice(3)) && extractIocs(fe.payload as unknown as TelemetryEvent).some(i => globalBad.has(i.value)); }
    return false;
  };
  const persistKey = (key: string, t: HostTruth | undefined): boolean => {
    if (key.startsWith("auto:")) return attackKey(key, t);
    if (key.startsWith("ev:")) { const fe = feedById.get(key.slice(3)); if (!fe || !attackIds.has(key.slice(3))) return false; const p = fe.payload as unknown as TelemetryEvent; return PERSIST.test(String(p.mitre_technique ?? "")) || PERSIST_TYPES.test(String(p.event_type ?? "")); }
    return false;
  };

  // ── findings ──
  const findings: FindingReview[] = [];
  for (const e of events) {
    if (e.type !== "forensic.finding") continue;
    const p = (e.payload ?? {}) as Record<string, unknown>;
    const kind = str(p.kind); const host = str(p.host); const k = hostKey(host); const t = truthByHost.get(k);
    const status = str(p.status) || null; const atMs = msOf(e);
    const refs = (Array.isArray(p.evidence) ? p.evidence : []).map(str).filter(Boolean);
    const text = `${str(p.summary)} ${(Array.isArray(p.evidence_text) ? p.evidence_text : []).map(str).join(" ")}`;
    // correctness
    let right: boolean | null; let wrongWhy = "";
    switch (kind) {
      case "host_status":
        if (status === "compromised") { right = !!t; wrongWhy = `${host} shows no attack activity in the shift`; }
        else if (status === "not_compromised") { right = !t; wrongWhy = `${host} was compromised (${t?.tp.length ?? 0} attack logs)`; }
        else right = null;
        break;
      case "c2": {
        const named = indicatorsIn(text, sessionHosts);
        if (named.length) { right = !!t && named.some(x => globalBad.has(x)); wrongWhy = t ? `${named.join(", ")} ${named.length > 1 ? "are" : "is"} not attacker infrastructure` : `${host} shows no attack activity`; }
        else { right = !!t && t.bad.size > 0; wrongWhy = `no attacker C2 traffic from ${host}`; }
        break;
      }
      case "persistence": right = !!t?.persistence; wrongWhy = `no attacker persistence was set on ${host}`; break;
      case "lateral": right = !!t?.lateral; wrongWhy = `no lateral movement involves ${host}`; break;
      case "exfiltration": right = !!t?.exfil; wrongWhy = `no data was staged or sent from ${host}`; break;
      case "patient_zero": {
        const pz = t ? patientZero.get(t.incident ?? "_") : undefined;
        right = !!t && pz === k; wrongWhy = pz ? `the entry point was ${truthByHost.get(pz)!.host}` : `${host} shows no attack activity`;
        break;
      }
      default: right = null;
    }
    // support: a cited row, from evidence taken before the finding, that shows it
    let supportedBy: string | null = null;
    if (right) for (const ref of refs) {
      const r = resolve(ref); if (!r || !(r.atMs <= atMs + 1000)) continue;
      const sameHost = hostKey(r.host) === k; const rt = truthByHost.get(hostKey(r.host));
      const ok = kind === "host_status" ? (status === "not_compromised" ? sameHost : sameHost && attackKey(r.key, t))
        : kind === "c2" ? c2Key(r.key) && (sameHost || !!rt)
        : kind === "persistence" ? sameHost && persistKey(r.key, t)
        : kind === "lateral" ? !!rt && attackKey(r.key, rt)
        : sameHost && attackKey(r.key, t);
      if (ok) { supportedBy = ref; break; }
    }
    const verdict: FindingVerdict = right == null ? "ungraded" : !right ? "wrong" : supportedBy ? "confirmed" : "guess";
    const reason = verdict === "ungraded" ? (kind === "host_status" ? "status left undetermined: honest, not graded" : "free note: not graded")
      : verdict === "wrong" ? wrongWhy
      : verdict === "confirmed" ? `right, and ${supportedBy!.startsWith("TL/") ? "the cited log" : supportedBy} shows it`
      : refs.length ? "right, but none of the cited rows shows it" : "right, but no evidence was cited";
    findings.push({ seq: e.seq, by: e.actor_id, kind, host, status, summary: str(p.summary).slice(0, 240), confidence: str(p.confidence),
      atS: relS(Number.isFinite(atMs) ? atMs : null), cited: refs.length, supportedBy, verdict, reason });
  }

  // ── hosts: coverage, preservation, status calls ──
  const inPlay = forensicHosts(events, feed);
  const hostList = new Map<string, string>();
  for (const h of inPlay) hostList.set(hostKey(h), h);
  for (const it of items) if (!hostList.has(hostKey(it.host))) hostList.set(hostKey(it.host), it.host);
  const kills = events.filter(e => e.type === "rtr.action" && (e.payload as { action?: unknown }).action === "kill");
  const hosts: HostReview[] = [...hostList].map(([k, host]) => {
    const t = truthByHost.get(k);
    const ev = items.filter(x => hostKey(x.host) === k);
    const killEv = t ? kills.find(e => { const p = e.payload as { host?: unknown; pid?: unknown; name?: unknown };
      return hostKey(str(p.host)) === k && (t.pids.has(Number(p.pid)) || t.names.has(str(p.name).toLowerCase())); }) : undefined;
    const killMs = killEv ? msOf(killEv) : NaN;
    const calls = findings.filter(f => f.kind === "host_status" && hostKey(f.host) === k && (f.status === "compromised" || f.status === "not_compromised"));
    const last = calls.at(-1);
    return {
      host, attacked: !!t, attackLogs: t?.tp.length ?? 0, evidence: ev.length,
      firstEvidenceS: ev.length ? relS(Math.min(...ev.map(x => x.at))) : null,
      kill: killEv ? { by: killEv.actor_id, atS: relS(killMs), preserved: ev.some(x => x.kind === "memory" && x.at <= killMs) } : null,
      statusCalled: (last?.status as HostReview["statusCalled"]) ?? null, statusRight: last ? last.verdict !== "wrong" : null,
    };
  }).sort((a, b) => Number(b.attacked) - Number(a.attacked) || a.host.localeCompare(b.host));

  // ── reports to the SOC Manager ──
  const reportEvs = events.filter(e => e.type === "forensic.report");
  const reports: ReportReview[] = reportEvs.map(e => {
    const p = (e.payload ?? {}) as Record<string, unknown>; const atMs = msOf(e);
    const readiness = str(p.readiness);
    let readinessCheck: ReportReview["readinessCheck"] = "honest"; let readinessNote = readiness === "ready" ? "" : "not claiming READY: nothing to check";
    if (readiness === "ready") {
      const playing = forensicHosts(events.filter(x => !(msOf(x) > atMs)), feed).map(hostKey).filter(h => truthByHost.has(h));
      const called = new Set(findings.filter(f => f.kind === "host_status" && f.status === "compromised" && (f.verdict === "confirmed" || f.verdict === "guess")
        && events.find(x => x.seq === f.seq && !(msOf(x) > atMs))).map(f => hostKey(f.host)));
      const open = playing.filter(h => !called.has(h)).map(h => truthByHost.get(h)!.host);
      readinessCheck = playing.length && !open.length ? "backed" : "premature";
      readinessNote = readinessCheck === "backed" ? "every attacked host in play had a confirmed status" : open.length ? `no confirmed status yet for ${open.join(", ")}` : "no attacked host had been examined yet";
    }
    const n = Number(p.next_update_min);
    let promiseKept: boolean | null = null;
    if (n > 0 && Number.isFinite(atMs)) {
      const due = atMs + n * 60_000 + 120_000;
      const next = reportEvs.find(x => x.seq > e.seq && x.actor_id === e.actor_id && msOf(x) > atMs);
      promiseKept = next && msOf(next) <= due ? true : endMs < due ? null : false;
    }
    return { seq: e.seq, by: e.actor_id, kind: str(p.kind), readiness, atS: relS(Number.isFinite(atMs) ? atMs : null), readinessCheck, readinessNote, promiseKept };
  });

  // ── per user ──
  const perUser: Record<string, UserForensics> = {};
  for (const m of roster) {
    const mine = findings.filter(f => f.by === m.user_id);
    const myEvidence = items.filter(x => x.by === m.user_id).length;
    const myReports = reports.filter(r => r.by === m.user_id);
    const myKills = hosts.filter(h => h.kill?.by === m.user_id);
    if (!mine.length && !myEvidence && !myReports.length && !myKills.length) continue;
    const graded = mine.filter(f => f.verdict !== "ungraded");
    const confirmed = graded.filter(f => f.verdict === "confirmed").length, guess = graded.filter(f => f.verdict === "guess").length;
    const high = graded.filter(f => f.confidence === "high");
    const highRight = high.filter(f => f.verdict !== "wrong").length;
    const preserved = myKills.filter(h => h.kill!.preserved).length;
    let reportPoints: number | null = null;
    if (myReports.length) {
      const pts = 1 + (myReports.every(r => r.readinessCheck !== "premature") ? 1 : 0) + (myReports.every(r => r.promiseKept !== false) ? 1 : 0);
      reportPoints = pts >= 3 ? 12 : pts === 2 ? 8 : 4;
    } else if (m.role === "t3" && (mine.length || myEvidence)) reportPoints = 0;
    perUser[m.user_id] = {
      evidence: myEvidence, findings: mine,
      graded: graded.length, confirmed, guess, wrong: graded.length - confirmed - guess,
      accPct: graded.length ? Math.round(((confirmed + guess * 0.5) / graded.length) * 100) : null,
      supportedPct: pct(confirmed, confirmed + guess),
      highTotal: high.length, highRight, calibrationPct: pct(highRight, high.length),
      destructiveKills: myKills.length, preservedKills: preserved, preservationPct: pct(preserved, myKills.length),
      reports: myReports, reportPoints,
    };
  }
  return { perUser, hosts, findings, reports };
}
