/**
 * Client-side ground truth for the solo dashboard's incident-report grader.
 *
 * QA-DASH-2 / QA-DASH-3: the truth sent to the grader is scoped to the ACTIVE
 * incident and to what the student could actually have seen: only that
 * incident's story events already injected into the feed, and only the
 * malicious ones (baseline / ambient-context rows and FP decoys are excluded).
 * Before the attack starts there is no incident, so the truth is empty.
 * Pure (no React), so it is unit-tested directly.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { isSha256Field, isIpCheckField, isDomainCheckField } from "@/components/threat-intel/ThreatIntelDrawer";
import type { TimelineRow, TruthEvent } from "@/lib/dashboard/timelineReport";

/**
 * Is this story event part of the attack itself? Baseline / "what normal looked
 * like" rows and training false positives are not: the incident must not open on
 * them (QA-DASH-10) and they are not ground truth (QA-DASH-3).
 */
export function isAttackEvent(e: Pick<TelemetryEvent, "is_baseline" | "expected_verdict" | "fp_explanation" | "it_verify_result">): boolean {
  if (e.is_baseline) return false;
  if (e.expected_verdict === "fp") return false;
  if (e.fp_explanation) return false;
  if (e.it_verify_result === "confirmed") return false;
  return true;
}

/**
 * Well-known benign / OS / browser / Office binaries. They show up in attack
 * events as a parent or as the process that did a download, but they are not
 * indicators of compromise, so they must never be ground-truth "IOCs".
 * Lower-case; compared case-insensitively.
 */
export const BENIGN_PROCESS_NAMES: ReadonlySet<string> = new Set([
  // Windows core / session
  "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe",
  "svchost.exe", "explorer.exe", "userinit.exe", "dwm.exe", "sihost.exe", "taskhostw.exe",
  "runtimebroker.exe", "searchindexer.exe", "searchhost.exe", "searchapp.exe", "spoolsv.exe",
  "dllhost.exe", "conhost.exe", "ctfmon.exe", "fontdrvhost.exe", "audiodg.exe", "lsaiso.exe",
  "startmenuexperiencehost.exe", "shellexperiencehost.exe", "textinputhost.exe", "smartscreen.exe",
  "securityhealthservice.exe", "msmpeng.exe", "nissrv.exe", "mssense.exe", "wmiprvse.exe",
  // Browsers
  "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "brave.exe", "opera.exe", "safari",
  // Office / collaboration
  "outlook.exe", "winword.exe", "excel.exe", "powerpnt.exe", "onenote.exe", "msaccess.exe",
  "teams.exe", "ms-teams.exe", "onedrive.exe", "slack.exe", "zoom.exe",
  // Unix init / shells' parents
  "systemd", "init", "launchd", "sshd", "cron", "crond",
]);

export function isBenignProcessName(name: string | undefined | null): boolean {
  return !!name && BENIGN_PROCESS_NAMES.has(name.trim().toLowerCase());
}

/**
 * Pull the real indicator values (IPs, users, hosts, domains, hashes, non-system
 * process names) out of a set of attack events. These are the ground truth the
 * report grader checks the student's write-up against.
 */
export function extractIndicators(events: TelemetryEvent[]): string[] {
  const out = new Set<string>();
  for (const e of events) {
    if (e.src_ip)    out.add(e.src_ip);
    if (e.dst_ip)    out.add(e.dst_ip);
    if (e.user_email) out.add(e.user_email);
    if (e.hostname)  out.add(e.hostname);
    const dom = (e.network as { domain?: string } | undefined)?.domain;
    if (dom) out.add(dom);
    const sha = (e.file as { sha256?: string } | undefined)?.sha256;
    if (sha) out.add(sha);
    const procObj = e.process as { name?: string; hash?: { sha256?: string } } | undefined;
    if (procObj?.name && !isBenignProcessName(procObj.name)) out.add(procObj.name);
    if (procObj?.hash?.sha256) out.add(procObj.hash.sha256);
    // Indicators that live ONLY in the vendor-native raw block, recognised with the
    // same helpers the Threat-Intel drawer uses, so ground truth == what's checkable.
    const raw = (e.raw ?? {}) as Record<string, unknown>;
    for (const [k, v] of Object.entries(raw)) {
      if (typeof v !== "string" || !v.trim()) continue;
      const val = v.trim();
      if (isSha256Field(k, val) || isIpCheckField(k, val) || isDomainCheckField(k, val)) out.add(val);
    }
  }
  return Array.from(out);
}

export interface IncidentTruthInput {
  /** The incident / story title. */
  title: string;
  /** The story's declared techniques: used only when no injected event carries one. */
  storyMitre?: string[];
  /** The incident's story events already injected into the feed (baseline included). */
  injected: TelemetryEvent[];
}

export interface IncidentGroundTruth {
  realIndicators: string[];
  storyTitle: string | null;
  storyMitre: string[];
}

/** Ground truth for the grader from the active incident (null → nothing to grade against). */
export function incidentGroundTruth(incident: IncidentTruthInput | null): IncidentGroundTruth {
  if (!incident) return { realIndicators: [], storyTitle: null, storyMitre: [] };
  const attack = incident.injected.filter(isAttackEvent);
  if (attack.length === 0) return { realIndicators: [], storyTitle: null, storyMitre: [] };
  const seen = Array.from(new Set(attack.map(e => e.mitre_technique).filter((m): m is string => !!m)));
  return {
    realIndicators: extractIndicators(attack),
    storyTitle: incident.title || null,
    storyMitre: seen.length > 0 ? seen : Array.from(new Set(incident.storyMitre ?? [])),
  };
}

// ── Timeline report (Tal, 2026-10-28) ────────────────────────────────────────

const lc = (v: string | undefined | null) => (v ?? "").trim();
const userOf = (e: TelemetryEvent) => lc(e.process?.user) || lc(e.user_email) || lc(e.user?.email);
const fmtClock = (ts: string) => { const d = new Date(ts); return Number.isNaN(d.getTime()) ? "" : d.toLocaleTimeString("en-GB", { hour12: false }); };

/** A timeline row pre-filled from a feed log: when, where and who come from the log;
 *  "what ran" is the command line when the log has one, else the analyst writes it. */
export function rowFromEvent(e: TelemetryEvent): TimelineRow {
  const p = e.process;
  return {
    id: `row_${e.id}`,
    eventId: e.id,
    time: fmtClock(e.ts),
    host: lc(e.hostname),
    actor: userOf(e) || lc(p?.parent_name),
    action: p?.cmdline ? lc(p.cmdline) : "",
  };
}

/** The attack's logs as the analyst saw them in the feed (the incident's ids), for the
 *  timeline grader. Only values a reader can find on the log itself go in. */
export function truthEventsFrom(feed: TelemetryEvent[], incidentIds: string[]): TruthEvent[] {
  const ids = new Set(incidentIds);
  return feed.filter(e => ids.has(e.id)).map(e => {
    const p = e.process;
    const net = e.network as { domain?: string; url?: string } | undefined;
    const files = [e.file?.sha256, e.file?.md5, e.file?.name, p?.hash?.sha256, p?.hash?.md5, p && !isBenignProcessName(p.name) ? p.name : undefined];
    const urlHost = net?.url ? net.url.replace(/^[a-z]+:\/\//i, "").split(/[/:?]/)[0] : undefined;
    return {
      id: e.id, ts: e.ts, source: String(e.source),
      stage: e.mitre_technique || String(e.event_type),
      host: lc(e.hostname) || undefined,
      users: [userOf(e), lc(e.user_email), lc(e.user?.email)].filter(Boolean),
      actors: [p?.name, p?.parent_name, p?.target?.name].filter((x): x is string => !!x),
      ips: [e.src_ip, e.dst_ip].filter((x): x is string => !!x),
      domains: [net?.domain, urlHost].filter((x): x is string => !!x),
      files: files.filter((x): x is string => !!x),
      cmd: p?.cmdline || undefined,
    };
  });
}
