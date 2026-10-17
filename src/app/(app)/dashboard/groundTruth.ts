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
