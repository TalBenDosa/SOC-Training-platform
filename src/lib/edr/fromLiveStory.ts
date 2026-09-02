/**
 * Build a live EdrInvestigation from the attack story running in the SOC
 * Dashboard feed — so "Investigate in EDR" opens the SAME attack the analyst is
 * watching, from the endpoint's point of view (SIEM + EDR = one product).
 *
 * The story's telemetry events already carry real endpoint process data
 * (process.pid / parent_pid / cmdline / path / user / hash.sha256 — see
 * TelemetryEvent in src/lib/sim/types.ts), so we reconstruct the true process
 * ANCESTRY rather than inventing one. Network/file activity and MITRE detections
 * are lifted from the same events.
 *
 * Returns null when the story has no endpoint process telemetry (a pure
 * identity/cloud attack — impossible travel, OAuth consent, password spray):
 * there is no process tree to walk, so the caller falls back to the static
 * console instead of showing an empty tree.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { lookupHash } from "@/lib/sim/hashDatabase";
import { classifyScope } from "./classifyScope";
import type { EdrInvestigation, EdrProcess, EdrDetection, EdrFileOp, EdrTimelineEvent, Verdict } from "./investigations";

const USER_WRITABLE = /\\(AppData|Temp|Users\\[^\\]+\\Downloads|ProgramData)\\|\/tmp\/|\/home\/[^/]+\//i;

/** HH:MM:SS out of an ISO timestamp, TZ-agnostic. */
function hhmmss(ts?: string): string {
  const m = ts?.match(/T(\d{2}:\d{2}:\d{2})/);
  return m ? m[1] : (ts ?? "").slice(11, 19) || "00:00:00";
}

function mostCommon(values: (string | undefined)[]): string | undefined {
  const counts = new Map<string, number>();
  for (const v of values) if (v) counts.set(v, (counts.get(v) ?? 0) + 1);
  return [...counts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0];
}

/** Hostname from a URL string, tolerant of relative/garbage values. */
function hostOf(url?: string): string | undefined {
  if (!url) return undefined;
  try { return new URL(url).hostname; } catch { return undefined; }
}

// Parents that have no business launching another executable — an Office doc or
// a script host spawning a child is the classic "living off the land" tell.
const ANOMALOUS_PARENTS = new Set([
  "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
  "wscript.exe", "cscript.exe", "mshta.exe", "cmd.exe", "powershell.exe",
]);

/**
 * The behavioural "why this stands out" a real EDR surfaces BEYOND the raw log
 * line — the enrichment the student reasons from. Shown in the debrief after the
 * decision (never up front, so it can't leak the answer). Built from the same
 * telemetry, so it stays tied to the case.
 */
function whyItStandsOut(
  p: NonNullable<TelemetryEvent["process"]>,
  o: { signed: boolean; malicious?: boolean; userWritable: boolean },
): string | undefined {
  const bits: string[] = [];
  if (o.malicious) bits.push("its SHA-256 matches a known-bad sample on record");
  if (!o.signed && o.userWritable) bits.push(`it runs UNSIGNED from a user-writable path (${p.path ?? "?"}) — a real system binary never does`);
  else if (!o.signed) bits.push("it is not digitally signed");
  else if (o.userWritable) bits.push(`it runs from a user-writable path (${p.path ?? "?"})`);
  const parent = p.parent_name?.toLowerCase();
  if (parent && ANOMALOUS_PARENTS.has(parent) && p.name.toLowerCase() !== parent)
    bits.push(`its parent is ${p.parent_name}, which has no legitimate reason to launch this`);
  if (bits.length === 0) return undefined;
  return "Why it stands out: " + bits.join("; ") + ".";
}

function timelineKind(e: TelemetryEvent): EdrTimelineEvent["kind"] {
  const t = e.event_type;
  if (t.startsWith("net") || t === "http_request" || t === "dns_query" || t === "http_blocked") return "network";
  if (t.startsWith("file")) return "file";
  if (e.mitre_technique && (e.severity === "high" || e.severity === "critical")) return "detection";
  return "process";
}

export function buildInvestigationFromStory(
  story: { id: string; title: string; events: TelemetryEvent[] },
): EdrInvestigation | null {
  const events = story.events ?? [];
  const procEvents = events.filter(e => e.process?.name && typeof e.process.pid === "number");
  if (procEvents.length === 0) return null; // no endpoint tree to walk

  // ── Processes (deduped by pid), plus stubs for referenced-but-unseen parents ──
  const procByPid = new Map<number, EdrProcess>();
  const seedProcess = (e: TelemetryEvent) => {
    const p = e.process!;
    if (procByPid.has(p.pid)) return;
    const sha256 = p.hash?.sha256;
    const malicious = sha256 ? lookupHash(sha256)?.malicious : false;
    const userWritable = USER_WRITABLE.test(p.path ?? "");
    // E-02: signing is authoritative when the log states it — a real EDR reads the
    // Authenticode result off the binary, and the console must not contradict it.
    // Prefer the explicit raw field (process.signed / file.signed / code_signature.*)
    // over the heuristic; only when the log is silent do we fall back to it (a
    // known-bad hash or a binary from a user-writable path is treated as unsigned,
    // the classic payload tell; system/Program Files binaries as signed). Displaying
    // "Signed: Yes" in green on a binary the log marks unsigned is the one finding
    // that can teach a wrong habit, so the log always wins.
    const rawSigned =
      (e.raw?.["process.signed"] ?? e.raw?.["file.signed"] ?? e.raw?.["code_signature.signed"] ??
       e.raw?.["process.code_signature.exists"] ?? e.raw?.["file.code_signature.valid"]) as unknown;
    const signed = rawSigned != null
      ? !/^(false|no|0|unsigned|invalid)$/i.test(String(rawSigned).trim())
      : !malicious && !userWritable;
    const verdict: Verdict = malicious
      ? "malicious"
      : (e.mitre_technique && (e.severity === "critical" || e.severity === "high")) || userWritable
        ? "suspicious"
        : "benign";
    procByPid.set(p.pid, {
      pid: p.pid,
      ppid: p.parent_pid ?? 0,
      name: p.name,
      cmdline: p.cmdline ?? p.name,
      user: p.user ?? e.user_email ?? e.user?.email ?? "unknown",
      path: p.path ?? p.name,
      signed,
      sha256,
      startedAt: hhmmss(e.ts),
      verdict,
      note: verdict === "benign" ? undefined : whyItStandsOut(p, { signed, malicious, userWritable }),
      network: [],
      files: [],
    });
  };
  for (const e of procEvents) {
    seedProcess(e);
    const p = e.process!;
    if (p.parent_pid != null && !procByPid.has(p.parent_pid)) {
      // A parent we never saw a create event for — add a benign stub so the
      // tree connects (real consoles show the ancestor even without its own row).
      procByPid.set(p.parent_pid, {
        pid: p.parent_pid, ppid: 0, name: p.parent_name ?? "process",
        cmdline: p.parent_name ?? "—", user: p.user ?? "unknown",
        path: p.parent_name ?? "—", signed: true, startedAt: hhmmss(e.ts), verdict: "benign",
        network: [], files: [],
      });
    }
  }
  const processes = [...procByPid.values()];

  // ── Payload = the process to flag. Prefer a known-bad hash; else the highest-
  //    severity endpoint detection; else the last-started suspicious process. ──
  const byHash = processes.filter(p => p.sha256 && lookupHash(p.sha256!)?.malicious);
  const payload =
    byHash.sort((a, b) => a.startedAt.localeCompare(b.startedAt)).at(-1)
    ?? processes.filter(p => p.verdict !== "benign").sort((a, b) => a.startedAt.localeCompare(b.startedAt)).at(-1)
    ?? null;
  if (payload) payload.verdict = "malicious";

  // ── Attach network / file activity to the owning process (orphans → payload) ──
  for (const e of events) {
    const owner = (e.process?.pid != null && procByPid.get(e.process.pid)) || payload;
    if (!owner) continue;
    const net = e.network;
    if ((net?.domain || net?.url || e.dst_ip) && (owner.network!.length < 8)) {
      owner.network!.push({
        ts: hhmmss(e.ts),
        direction: "outbound",
        remote_ip: e.dst_ip ?? "—",
        remote_port: e.dst_port ?? (net?.url?.startsWith("https") ? 443 : 80),
        domain: net?.domain ?? hostOf(net?.url),
        proto: e.protocol ?? (net?.url?.startsWith("https") ? "TLS" : "HTTP"),
        bytes: net?.bytes_out,
        method: net?.method,
        status: net?.status,
        url: net?.url,
      });
    }
    if (e.file?.path && owner.files!.length < 8) {
      const action: EdrFileOp["action"] =
        e.event_type === "file_delete" ? "delete" :
        e.event_type === "file_rename" ? "rename" :
        e.event_type === "file_access" ? "read" : "write";
      owner.files!.push({ ts: hhmmss(e.ts), action, path: e.file.path });
    }
  }

  // ── Detections ────────────────────────────────────────────────────────────
  // E-03: map EVERY EDR-source detection to a console detection, not only the ones
  // carrying a MITRE technique. A CrowdStrike prevention/quarantine event (Kill
  // Process + Quarantine File, pattern_disposition 128) is the decisive detection of
  // the case yet carries no technique_id; excluding it made the console report fewer
  // detections than the SIEM feed, score the incident a whole band too low (a
  // critical read as Medium), and undercount the "Investigate in EDR" badge. Now the
  // detection set == the EDR events the analyst saw in the feed, so score, severity
  // band and count line up with the SIEM.
  const ACTION_LABEL: Record<string, string> = {
    quarantine: "Quarantine", kill: "Kill Process", block: "Prevention", prevent: "Prevention",
  };
  const detectionKind = (e: TelemetryEvent) => {
    const hay = `${e.event_type ?? ""} ${String(e.raw?.["action_result"] ?? "")} ${String(e.raw?.["quarantine.status"] ?? "")}`.toLowerCase();
    if (/quarantin/.test(hay)) return "quarantine";
    if (/kill|terminat/.test(hay)) return "kill";
    if (/block|prevent/.test(hay)) return "block";
    return null;
  };
  const isDetectionEvent = (e: TelemetryEvent) =>
    e.is_detection === true ||
    /detection|threat|malware|ransom|quarantin|prevent/i.test(`${e.event_type ?? ""} ${String(e.raw?.["action_result"] ?? "")}`);
  const seenDet = new Set<string>();
  const detections: EdrDetection[] = [];
  for (const e of events) {
    const pid = e.process?.pid;
    if (pid == null) continue;
    const sevOk = e.severity === "critical" || e.severity === "high" || e.severity === "medium";
    const techniqueDet = !!e.mitre_technique && sevOk;
    const edrDet = e.source === "edr" && isDetectionEvent(e);
    if (!techniqueDet && !edrDet) continue;
    // A technique row keys on pid+technique; a techniqueless prevention keys on its
    // action so it never collapses into a technique row — and so a kill AND a
    // quarantine on the same pid both count.
    const action = detectionKind(e);
    const key = `${pid}:${e.mitre_technique ?? `${e.event_type}:${action ?? String(e.raw?.["action_result"] ?? "")}`}`;
    if (seenDet.has(key)) continue;
    seenDet.add(key);
    const technique = e.mitre_technique ?? (action ? ACTION_LABEL[action] : "EDR Detection");
    const severity = (["critical", "high", "medium", "low"].includes(e.severity as string)
      ? e.severity : "high") as EdrDetection["severity"];
    detections.push({
      pid,
      technique,
      name: e.rule?.name ?? e.description?.split(/[.—]/)[0]?.trim().slice(0, 80) ?? e.event_type,
      severity,
      ioa: e.description,
    });
  }

  // ── Autoruns / persistence (E-04) — from THIS case's own registry telemetry ──
  // The RTR shell's `reg query Run` reads these; when the case has none it truthfully
  // reports "no autorun entries found" instead of a hard-coded key from another host.
  const autoruns = events
    .filter(e => (e.event_type ?? "").startsWith("registry") && e.registry)
    .map(e => ({
      key: e.registry!.path ?? e.registry!.key ?? "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      value: e.registry!.value ?? e.process?.cmdline ?? "(unnamed)",
    }));

  // ── Timeline (chronological, capped) ──
  const timeline: EdrTimelineEvent[] = events
    .slice()
    .sort((a, b) => (a.ts ?? "").localeCompare(b.ts ?? ""))
    .slice(0, 20)
    .map(e => ({
      at: hhmmss(e.ts),
      kind: timelineKind(e),
      pid: e.process?.pid,
      text: e.description ?? e.event_type.replace(/_/g, " "),
    }));

  // ── Host header ──
  const isLinux = events.some(e => e.source === "linux_audit");
  const host = {
    name: mostCommon(procEvents.map(e => e.hostname)) ?? mostCommon(events.map(e => e.hostname)) ?? "endpoint",
    os: isLinux ? "Linux" : "Windows",
    ip: mostCommon(procEvents.map(e => e.src_ip)) ?? mostCommon(events.map(e => e.src_ip)) ?? "—",
    user: mostCommon(procEvents.map(e => e.process?.user ?? e.user_email)) ?? "—",
  };

  const explanation = payload
    ? `${payload.name} (pid ${payload.pid}) is the payload of this attack: ${payload.signed ? "" : "an unsigned binary "}running "${payload.cmdline}"${payload.sha256 && lookupHash(payload.sha256)?.malicious ? ", with a hash that matches a known-bad sample" : ""}. It is the process in the chain that carried the malicious behaviour — the parents above it are the delivery chain that launched it.`
    : "No single payload process stood out — treat the highest-severity detection in the tree as the process to contain, and correlate it with the timeline.";

  return {
    id: "live",
    title: `${story.title} — live from the Dashboard`,
    summary: `This is the endpoint view of the attack running in your SOC Dashboard feed (${story.title}). Walk the process tree, confirm the payload, and contain the host.`,
    host,
    processes,
    detections,
    timeline,
    autoruns,
    answer: { pid: payload?.pid ?? -1, explanation },
  };
}

/**
 * Build the EDR investigations for a ready scenario — ONE per incident_id, fully
 * isolated (SPEC-edr-scenario-integration §6.1). Each incident that is endpoint-
 * investigable (edr / hybrid) and actually carries process telemetry becomes its
 * own EdrInvestigation whose id is the incident_id, so the console's case-switcher
 * shows them as separate cases with no cross-incident mixing. Identity/cloud-only
 * incidents (non_edr) and incidents with no process tree to walk are skipped.
 */
export function buildInvestigationsFromScenario(
  bundle: { title?: string; events: TelemetryEvent[] },
): EdrInvestigation[] {
  const byIncident = new Map<string, TelemetryEvent[]>();
  for (const e of bundle.events) {
    if (!e.incident_id) continue;
    const list = byIncident.get(e.incident_id) ?? [];
    list.push(e);
    byIncident.set(e.incident_id, list);
  }
  const out: EdrInvestigation[] = [];
  for (const [incidentId, events] of byIncident) {
    // The authored edr_scope on the detection wins; fall back to the classifier.
    const authored = events.find(e => e.edr_scope)?.edr_scope;
    const scope = authored ?? classifyScope(events);
    if (scope === "non_edr") continue;
    const inv = buildInvestigationFromStory({ id: incidentId, title: bundle.title ?? incidentId, events });
    if (!inv) continue; // no process tree to walk
    inv.id = incidentId;
    inv.title = `${bundle.title ?? "Incident"} — endpoint view`;
    out.push(inv);
  }
  return out;
}
