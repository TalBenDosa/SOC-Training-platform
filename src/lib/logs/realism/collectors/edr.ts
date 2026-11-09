/**
 * EDR console collector (/edr and the dashboard's "Investigate in EDR").
 *
 * - Live Feed cases: buildInvestigationFromStory over the story's rows as the feed injected them
 *   (re-timed, labelled for the company's products), as page.tsx builds liveEdrInvestigation.
 * - Scenario cases: buildInvestigationsFromScenario over the events the page hands the client.
 * For each case: the RTR `ps` view (hostProcesses: the case's tree plus the host's background),
 * each process's network connections, and the Static Lab strings / FLOSS / capa output of each
 * process image the analyst can `get`.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { buildInvestigationFromStory, buildInvestigationsFromScenario } from "@/lib/edr/fromLiveStory";
import { hostProcesses } from "@/lib/edr/rtr";
import { sampleFromPath, stringsOutput, flossOutput, capaOutput } from "@/lib/edr/staticLab";
import type { EdrInvestigation } from "@/lib/edr/investigations";
import type { Collected, LogRow } from "../types";

function casesRows(out: Collected, inv: EdrInvestigation, caseKey: string, company: string | undefined, feedEvents: TelemetryEvent[]): number {
  let n = 0;
  const caseProcs = new Set(inv.processes.map(p => p.pid));
  for (const p of hostProcesses(inv, new Set())) {
    out.rows.push({
      surface: "edr", company, storyId: caseKey, rowId: `${caseKey}:ps:${p.pid}:${p.name}`, source: "rtr.ps", eventType: "process",
      raw: { pid: p.pid, ppid: p.ppid, name: p.name, path: p.path, cmdline: p.cmdline, user: p.user, sha256: p.sha256, startedAt: p.startedAt },
      isAttack: p.verdict === "malicious" || p.verdict === "abused" ? true : p.verdict === "benign" ? false : undefined,
      meta: { process: p, host: inv.host.name, hostIp: inv.host.ip, inCase: caseProcs.has(p.pid), feedEvents },
    });
    n++;
    (p.network ?? []).forEach((c, i) => {
      out.rows.push({
        surface: "edr", company, storyId: caseKey, rowId: `${caseKey}:net:${p.pid}:${i}`, source: "edr.network", eventType: "network",
        raw: { pid: p.pid, remote_ip: c.remote_ip, remote_port: c.remote_port, domain: c.domain, url: c.url, local_ip: inv.host.ip },
        meta: { host: inv.host.name },
      });
      n++;
    });
  }
  for (const p of inv.processes) {
    if (!p.path || p.verdict === "benign") continue;
    const s = sampleFromPath(inv, p.path);
    if (!s) continue;
    for (const [tool, text] of [["strings", stringsOutput(s)], ["floss", flossOutput(s)], ["capa", capaOutput(s)]] as const) {
      out.rows.push({ surface: "edr", company, storyId: caseKey, rowId: `${caseKey}:lab:${tool}:${s.name}`, source: `staticlab.${tool}`, eventType: tool, raw: text, meta: { host: inv.host.name } });
      n++;
    }
  }
  return n;
}

export function collectEdr(out: Collected, scenarios: { slug: string; events: TelemetryEvent[] }[]): void {
  // Live Feed cases, from the live rows already collected.
  const byStory = new Map<string, { company?: string; events: TelemetryEvent[]; title: string }>();
  for (const r of out.rows) {
    if (r.surface !== "live" || !r.meta?.injected || !r.storyId) continue;
    const slot = byStory.get(r.storyId) ?? byStory.set(r.storyId, { company: r.company, events: [], title: String(r.meta.storyTitle ?? r.storyId) }).get(r.storyId)!;
    slot.events.push(r.meta.injected as TelemetryEvent);
  }
  let liveCases = 0, liveRows = 0;
  for (const [id, s] of byStory) {
    let inv: EdrInvestigation | null = null;
    try { inv = buildInvestigationFromStory({ id, title: s.title, events: s.events }); } catch { inv = null; }
    if (!inv) continue;
    liveCases++;
    liveRows += casesRows(out, inv, `live:${id}`, s.company, s.events);
  }
  let scCases = 0, scRows = 0;
  for (const sc of scenarios) {
    let invs: EdrInvestigation[] = [];
    try { invs = buildInvestigationsFromScenario({ events: sc.events, iocTruth: null }); } catch { invs = []; }
    for (const inv of invs) { scCases++; scRows += casesRows(out, inv, `scenario:${sc.slug}:${inv.id}`, undefined, sc.events); }
  }
  out.notes.push(`edr: ${liveCases} live cases (${liveRows} rows), ${scCases} scenario cases (${scRows} rows)`);
}
