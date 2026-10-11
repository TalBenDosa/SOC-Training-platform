"use client";
import { Microscope } from "lucide-react";
import { Card } from "@/components/ui/Card";
import type { FindingReview, HostReview, ReportReview, UserForensics } from "@/lib/team/report/forensicReview";

/**
 * After-action view of Tier-3's forensic work, judged against what really happened:
 * each finding (confirmed / guess / wrong / not graded) with the reason, the hosts examined
 * (evidence preserved before a kill?), and the reports to the SOC Manager.
 */

const mmss = (s: number | null) => (s == null ? "" : `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`);
const KIND: Record<string, string> = {
  host_status: "Host status", persistence: "Persistence", c2: "C2 channel", lateral: "Lateral movement",
  patient_zero: "Patient zero", exfiltration: "Data staged / exfiltrated", note: "Note",
};
const REPORT_KIND: Record<string, string> = {
  status: "Status update", scope_grew: "Scope grew", data_at_risk: "Data at risk", containment_ready: "Containment readiness", need_decision: "Needs a decision",
};
const VERDICT = {
  confirmed: { label: "✓ confirmed", cls: "border-neon-green/30 bg-neon-green/[0.05]", tone: "text-neon-green" },
  guess: { label: "≈ right, no proof", cls: "border-neon-amber/40 bg-neon-amber/[0.05]", tone: "text-neon-amber" },
  wrong: { label: "✗ wrong", cls: "border-severity-high/40 bg-severity-high/[0.06]", tone: "text-severity-high" },
  ungraded: { label: "· not graded", cls: "border-border bg-bg", tone: "text-slate-400" },
} as const;

export function FindingList({ items, nameOf }: { items: FindingReview[]; nameOf?: (u: string | null) => string }) {
  if (!items.length) return <p className="text-[10px] text-slate-500">No findings published.</p>;
  return (
    <ul className="space-y-1">
      {items.map(f => {
        const v = VERDICT[f.verdict];
        return (
          <li key={f.seq} className={`rounded border px-2 py-1 text-[11px] ${v.cls}`}>
            <div className="flex flex-wrap items-center gap-1.5">
              <span className={`shrink-0 font-mono text-[10px] font-bold ${v.tone}`}>{v.label}</span>
              <span className="shrink-0 text-slate-300">{KIND[f.kind] ?? f.kind}{f.status ? `: ${f.status.replace("_", " ")}` : ""}</span>
              <span className="min-w-0 flex-1 truncate font-mono text-slate-200" title={f.host}>{f.host}</span>
              {f.confidence && <span className="shrink-0 text-[10px] text-slate-500">{f.confidence} confidence</span>}
              {f.atS != null && <span className="shrink-0 font-mono text-[10px] text-slate-500">{mmss(f.atS)}</span>}
            </div>
            <p className="mt-0.5 text-[10px] text-slate-300"><bdi>{f.summary}</bdi></p>
            <p className="text-[10px] text-slate-400">{f.reason}{f.cited ? ` · ${f.cited} row${f.cited === 1 ? "" : "s"} cited` : ""}{nameOf ? <> · by <bdi>{nameOf(f.by)}</bdi></> : ""}</p>
          </li>
        );
      })}
    </ul>
  );
}

function ReportList({ items, nameOf }: { items: ReportReview[]; nameOf?: (u: string | null) => string }) {
  if (!items.length) return <p className="text-[10px] text-slate-500">No report was sent to the SOC Manager.</p>;
  return (
    <ul className="space-y-1">
      {items.map(r => (
        <li key={r.seq} className={`rounded border px-2 py-1 text-[11px] ${r.readinessCheck === "premature" ? "border-severity-high/40" : "border-border"}`}>
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="shrink-0 text-slate-200">{REPORT_KIND[r.kind] ?? r.kind}</span>
            <span className={`shrink-0 rounded border px-1 text-[10px] ${r.readiness === "ready" ? (r.readinessCheck === "backed" ? "border-neon-green/40 text-neon-green" : "border-severity-high/50 text-severity-high") : "border-border text-slate-400"}`}>
              {r.readiness === "ready" ? (r.readinessCheck === "backed" ? "READY, backed" : "READY too early") : r.readiness === "not_ready" ? "not ready" : "readiness unknown"}
            </span>
            {r.promiseKept != null && <span className={`shrink-0 text-[10px] ${r.promiseKept ? "text-neon-green" : "text-neon-amber"}`}>{r.promiseKept ? "next update on time" : "promised update missed"}</span>}
            <span className="ml-auto shrink-0 font-mono text-[10px] text-slate-500">{mmss(r.atS)}</span>
          </div>
          <p className="text-[10px] text-slate-400">{r.readinessNote}{nameOf ? <> · by <bdi>{nameOf(r.by)}</bdi></> : ""}</p>
        </li>
      ))}
    </ul>
  );
}

function HostTable({ items }: { items: HostReview[] }) {
  if (!items.length) return null;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-[11px]">
        <thead><tr className="text-[10px] uppercase tracking-wider text-slate-500">
          <th className="py-1 pr-2 font-semibold">Host</th><th className="py-1 pr-2 font-semibold">Truth</th><th className="py-1 pr-2 font-semibold">Evidence</th>
          <th className="py-1 pr-2 font-semibold">Status called</th><th className="py-1 font-semibold">Kill vs capture</th>
        </tr></thead>
        <tbody>
          {items.map(h => (
            <tr key={h.host} className="border-t border-border/40">
              <td className="py-1 pr-2 font-mono text-slate-200">{h.host}</td>
              <td className={`py-1 pr-2 ${h.attacked ? "text-severity-high" : "text-slate-400"}`}>{h.attacked ? `compromised (${h.attackLogs} logs)` : "clean"}</td>
              <td className="py-1 pr-2 text-slate-300">{h.evidence ? `${h.evidence} item${h.evidence === 1 ? "" : "s"}${h.firstEvidenceS != null ? ` · first at ${mmss(h.firstEvidenceS)}` : ""}` : <span className={h.attacked ? "text-neon-amber" : "text-slate-500"}>none</span>}</td>
              <td className={`py-1 pr-2 ${h.statusRight == null ? "text-slate-500" : h.statusRight ? "text-neon-green" : "text-severity-high"}`}>{h.statusCalled ? `${h.statusCalled.replace("_", " ")} ${h.statusRight ? "✓" : "✗"}` : "not called"}</td>
              <td className={`py-1 ${h.kill == null ? "text-slate-500" : h.kill.preserved ? "text-neon-green" : "text-severity-high"}`}>{h.kill == null ? "no kill" : h.kill.preserved ? "memory captured first ✓" : "killed before capture: evidence lost"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Team after-action card: every host examined, every finding judged, every report. */
export function ForensicTeamCard({ forensic, nameOf }: { forensic: { hosts: HostReview[]; findings: FindingReview[]; reports: ReportReview[] }; nameOf: (u: string | null) => string }) {
  const graded = forensic.findings.filter(f => f.verdict !== "ungraded");
  const confirmed = graded.filter(f => f.verdict === "confirmed").length;
  const wrong = graded.filter(f => f.verdict === "wrong").length;
  return (
    <Card className={wrong ? "border-severity-high/30" : undefined}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="flex items-center gap-2 text-sm font-bold text-white"><Microscope className="h-4 w-4 text-cyber-300" aria-hidden /> Forensic review (Tier-3)</h3>
        {graded.length > 0 && <span className="font-mono text-[11px] font-bold text-slate-200">{confirmed}/{graded.length} confirmed{wrong ? ` · ${wrong} wrong` : ""}</span>}
      </div>
      <p className="mt-1 text-[11px] text-slate-400">Each finding was checked against what really happened. Confirmed = right, and a row it cites (from evidence taken before the finding) shows it. A right call without such a row is not proof.</p>
      <div className="mt-3 space-y-3">
        <HostTable items={forensic.hosts} />
        <div className="grid gap-3 lg:grid-cols-2">
          <div><p className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-slate-400">Findings</p><FindingList items={forensic.findings} nameOf={nameOf} /></div>
          <div><p className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-slate-400">Reports to the SOC Manager</p><ReportList items={forensic.reports} nameOf={nameOf} /></div>
        </div>
      </div>
    </Card>
  );
}

/** The Tier-3 analyst's own forensic section inside their card. */
export function ForensicUserSection({ f }: { f: UserForensics }) {
  return (
    <div className="mt-3 border-t border-border/40 pt-2">
      <div className="mb-1.5 flex flex-wrap items-center justify-between gap-2">
        <p className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-slate-400"><Microscope className="h-3 w-3" aria-hidden /> Your forensic work</p>
        <span className="font-mono text-[10px] text-slate-300">
          {f.evidence} evidence · {f.confirmed} confirmed · {f.guess} unproven · {f.wrong} wrong
          {f.destructiveKills ? ` · evidence preserved ${f.preservedKills}/${f.destructiveKills}` : ""}
        </span>
      </div>
      <FindingList items={f.findings} />
      {f.reports.length > 0 && <div className="mt-2"><p className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-slate-400">Your reports to the SOC Manager</p><ReportList items={f.reports} /></div>}
    </div>
  );
}
