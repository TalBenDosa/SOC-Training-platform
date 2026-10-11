"use client";
import { useEffect, useState } from "react";
import { Activity, AlertTriangle, ChevronDown, RefreshCw } from "lucide-react";
import { fetchOrError } from "@/lib/http/safeFetch";
import type { OpsEvent, OpsHealthRow, OpsLevel } from "@/lib/ops/opsHealth";

interface Payload { health: OpsHealthRow | null; events: OpsEvent[]; level: OpsLevel; reasons: string[] }

const TONE: Record<OpsLevel, { box: string; text: string; label: string }> = {
  ok:       { box: "border-neon-green/30 bg-neon-green/5",       text: "text-neon-green",     label: "All systems normal" },
  warning:  { box: "border-neon-amber/40 bg-neon-amber/5",       text: "text-neon-amber",     label: "Needs a look" },
  critical: { box: "border-severity-high/50 bg-severity-high/10", text: "text-severity-high", label: "Something is failing" },
};

/**
 * Platform health on /superadmin (QA phase 7, E-06): background-job errors and
 * realtime broadcast failures used to land in team_ops_events where nobody
 * would see them. A quiet one-line strip when all is well; reasons + the
 * recent errors when it isn't. Refreshes every 2 minutes while open.
 */
export function OpsHealthCard() {
  const [data, setData] = useState<Payload | null>(null);
  const [failed, setFailed] = useState(false);
  const [open, setOpen] = useState(false);
  const [tick, setTick] = useState(0);

  useEffect(() => {
    let alive = true;
    (async () => {
      const res = await fetchOrError("/api/superadmin/ops-health");
      if (!alive) return;
      if (!res.ok) { setFailed(true); return; }
      setFailed(false);
      setData(await res.json().catch(() => null));
    })();
    const iv = setInterval(() => setTick(t => t + 1), 120_000);
    return () => { alive = false; clearInterval(iv); };
  }, [tick]);

  const level: OpsLevel = failed ? "warning" : data?.level ?? "ok";
  const tone = TONE[level];
  const h = data?.health;

  return (
    <div className={`rounded-xl border px-4 py-3 ${tone.box}`}>
      <div className="flex flex-wrap items-center gap-2 text-sm">
        {level === "ok" ? <Activity className={`h-4 w-4 ${tone.text}`} /> : <AlertTriangle className={`h-4 w-4 ${tone.text}`} />}
        <span className={`font-semibold ${tone.text}`}>{failed ? "Couldn't check platform health" : tone.label}</span>
        {h && (
          <span className="text-xs text-slate-400 tabular-nums">
            · {h.running_sessions} team session(s) running · {h.ops_errors_1h} job error(s) in the last hour
          </span>
        )}
        <span className="ml-auto flex items-center gap-1">
          <button onClick={() => setTick(t => t + 1)} aria-label="Refresh health" className="rounded p-1 text-slate-400 hover:text-white"><RefreshCw className="h-3.5 w-3.5" /></button>
          {(data?.events.length ?? 0) > 0 && (
            <button onClick={() => setOpen(o => !o)} aria-expanded={open} className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] text-slate-300 hover:text-white">
              Recent errors <ChevronDown className={`h-3 w-3 transition ${open ? "rotate-180" : ""}`} />
            </button>
          )}
        </span>
      </div>
      {data && data.reasons.length > 0 && (
        <ul className="mt-2 list-disc space-y-0.5 pl-6 text-xs text-slate-300">
          {data.reasons.map(r => <li key={r}>{r}</li>)}
        </ul>
      )}
      {open && data && (
        <div className="mt-2 max-h-64 overflow-auto rounded-lg border border-border bg-bg">
          <table className="w-full text-left text-[11px]">
            <thead className="text-slate-500"><tr><th className="px-2 py-1">When</th><th className="px-2 py-1">Job</th><th className="px-2 py-1">Detail</th></tr></thead>
            <tbody>
              {data.events.map((e, i) => (
                <tr key={`${e.at}-${i}`} className="border-t border-border/60 align-top">
                  <td className="whitespace-nowrap px-2 py-1 text-slate-400 tabular-nums">{new Date(e.at).toLocaleString("en-GB", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" })}</td>
                  <td className="whitespace-nowrap px-2 py-1 font-mono text-slate-300">{e.kind}</td>
                  <td className="px-2 py-1 font-mono text-slate-400 break-all">{e.detail ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
