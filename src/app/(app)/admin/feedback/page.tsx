"use client";
/**
 * Content-feedback triage inbox (platform admin).
 *
 * A separate page rather than another tab inside admin/page.tsx — that file is
 * already ~2,900 lines, and this needs none of its state.
 */
import { useEffect, useState } from "react";
import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import { Flag, Loader2, AlertTriangle } from "lucide-react";
import { cn } from "@/lib/utils";

type Status = "new" | "triaged" | "resolved" | "wontfix";

interface Report {
  id: string;
  target_kind: string;
  target_id: string;
  context: Record<string, string>;
  message: string;
  status: Status;
  created_at: string;
  profiles: { handle?: string; display_name?: string } | null;
}

const FILTERS: { key: string; label: string }[] = [
  { key: "new", label: "New" },
  { key: "triaged", label: "Triaged" },
  { key: "resolved", label: "Resolved" },
  { key: "wontfix", label: "Won't fix" },
  { key: "all", label: "All" },
];

const STATUS_STYLE: Record<Status, string> = {
  new:      "border-neon-amber/40 bg-neon-amber/10 text-neon-amber",
  triaged:  "border-cyber-500/40 bg-cyber-500/10 text-cyber-300",
  resolved: "border-neon-green/40 bg-neon-green/10 text-neon-green",
  wontfix:  "border-slate-600 bg-slate-800/60 text-slate-400",
};

export default function AdminFeedbackPage() {
  const [items, setItems] = useState<Report[]>([]);
  const [filter, setFilter] = useState("new");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function load(f = filter) {
    setLoading(true); setError(null);
    const res = await fetch(`/api/feedback?status=${encodeURIComponent(f)}`);
    setLoading(false);
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Failed to load."); return; }
    setItems((await res.json()).items ?? []);
  }
  useEffect(() => { load(filter); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [filter]);

  async function setStatus(id: string, status: Status) {
    setItems(prev => prev.map(r => (r.id === id ? { ...r, status } : r)));
    await fetch("/api/feedback", {
      method: "PATCH", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id, status }),
    }).catch(() => {});
    // Re-filter: a triaged item usually leaves the current view.
    if (filter !== "all" && filter !== status) load(filter);
  }

  return (
    <div>
      <Topbar title="Content feedback" subtitle="What students reported as wrong, confusing or broken" />
      <div className="container mx-auto max-w-[1000px] px-6 py-6 space-y-4">
        <div className="flex flex-wrap gap-2">
          {FILTERS.map(f => (
            <button
              key={f.key} onClick={() => setFilter(f.key)}
              className={cn(
                "rounded-lg border px-3 py-1.5 text-xs font-semibold transition",
                filter === f.key
                  ? "border-cyber-500/50 bg-cyber-500/10 text-cyber-300"
                  : "border-border text-slate-400 hover:text-white",
              )}
            >
              {f.label}
            </button>
          ))}
        </div>

        {error && (
          <div className="flex items-center gap-2 rounded-lg border border-severity-high/40 bg-severity-high/10 px-4 py-3 text-sm text-severity-high">
            <AlertTriangle className="h-4 w-4" />{error}
          </div>
        )}

        {loading ? (
          <div className="flex items-center gap-2 text-sm text-slate-400"><Loader2 className="h-4 w-4 animate-spin" /> Loading…</div>
        ) : items.length === 0 ? (
          <Card>
            <p className="flex items-center gap-2 text-sm text-slate-400">
              <Flag className="h-4 w-4" /> Nothing here. Reports students file from a room or scenario land in this inbox.
            </p>
          </Card>
        ) : (
          <div className="space-y-3">
            {items.map(r => (
              <Card key={r.id}>
                <div className="mb-2 flex flex-wrap items-center gap-2">
                  <span className={cn("rounded-full border px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider", STATUS_STYLE[r.status])}>
                    {r.status}
                  </span>
                  <span className="rounded border border-border px-1.5 py-0.5 font-mono text-[10px] text-slate-400">
                    {r.target_kind}
                  </span>
                  <span className="font-mono text-[11px] text-slate-300">{r.target_id}</span>
                  <span className="ml-auto text-[11px] text-slate-500">
                    {r.profiles?.display_name || r.profiles?.handle || "unknown"} · {new Date(r.created_at).toLocaleString("en-GB")}
                  </span>
                </div>

                <p className="whitespace-pre-wrap text-sm text-slate-200">{r.message}</p>

                {r.context && Object.keys(r.context).length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {Object.entries(r.context).map(([k, v]) => (
                      <span key={k} className="rounded bg-bg px-1.5 py-0.5 font-mono text-[10px] text-slate-400">
                        {k}: {v}
                      </span>
                    ))}
                  </div>
                )}

                <div className="mt-3 flex flex-wrap gap-1.5 border-t border-border/50 pt-2">
                  {(["triaged", "resolved", "wontfix", "new"] as Status[])
                    .filter(s => s !== r.status)
                    .map(s => (
                      <button key={s} onClick={() => setStatus(r.id, s)}
                        className="rounded border border-border px-2 py-1 text-[11px] text-slate-400 transition hover:text-white">
                        Mark {s}
                      </button>
                    ))}
                </div>
              </Card>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
