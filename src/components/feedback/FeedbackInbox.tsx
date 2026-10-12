"use client";
/**
 * Feedback / reports triage inbox — the shared body used by BOTH the platform
 * admin page (/admin/feedback) and the super-admin console (/superadmin/feedback).
 * Reads and triages via /api/feedback, which accepts a platform admin OR the platform
 * super-admin.
 *
 * Each card answers three questions in order: WHERE is the problem (kind, breadcrumb,
 * exact step, a link to open it — resolved server-side by lib/feedback/resolveLocation),
 * WHAT the learner had on screen, and WHAT they wrote (shown large, direction-aware so a
 * Hebrew message reads right-to-left). Technical extras (page, browser, ids) sit collapsed.
 */
import { useEffect, useMemo, useState } from "react";
import { fetchOrError } from "@/lib/http/safeFetch";
import { Card } from "@/components/ui/Card";
import {
  Flag, Loader2, AlertTriangle, Bug, Send, CheckCircle2, BookOpen, LayoutGrid, ListChecks,
  Crosshair, Activity, ExternalLink, Search, MapPin, Monitor, Copy,
} from "lucide-react";
import { cn } from "@/lib/utils";

type Status = "new" | "triaged" | "resolved" | "wontfix";

interface LocationView {
  kind: string;
  kindLabel: string;
  crumbs: string[];
  step?: string;
  shown?: string;
  href?: string;
  details: { label: string; value: string }[];
}

interface Report {
  id: string;
  target_kind: string;
  target_id: string;
  context: Record<string, string>;
  message: string;
  status: Status;
  created_at: string;
  admin_response?: string | null;
  responded_at?: string | null;
  profiles: { handle?: string; display_name?: string } | null;
  org?: { name?: string } | null;
  location?: LocationView;
}

const STATUSES: { key: Status | "all"; label: string }[] = [
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
const STATUS_LABEL: Record<Status, string> = { new: "New", triaged: "Triaged", resolved: "Resolved", wontfix: "Won't fix" };
const STATUS_ACTION: Record<Status, string> = { new: "Reopen", triaged: "Mark triaged", resolved: "Resolve", wontfix: "Won't fix" };

const KINDS: { key: string; label: string; icon: typeof Bug; tone: string }[] = [
  { key: "room_task", label: "Learning rooms", icon: LayoutGrid, tone: "border-neon-purple/40 bg-neon-purple/10 text-neon-purple" },
  { key: "lesson",    label: "Lessons",        icon: BookOpen,   tone: "border-cyber-500/40 bg-cyber-500/10 text-cyber-300" },
  { key: "quiz",      label: "Quizzes",        icon: ListChecks, tone: "border-neon-blue/40 bg-neon-blue/10 text-neon-blue" },
  { key: "scenario",  label: "Scenarios",      icon: Crosshair,  tone: "border-neon-green/40 bg-neon-green/10 text-neon-green" },
  { key: "dashboard", label: "Live SOC feed",  icon: Activity,   tone: "border-severity-high/40 bg-severity-high/10 text-severity-high" },
  { key: "technical", label: "Technical",      icon: Bug,        tone: "border-neon-amber/40 bg-neon-amber/10 text-neon-amber" },
];
const kindOf = (r: Report) => r.location?.kind ?? (r.context?.category === "technical" || r.target_id === "technical" ? "technical" : r.target_kind);
const kindMeta = (k: string) => KINDS.find(x => x.key === k) ?? { key: k, label: k, icon: Flag, tone: "border-border text-slate-400" };

function relTime(iso: string): string {
  const s = Math.max(0, (Date.now() - Date.parse(iso)) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  if (s < 86400 * 30) return `${Math.floor(s / 86400)} d ago`;
  return new Date(iso).toLocaleDateString("en-GB");
}

export function FeedbackInbox() {
  const [items, setItems] = useState<Report[]>([]);
  const [status, setStatusFilter] = useState<Status | "all">("new");
  const [kind, setKind] = useState<string>("all");
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  const [sending, setSending] = useState<string | null>(null);
  const [notes, setNotes] = useState<Record<string, { ok: boolean; text: string }>>({});

  // One load of the latest reports (every status), so the tabs can show counts and
  // filtering is instant; a status change updates the list in place.
  async function load() {
    setLoading(true); setError(null);
    const res = await fetchOrError(`/api/feedback?status=all`);
    setLoading(false);
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Failed to load."); return; }
    setItems((await res.json()).items ?? []);
  }
  useEffect(() => { void load(); }, []);

  async function setStatus(id: string, next: Status) {
    const before = items.find(r => r.id === id)?.status;
    setItems(prev => prev.map(r => (r.id === id ? { ...r, status: next } : r)));
    const res = await fetchOrError("/api/feedback", {
      method: "PATCH", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id, status: next }),
    });
    if (!res.ok) {
      // E-23: the server refused — put the old status back and say so.
      if (before) setItems(prev => prev.map(r => (r.id === id ? { ...r, status: before } : r)));
      setError((await res.json().catch(() => ({})))?.error ?? "Couldn't update the status — please try again.");
    }
  }

  async function sendReply(id: string) {
    const message = (drafts[id] ?? "").trim();
    if (!message) return;
    setSending(id);
    setNotes(n => { const c = { ...n }; delete c[id]; return c; });
    let res: Response;
    try {
      res = await fetchOrError(`/api/feedback/${id}/reply`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message }),
      });
    } catch {
      setSending(null);
      setNotes(n => ({ ...n, [id]: { ok: false, text: "Network error — reply not sent." } }));
      return;
    }
    setSending(null);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      setNotes(n => ({ ...n, [id]: { ok: false, text: data?.error ?? "Failed to send reply." } }));
      return;
    }
    setItems(prev => prev.map(r => (r.id === id
      ? { ...r, admin_response: message, responded_at: new Date().toISOString(), status: "resolved" as Status }
      : r)));
    setDrafts(d => { const c = { ...d }; delete c[id]; return c; });
    setNotes(n => ({ ...n, [id]: {
      ok: true,
      text: data.emailed
        ? "Reply emailed to the reporter and marked resolved."
        : "Reply saved and marked resolved — but email delivery is not configured, so the reporter was NOT emailed.",
    } }));
  }

  // Reports on the same spot (same kind + target), so a recurring problem stands out.
  const sameSpot = useMemo(() => {
    const m = new Map<string, number>();
    for (const r of items) if (kindOf(r) !== "technical") m.set(`${r.target_kind}|${r.target_id}`, (m.get(`${r.target_kind}|${r.target_id}`) ?? 0) + 1);
    return m;
  }, [items]);

  const byStatus = useMemo(() => {
    const c: Record<string, number> = { all: items.length };
    for (const r of items) c[r.status] = (c[r.status] ?? 0) + 1;
    return c;
  }, [items]);

  const inStatus = items.filter(r => status === "all" || r.status === status);
  const byKind = useMemo(() => {
    const c: Record<string, number> = { all: inStatus.length };
    for (const r of inStatus) c[kindOf(r)] = (c[kindOf(r)] ?? 0) + 1;
    return c;
  }, [inStatus]);

  const q = query.trim().toLowerCase();
  const visible = inStatus.filter(r => (kind === "all" || kindOf(r) === kind) && (!q || [
    r.message, r.location?.crumbs.join(" "), r.location?.step, r.location?.shown,
    r.profiles?.display_name, r.profiles?.handle, r.org?.name,
  ].some(v => v?.toLowerCase().includes(q))));

  return (
    <div className="space-y-4">
      {/* Status tabs with counts */}
      <div className="flex flex-wrap items-center gap-2">
        {STATUSES.map(s => (
          <button
            key={s.key} onClick={() => setStatusFilter(s.key)}
            className={cn(
              "inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-semibold transition",
              status === s.key ? "border-cyber-500/50 bg-cyber-500/10 text-cyber-300" : "border-border text-slate-400 hover:text-white",
            )}
          >
            {s.label}
            <span className="rounded bg-bg px-1.5 font-mono text-[10px] text-slate-400">{byStatus[s.key] ?? 0}</span>
          </button>
        ))}
        <label className="relative ml-auto w-full sm:w-64">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" aria-hidden="true" />
          <input
            id="feedback-search" value={query} onChange={e => setQuery(e.target.value)} dir="auto"
            placeholder="Search message, place, reporter…" aria-label="Search reports"
            className="w-full rounded-lg border border-border bg-bg py-1.5 pl-8 pr-3 text-xs text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none"
          />
        </label>
      </div>

      {/* Kind filter */}
      <div className="flex flex-wrap gap-1.5">
        <button onClick={() => setKind("all")}
          className={cn("rounded-full border px-2.5 py-1 text-[11px] transition", kind === "all" ? "border-cyber-500/50 bg-cyber-500/10 text-cyber-300" : "border-border text-slate-400 hover:text-white")}>
          Everything · {byKind.all ?? 0}
        </button>
        {KINDS.filter(k => byKind[k.key]).map(k => {
          const Icon = k.icon;
          return (
            <button key={k.key} onClick={() => setKind(k.key)}
              className={cn("inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-[11px] transition", kind === k.key ? k.tone : "border-border text-slate-400 hover:text-white")}>
              <Icon className="h-3 w-3" aria-hidden="true" /> {k.label} · {byKind[k.key]}
            </button>
          );
        })}
      </div>

      {error && (
        <div className="flex items-center gap-2 rounded-lg border border-severity-high/40 bg-severity-high/10 px-4 py-3 text-sm text-severity-high">
          <AlertTriangle className="h-4 w-4" />{error}
        </div>
      )}

      {loading ? (
        <div className="flex items-center gap-2 text-sm text-slate-400"><Loader2 className="h-4 w-4 animate-spin" /> Loading…</div>
      ) : visible.length === 0 ? (
        <Card>
          <p className="flex items-center gap-2 text-sm text-slate-400">
            <Flag className="h-4 w-4" />
            {items.length === 0
              ? "No reports yet. Content reports (from a lesson, room, quiz, scenario or the live feed) and technical problem reports all land here."
              : "No reports match these filters."}
          </p>
        </Card>
      ) : (
        <div className="space-y-3">
          {visible.map(r => {
            const loc = r.location;
            const km = kindMeta(kindOf(r));
            const KindIcon = km.icon;
            const dupes = (sameSpot.get(`${r.target_kind}|${r.target_id}`) ?? 1) - 1;
            const reporter = r.profiles?.display_name || r.profiles?.handle || "Unknown learner";
            return (
              <Card key={r.id} className="space-y-3">
                {/* 1. Kind, status, reporter */}
                <div className="flex flex-wrap items-center gap-2">
                  <span className={cn("inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-semibold", km.tone)}>
                    <KindIcon className="h-3 w-3" aria-hidden="true" /> {loc?.kindLabel ?? km.label}
                  </span>
                  <span className={cn("rounded-full border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider", STATUS_STYLE[r.status])}>
                    {STATUS_LABEL[r.status]}
                  </span>
                  {dupes > 0 && (
                    <button type="button" onClick={() => { setStatusFilter("all"); setKind(kindOf(r)); setQuery(loc?.crumbs.at(-1) ?? ""); }}
                      className="rounded-full border border-severity-high/40 bg-severity-high/10 px-2 py-0.5 text-[10px] font-semibold text-severity-high hover:bg-severity-high/20"
                      title="Show every report on this spot">
                      +{dupes} more on this spot
                    </button>
                  )}
                  <span className="ml-auto text-[11px] text-slate-400" title={new Date(r.created_at).toLocaleString("en-GB")}>
                    <bdi className="font-semibold text-slate-200">{reporter}</bdi>
                    {r.org?.name && <> · <bdi>{r.org.name}</bdi></>} · {relTime(r.created_at)}
                  </span>
                </div>

                {/* 2. Where */}
                <div className="flex items-start gap-2 rounded-lg border border-border bg-bg px-3 py-2">
                  <MapPin className="mt-0.5 h-4 w-4 flex-shrink-0 text-cyber-400" aria-hidden="true" />
                  <div className="min-w-0 flex-1">
                    <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Where</p>
                    <p className="text-sm text-slate-300" dir="auto">
                      {(loc?.crumbs ?? [r.target_id]).map((c, i, arr) => (
                        <span key={i}>
                          <bdi className={i === arr.length - 1 ? "font-semibold text-white" : ""}>{c}</bdi>
                          {i < arr.length - 1 && <span className="mx-1 text-slate-600">›</span>}
                        </span>
                      ))}
                    </p>
                    {loc?.step && <p className="mt-0.5 text-xs font-semibold text-cyber-300">{loc.step}</p>}
                  </div>
                  {loc?.href && (
                    <a href={loc.href} target="_blank" rel="noopener noreferrer"
                      className="inline-flex flex-shrink-0 items-center gap-1 rounded-md border border-border px-2 py-1 text-[11px] text-slate-300 hover:border-cyber-500/50 hover:text-white">
                      Open <ExternalLink className="h-3 w-3" aria-hidden="true" />
                    </a>
                  )}
                </div>

                {/* 3. What was on screen */}
                {loc?.shown && (
                  <div>
                    <p className="mb-1 flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                      <Monitor className="h-3 w-3" aria-hidden="true" /> On screen
                    </p>
                    <p className="line-clamp-3 border-l-2 border-border pl-3 text-xs leading-relaxed text-slate-400" dir="auto" title={loc.shown}>
                      {loc.shown}
                    </p>
                  </div>
                )}

                {/* 4. What the learner wrote */}
                <div>
                  <p className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-slate-500">The learner wrote</p>
                  <p className="whitespace-pre-wrap rounded-lg border-l-4 border-neon-amber/60 bg-neon-amber/5 px-3 py-2 text-[15px] leading-relaxed text-white" dir="auto">
                    {r.message}
                  </p>
                </div>

                {/* 5. Technical details (collapsed) */}
                {loc && loc.details.length > 0 && (
                  <details className="group text-[11px] text-slate-400">
                    <summary className="cursor-pointer select-none text-slate-500 hover:text-slate-300">Technical details</summary>
                    <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
                      {loc.details.map(d => (
                        <div key={d.label} className="contents">
                          <dt className="text-slate-500">{d.label}</dt>
                          <dd className="flex min-w-0 items-center gap-1 font-mono text-slate-300">
                            <span className="truncate">{d.value}</span>
                            <button type="button" onClick={() => { void navigator.clipboard?.writeText(d.value); }}
                              className="rounded p-0.5 text-slate-500 hover:text-white" aria-label={`Copy ${d.label}`}>
                              <Copy className="h-3 w-3" />
                            </button>
                          </dd>
                        </div>
                      ))}
                    </dl>
                  </details>
                )}

                {/* 6. Triage + reply */}
                <div className="flex flex-wrap gap-1.5 border-t border-border/50 pt-3">
                  {(["triaged", "resolved", "wontfix", "new"] as Status[])
                    .filter(s => s !== r.status)
                    .map(s => (
                      <button key={s} onClick={() => setStatus(r.id, s)}
                        className="rounded border border-border px-2 py-1 text-[11px] text-slate-400 transition hover:text-white">
                        {STATUS_ACTION[s]}
                      </button>
                    ))}
                </div>

                {r.admin_response ? (
                  <div className="rounded-lg border border-neon-green/30 bg-neon-green/5 px-3 py-2">
                    <p className="flex items-center gap-1.5 text-[11px] font-semibold text-neon-green">
                      <CheckCircle2 className="h-3.5 w-3.5" /> Replied to the learner
                      {r.responded_at && <span className="font-normal text-slate-500">· {new Date(r.responded_at).toLocaleString("en-GB")}</span>}
                    </p>
                    <p className="mt-1 whitespace-pre-wrap text-sm text-slate-300" dir="auto">{r.admin_response}</p>
                  </div>
                ) : (
                  <div>
                    <textarea
                      id={`reply-${r.id}`}
                      value={drafts[r.id] ?? ""}
                      onChange={e => setDrafts(d => ({ ...d, [r.id]: e.target.value }))}
                      placeholder="Reply to the learner (emailed to them, and marks the report resolved)…"
                      rows={2} dir="auto" aria-label="Reply to the learner"
                      className="w-full resize-y rounded-lg border border-border bg-bg px-3 py-2 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none"
                    />
                    <button
                      onClick={() => sendReply(r.id)}
                      disabled={sending === r.id || !(drafts[r.id] ?? "").trim()}
                      className="mt-1.5 inline-flex items-center gap-1.5 rounded-lg border border-cyber-500/50 bg-cyber-500/10 px-3 py-1.5 text-[11px] font-semibold text-cyber-300 transition hover:bg-cyber-500/20 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      {sending === r.id ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Send className="h-3.5 w-3.5" />}
                      Send reply
                    </button>
                  </div>
                )}
                {notes[r.id] && (
                  <p className={cn("text-[11px]", notes[r.id].ok ? "text-neon-green" : "text-severity-high")}>{notes[r.id].text}</p>
                )}
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
