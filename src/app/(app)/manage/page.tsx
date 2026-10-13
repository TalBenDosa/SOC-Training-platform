"use client";
/**
 * Org-admin console — a college's own dashboard. Scoped entirely to the admin's
 * org by the /api/org/* routes (org id comes from their JWT, never the client),
 * so a college admin sees and touches only their own students.
 */
import { safeFetch, NETWORK_ERROR, fetchOrError } from "@/lib/http/safeFetch";
import { useEffect, useState } from "react";
import { Topbar } from "@/components/nav/Topbar";
import { usePageTitle } from "@/lib/hooks/usePageTitle";
import Link from "next/link";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import {
  Users, Activity, DoorOpen, Copy, AlertTriangle, Loader2, KeyRound,
  Power, PowerOff, Trash2, Download, TrendingDown, Building2, ChevronRight, Route, Search, Gauge, XCircle,
} from "lucide-react";
import type { OrgMember, OrgUsage } from "@/lib/org/types";
import type { StudentRow } from "@/app/api/org/analytics/route";
import { cohortPathProgress, studentPathPercent } from "@/lib/org/pathProgress";
import { LearningPlansPanel } from "@/components/manage/LearningPlansPanel";
import { GroupsPanel } from "@/components/manage/GroupsPanel";
import { MediaPanel } from "@/components/manage/MediaPanel";
import { ContentAuthoringPanel } from "@/components/manage/ContentAuthoringPanel";
import { SkillsPanel } from "@/components/manage/SkillsPanel";

type ManageTab = "students" | "overview" | "skills" | "mistakes" | "plans" | "content";
type SortKey = "xp" | "name" | "first_try" | "path" | "active";

interface OrgLite { id: string; name: string; slug: string; seat_limit: number; status: string; expires_at: string | null }
type Member = OrgMember & { xp?: number };

/** A student's right-to-deletion request awaiting this college's decision. */
interface DeletionRequest {
  id: string;
  user_id: string;
  handle: string | null;
  display_name: string | null;
  reason: string | null;
  requested_at: string;
  days_open: number;
}

interface ClassStats {
  size: number;
  avg_scenario_score: number | null;
  avg_rooms_completed: number | null;
  total_rooms_completed: number;
  active_7d: number;
  never_started: number;
  dormant_14d: number;
  hardest_rooms: { room_id: string; title: string; started: number; completed: number; completion_rate: number }[];
}

/** "3d ago" / "just now" — an instructor scans for staleness, not exact timestamps. */
function sinceLabel(iso: string | null): string {
  if (!iso) return "never";
  const days = Math.floor((Date.now() - Date.parse(iso)) / 86_400_000);
  if (days <= 0) return "today";
  if (days === 1) return "1d ago";
  return `${days}d ago`;
}

/** RFC-4180-ish escaping: quote everything, double any inner quotes. */
function toCsv(rows: string[][]): string {
  return rows.map(r => r.map(c => `"${String(c ?? "").replace(/"/g, '""')}"`).join(",")).join("\r\n");
}

export default function ManagePage() {
  usePageTitle("Manage class");
  const [org, setOrg] = useState<OrgLite | null>(null);
  const [members, setMembers] = useState<Member[]>([]);
  const [usage, setUsage] = useState<OrgUsage | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  // cohort analytics (per-student progress + class signals)
  const [students, setStudents] = useState<StudentRow[]>([]);
  const [analyticsError, setAnalyticsError] = useState<string | null>(null);   // E-10: say it, don't show empty progress
  const [classStats, setClassStats] = useState<ClassStats | null>(null);

  // right-to-deletion requests filed by this college's students
  const [deletions, setDeletions] = useState<DeletionRequest[]>([]);
  // P5-08: a failed read must not look like "no requests" — each has a legal deadline.
  const [deletionsFailed, setDeletionsFailed] = useState(false);
  const [dBusy, setDBusy] = useState<string | null>(null);

  // class affiliation code (0028) — the live code + when a new one is allowed
  const [classCode, setClassCode] = useState<{ code: string; expires_at: string } | null>(null);
  const [codeNextAt, setCodeNextAt] = useState<string | null>(null);
  const [codeBusy, setCodeBusy] = useState(false);

  // Bumped by the Groups panel so the Learning plans recipients picker refetches.
  const [groupsRev, setGroupsRev] = useState(0);

  // Tabs + the Students tab's search / filter / sort.
  const [tab, setTab] = useState<ManageTab>("students");
  const [query, setQuery] = useState("");
  const [view, setView] = useState<"all" | "attention" | "inactive">("all");
  const [sortBy, setSortBy] = useState<SortKey>("xp");

  async function load() {
    setError(null);
    const res = await safeFetch("/api/org/members");
    setLoading(false);
    if (!res) { setError(NETWORK_ERROR); return; }
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Failed to load."); return; }
    const data = await res.json();
    setOrg(data.org); setMembers(data.members); setUsage(data.usage);
    // Per-student progress + class signals. Separate call so the roster still
    // renders if analytics is slow or unavailable.
    const anRes = await safeFetch("/api/org/analytics");
    if (anRes?.ok) {
      const { students: rows, class: cls } = await anRes.json();
      setStudents(rows ?? []);
      setClassStats(cls ?? null);
      setAnalyticsError(null);
    } else {
      setAnalyticsError("Couldn't load your students' progress just now — the roster is shown, progress columns may be empty. Refresh to try again.");
    }
    // Right-to-deletion queue. Separate call for the same reason as analytics:
    // the roster must still render if this is slow or the table isn't migrated
    // yet on a given deployment.
    const dlRes = await safeFetch("/api/org/deletion-requests");
    if (dlRes?.ok) {
      const { requests } = await dlRes.json();
      setDeletions(requests ?? []);
      setDeletionsFailed(false);
    } else {
      setDeletionsFailed(true);
    }
    const ccRes = await safeFetch("/api/org/class-code");
    if (ccRes?.ok) {
      const cc = await ccRes.json();
      setClassCode(cc.active ?? null);
      setCodeNextAt(cc.next_generate_at ?? null);
    }
  }

  async function generateClassCode() {
    setCodeBusy(true);
    const res = await safeFetch("/api/org/class-code", { method: "POST" });
    setCodeBusy(false);
    if (!res) { setError(NETWORK_ERROR); return; }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { setError(data?.error ?? "Could not generate a code."); return; }
    setClassCode(data.active ?? null);
    // The cooldown starts from this generation.
    const ccRes = await safeFetch("/api/org/class-code");
    if (ccRes?.ok) { const cc = await ccRes.json(); setCodeNextAt(cc.next_generate_at ?? null); }
    setNotice("New class code generated — valid for 24 hours.");
  }
  useEffect(() => { load(); }, []);

  /** Grade sheet for the college's own records / their LMS. */
  function exportCsv() {
    const header = [
      "Student", "Handle", "Status", "Role", "XP", "Level",
      "Rooms completed", "Rooms started", "Right first try %", "Questions answered", "Scenarios completed", "Avg scenario score",
      "Dashboard sessions", "Avg detect rate %", "Last active", "Enrolment valid until",
    ];
    const body = students.map(s => [
      s.display_name ?? s.handle ?? s.user_id.slice(0, 8),
      s.handle ?? "", s.status, s.role, String(s.xp), String(s.level),
      String(s.rooms_completed), String(s.rooms_started),
      s.task_accuracy === null ? "" : String(s.task_accuracy), String(s.tasks_graded),
      String(s.scenarios_completed), s.scenario_avg_score === null ? "" : String(s.scenario_avg_score),
      String(s.sessions), s.avg_detect_rate === null ? "" : String(s.avg_detect_rate),
      s.last_active_at ?? "",
      s.affiliation_expires_at ?? "",
    ]);
    const blob = new Blob([toCsv([header, ...body])], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${org?.slug ?? "class"}-progress-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  async function setActive(userId: string, active: boolean) {
    setError(null);
    const res = await fetchOrError("/api/org/members", {
      method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ user_id: userId, active }),
    });
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Failed to update status."); return; }
    const notRevoked = (await res.json().catch(() => ({})))?.sessions_revoked === false;
    await load();
    if (notRevoked) setError("Deactivated — but their open sessions couldn't be ended right now, so they may stay signed in for up to an hour.");
  }

  async function removeMember(userId: string) {
    if (!confirm("Permanently remove this student from your class? Their class data is detached. This can't be undone.")) return;
    const res = await fetchOrError("/api/org/members", {
      method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ user_id: userId }),
    });
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Failed to remove."); return; }
    const notRevoked = (await res.json().catch(() => ({})))?.sessions_revoked === false;
    await load();
    if (notRevoked) setError("Removed — but their open sessions couldn't be ended right now, so they may stay signed in for up to an hour.");
  }

  /**
   * Decide a right-to-deletion request. Approving ERASES the student's account
   * and everything cascading from it — hence the explicit confirm naming the
   * student, separate from the generic "remove from class" above, which only
   * detaches them and leaves the account intact.
   */
  async function decideDeletion(r: DeletionRequest, decision: "approve" | "reject") {
    const who = r.display_name || r.handle || "this student";
    if (decision === "approve" && !confirm(
      `Permanently erase ${who}'s account and all of their learning data?\n\n` +
      `This satisfies their legal deletion request and CANNOT be undone. ` +
      `Their results will no longer appear in your class records.`,
    )) return;

    setDBusy(r.id);
    const res = await fetchOrError("/api/org/deletion-requests", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: r.id, decision }),
    });
    setDBusy(null);
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Failed to action the request."); return; }
    setNotice(decision === "approve" ? `${who}'s account was deleted.` : `Request from ${who} was declined.`);
    await load();
  }

  const active = members.filter(m => m.status === "active");
  // Active first, then by XP.
  const roster = [...members].sort((a, b) =>
    (a.status === "active" ? 0 : 1) - (b.status === "active" ? 0 : 1) || (b.xp ?? 0) - (a.xp ?? 0),
  );

  // Cohort position along the graded path (Foundations → SOC Tier 1 → Advanced),
  // computed client-side from each student's completed_room_ids + ROOMS_META.
  const pathProg = cohortPathProgress(students);
  const overallPathPct = students.length
    ? Math.round(students.reduce((s, st) => s + studentPathPercent(st.completed_room_ids), 0) / students.length)
    : 0;

  // Who needs attention, and WHY — one list feeds both the count and the names, so they
  // always agree. Weak = under 60% right on the first try, judged only with 10+ questions.
  const reasonsFor = (s: StudentRow): string[] => {
    if (s.status !== "active") return [];
    const r: string[] = [];
    if (s.rooms_started === 0 && s.scenarios_completed === 0 && s.sessions === 0) r.push("not started");
    else if (s.last_active_at && Date.now() - Date.parse(s.last_active_at) >= 14 * 86_400_000) r.push(`quiet ${Math.floor((Date.now() - Date.parse(s.last_active_at)) / 86_400_000)} days`);
    if (s.task_accuracy !== null && s.tasks_graded >= 10 && s.task_accuracy < 60) r.push(`${s.task_accuracy}% right first try`);
    if (s.tasks_unsolved >= 5) r.push(`${s.tasks_unsolved} questions still unsolved`);
    return r;
  };
  const atRisk = students.map(s => ({ s, why: reasonsFor(s) })).filter(x => x.why.length > 0);
  const graded = students.filter(s => s.status === "active" && s.task_accuracy !== null && s.tasks_graded >= 5);
  const classFirstTry = graded.length ? Math.round(graded.reduce((n, s) => n + (s.task_accuracy ?? 0), 0) / graded.length) : null;

  // Students tab: search, filter, sort.
  const statOf = (id: string) => students.find(x => x.user_id === id);
  const q = query.trim().toLowerCase();
  const riskIds = new Set(atRisk.map(x => x.s.user_id));
  const sortVal = (m: Member): number | string => {
    const s = statOf(m.user_id);
    switch (sortBy) {
      case "name": return (m.display_name || m.handle || "").toLowerCase();
      case "first_try": return s?.task_accuracy ?? -1;
      case "path": return s ? studentPathPercent(s.completed_room_ids) : -1;
      case "active": return s?.last_active_at ? Date.parse(s.last_active_at) : 0;
      default: return m.xp ?? 0;
    }
  };
  const visibleRoster = roster
    .filter(m => view === "all" ? true : view === "attention" ? riskIds.has(m.user_id) : m.status !== "active")
    .filter(m => !q || [m.display_name, m.handle, statOf(m.user_id)?.email].some(v => v?.toLowerCase().includes(q)))
    .sort((a, b) => {
      const x = sortVal(a), y = sortVal(b);
      return sortBy === "name" ? String(x).localeCompare(String(y)) : (y as number) - (x as number);
    });

  const codeCoolingDown = Boolean(codeNextAt && new Date(codeNextAt) > new Date());

  return (
    <div>
      <Topbar title={org ? `Manage: ${org.name}` : "Manage class"} subtitle="Your students and their progress" />
      <div className="container mx-auto max-w-[1100px] space-y-5 px-6 py-6">
        {error && <div className="flex items-center gap-2 rounded-lg border border-severity-high/40 bg-severity-high/10 px-4 py-3 text-sm text-severity-high"><AlertTriangle className="h-4 w-4" />{error}</div>}
        {notice && <div className="rounded-lg border border-neon-green/30 bg-neon-green/10 px-4 py-3 text-sm text-neon-green">{notice}</div>}

        {loading ? (
          <div className="flex items-center gap-2 text-sm text-slate-400"><Loader2 className="h-4 w-4 animate-spin" /> Loading…</div>
        ) : (
          <>
            {/* College + class code: one card (it used to appear twice). */}
            <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-neon-cyan/30 bg-neon-cyan/[0.05] px-5 py-4">
              <div className="flex min-w-0 items-center gap-3">
                <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg border border-neon-cyan/30 bg-neon-cyan/10">
                  <Building2 className="h-5 w-5 text-neon-cyan" />
                </span>
                <div className="min-w-0">
                  <p className="text-[10px] uppercase tracking-wider text-slate-400">College</p>
                  <p className="truncate text-lg font-bold text-white"><bdi>{org?.name ?? "n/a"}</bdi></p>
                  <p className="text-[11px] text-slate-400">{active.length}{org && org.seat_limit > 0 ? ` of ${org.seat_limit} seats` : ""} active students</p>
                </div>
              </div>
              <div className="flex flex-wrap items-center gap-3">
                <div className="text-right">
                  <p className="flex items-center justify-end gap-1 text-[10px] uppercase tracking-wider text-slate-400"><KeyRound className="h-3 w-3" /> Class code</p>
                  {classCode ? (
                    <>
                      <p className="font-mono text-xl font-bold tracking-[0.3em] text-neon-cyan">{classCode.code}</p>
                      <p className="text-[10px] text-slate-500">expires {new Date(classCode.expires_at).toLocaleString("en-GB")} · enrolment lasts 100 days</p>
                    </>
                  ) : <p className="text-sm text-slate-400">No live code</p>}
                </div>
                {classCode && (
                  <Button variant="outline" size="sm" aria-label="Copy class code"
                    // P5-18: only claim "copied" once the clipboard write actually resolves
                    onClick={() => {
                      Promise.resolve().then(() => navigator.clipboard.writeText(classCode.code)).then(
                        () => setNotice("Class code copied."),
                        () => setError("Couldn't copy. Select the code and copy it manually."),
                      );
                    }}>
                    <Copy className="h-4 w-4" />
                  </Button>
                )}
                <Button variant="primary" size="sm" disabled={codeBusy || codeCoolingDown} onClick={generateClassCode}
                  title={codeCoolingDown && codeNextAt ? `Next code can be generated ${new Date(codeNextAt).toLocaleString("en-GB")}` : "Students register with their email and this code; it is valid for 24 hours"}>
                  {codeBusy ? "Generating…" : "Generate today's code"}
                </Button>
              </div>
            </div>

            {/* Right-to-deletion queue: above the tabs on purpose (30-day statutory deadline). */}
            {deletionsFailed && (
              <div role="alert" className="rounded-lg border border-severity-high/40 bg-severity-high/10 px-4 py-3 text-sm text-severity-high">
                Couldn&apos;t load your students&apos; account-deletion requests. Each one has a 30-day deadline, so reload the page to check them.
              </div>
            )}
            {deletions.length > 0 && (
              <Card className="border-neon-amber/40">
                <h2 className="flex items-center gap-2 text-sm font-bold text-white">
                  <AlertTriangle className="h-4 w-4 text-neon-amber" /> Account deletion requests ({deletions.length})
                </h2>
                <p className="mt-1.5 text-xs text-slate-400">
                  Students exercising their right to deletion under the Privacy Protection Law. You must answer within 30 days.
                  Approving <strong className="text-slate-300">permanently erases</strong> the account and removes their results from your class records.
                </p>
                <div className="mt-4 space-y-2">
                  {deletions.map(r => (
                    <div key={r.id} className="flex flex-wrap items-center gap-3 rounded-lg border border-border bg-bg-elevated px-3 py-2.5">
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm font-medium text-slate-100"><bdi>{r.display_name || r.handle || "Unnamed student"}</bdi></p>
                        <p className="text-xs text-slate-400">
                          Requested {sinceLabel(r.requested_at)}
                          {r.days_open > 30 ? (
                            <span className="ml-2 font-semibold text-severity-high">· overdue by {r.days_open - 30} day{r.days_open - 30 === 1 ? "" : "s"}</span>
                          ) : r.days_open >= 21 && (
                            <span className="ml-2 font-semibold text-neon-amber">· {30 - r.days_open} days left to answer</span>
                          )}
                        </p>
                        {r.reason && <p className="mt-1 text-xs italic text-slate-400" dir="auto">“{r.reason}”</p>}
                      </div>
                      <div className="flex gap-2">
                        <Button size="sm" variant="danger" disabled={dBusy === r.id} onClick={() => decideDeletion(r, "approve")}>{dBusy === r.id ? "Working…" : "Approve and erase"}</Button>
                        <Button size="sm" variant="ghost" disabled={dBusy === r.id} onClick={() => decideDeletion(r, "reject")}>Decline</Button>
                      </div>
                    </div>
                  ))}
                </div>
              </Card>
            )}

            {/* Tabs */}
            <div role="tablist" aria-label="Manage sections" className="flex flex-wrap gap-1 border-b border-border">
              {([
                ["students", "Students", Users, active.length],
                ["overview", "Class overview", Activity, atRisk.length],
                ["skills", "Skills", Gauge, null],
                ["mistakes", "Common mistakes", XCircle, null],
                ["plans", "Plans and groups", Route, null],
                ["content", "Content", DoorOpen, null],
              ] as const).map(([key, label, Icon, count]) => (
                <button key={key} role="tab" aria-selected={tab === key} onClick={() => setTab(key)}
                  className={`-mb-px inline-flex items-center gap-1.5 border-b-2 px-3 py-2 text-sm transition ${tab === key ? "border-cyber-400 font-semibold text-white" : "border-transparent text-slate-400 hover:text-white"}`}>
                  <Icon className="h-4 w-4" aria-hidden="true" /> {label}
                  {count !== null && count > 0 && (
                    <span className={`rounded px-1.5 font-mono text-[10px] ${key === "overview" ? "bg-neon-amber/15 text-neon-amber" : "bg-bg text-slate-400"}`}>{count}</span>
                  )}
                </button>
              ))}
            </div>

            {/* ── Students ─────────────────────────────────────────────── */}
            {tab === "students" && (
              <Card className="overflow-hidden p-0">
                <div className="flex flex-wrap items-center gap-2 px-4 py-3">
                  <label className="relative w-full sm:w-64">
                    <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" aria-hidden="true" />
                    <input id="roster-search" value={query} onChange={e => setQuery(e.target.value)} dir="auto" aria-label="Search students"
                      placeholder="Search name, handle or email"
                      className="w-full rounded-lg border border-border bg-bg py-1.5 pl-8 pr-3 text-xs text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
                  </label>
                  <div className="flex gap-1">
                    {([["all", "All"], ["attention", `Needs attention · ${atRisk.length}`], ["inactive", "Inactive"]] as const).map(([v, label]) => (
                      <button key={v} onClick={() => setView(v)}
                        className={`rounded-full border px-2.5 py-1 text-[11px] transition ${view === v ? "border-cyber-500/50 bg-cyber-500/10 text-cyber-300" : "border-border text-slate-400 hover:text-white"}`}>{label}</button>
                    ))}
                  </div>
                  <label className="ml-auto flex items-center gap-1.5 text-[11px] text-slate-400">
                    Sort by
                    <select id="roster-sort" value={sortBy} onChange={e => setSortBy(e.target.value as SortKey)}
                      className="rounded-md border border-border bg-bg px-2 py-1 text-xs text-slate-200">
                      <option value="xp">XP</option><option value="name">Name</option><option value="first_try">Right first try</option>
                      <option value="path">Path progress</option><option value="active">Last active</option>
                    </select>
                  </label>
                  {students.length > 0 && (
                    <Button variant="outline" size="sm" onClick={exportCsv}><Download className="mr-1.5 h-4 w-4" /> Export CSV</Button>
                  )}
                </div>
                {analyticsError && <p role="status" className="px-4 pb-2 text-xs text-neon-amber">{analyticsError}</p>}
                {roster.length === 0 ? (
                  <p className="px-4 pb-4 text-sm text-slate-400">No students yet. Share today&apos;s class code so they can register.</p>
                ) : visibleRoster.length === 0 ? (
                  <p className="px-4 pb-4 text-sm text-slate-400">No students match this search or filter.</p>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-sm">
                      <thead>
                        <tr className="border-y border-border text-[11px] uppercase tracking-wider text-slate-400">
                          <th className="px-4 py-2.5 font-medium">Student</th>
                          <th className="px-4 py-2.5 font-medium" title="Share of room questions answered correctly on the FIRST attempt. Retries and readings don't count.">Right first try</th>
                          <th className="px-4 py-2.5 font-medium" title="Share of the graded room curriculum completed (Foundations, SOC Tier 1, Advanced)">Path progress</th>
                          <th className="px-4 py-2.5 font-medium" title="Average share of attacks caught in the live SOC feed">Live feed detection</th>
                          <th className="px-4 py-2.5 font-medium">XP</th>
                          <th className="px-4 py-2.5 font-medium">Last active</th>
                          <th className="px-4 py-2.5 text-right font-medium">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-border/60">
                        {visibleRoster.map(m => {
                          const isActive = m.status === "active";
                          const s = statOf(m.user_id);
                          const why = s ? reasonsFor(s) : [];
                          return (
                            <tr key={m.user_id} className={`transition hover:bg-white/[0.02] ${isActive ? "" : "opacity-60"}`}>
                              <td className="px-4 py-2.5">
                                <Link href={`/manage/students/${m.user_id}`} className="group inline-flex items-center gap-1">
                                  <bdi className="font-medium text-white group-hover:text-cyber-300">{m.display_name || m.handle || m.user_id.slice(0, 8)}</bdi>
                                  <ChevronRight className="h-3.5 w-3.5 text-slate-500 transition group-hover:translate-x-0.5 group-hover:text-cyber-300" />
                                </Link>
                                <p className="font-mono text-[10px] text-slate-500">{s?.email ?? (m.handle ? `@${m.handle}` : "")}{isActive ? "" : " · inactive"}</p>
                                {why.length > 0 && <p className="mt-0.5 text-[10px] text-neon-amber">{why.join(" · ")}</p>}
                              </td>
                              <td className={`px-4 py-2.5 font-mono ${s && s.task_accuracy !== null && s.tasks_graded >= 5 && s.task_accuracy < 60 ? "text-severity-high" : "text-slate-200"}`}
                                title={s && s.tasks_graded ? `${s.task_accuracy}% of ${s.tasks_graded} questions right on the first try` : "No graded questions yet"}>
                                {s && s.task_accuracy !== null ? `${s.task_accuracy}%` : "n/a"}
                                {s && s.tasks_graded > 0 && <span className="ml-1 text-[10px] text-slate-500">of {s.tasks_graded}</span>}
                              </td>
                              <td className="px-4 py-2.5">
                                {s ? (
                                  <div className="flex items-center gap-2" title={`${s.rooms_completed} rooms completed`}>
                                    <span className="h-1.5 w-14 overflow-hidden rounded-full bg-bg"><span className="block h-full bg-cyber-500" style={{ width: `${studentPathPercent(s.completed_room_ids)}%` }} /></span>
                                    <span className="font-mono text-[11px] text-slate-400">{studentPathPercent(s.completed_room_ids)}%</span>
                                  </div>
                                ) : <span className="text-slate-500">n/a</span>}
                              </td>
                              <td className="px-4 py-2.5 font-mono text-[12px] text-slate-300">{s && s.avg_detect_rate !== null ? `${s.avg_detect_rate}%` : "n/a"}</td>
                              <td className="px-4 py-2.5 font-mono font-bold text-cyber-300">{(m.xp ?? 0).toLocaleString()}</td>
                              <td className={`px-4 py-2.5 text-[12px] ${!s?.last_active_at ? "text-slate-500" : Date.now() - Date.parse(s.last_active_at) >= 14 * 86_400_000 ? "text-neon-amber" : "text-slate-400"}`}>
                                {sinceLabel(s?.last_active_at ?? null)}
                              </td>
                              <td className="px-4 py-2.5">
                                <div className="flex items-center justify-end gap-1">
                                  {isActive ? (
                                    <button onClick={() => setActive(m.user_id, false)} aria-label={`Deactivate ${m.handle ?? "student"}`} title="Set inactive"
                                      className="rounded p-1.5 text-slate-400 transition hover:bg-neon-amber/10 hover:text-neon-amber"><PowerOff className="h-4 w-4" aria-hidden="true" /></button>
                                  ) : (
                                    <button onClick={() => setActive(m.user_id, true)} aria-label={`Activate ${m.handle ?? "student"}`} title="Set active"
                                      className="rounded p-1.5 text-slate-400 transition hover:bg-neon-green/10 hover:text-neon-green"><Power className="h-4 w-4" aria-hidden="true" /></button>
                                  )}
                                  <button onClick={() => removeMember(m.user_id)} aria-label={`Remove ${m.handle ?? "student"}`} title="Remove from class"
                                    className="rounded p-1.5 text-slate-400 transition hover:bg-severity-high/10 hover:text-severity-high"><Trash2 className="h-4 w-4" aria-hidden="true" /></button>
                                </div>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </Card>
            )}

            {/* ── Class overview ───────────────────────────────────────── */}
            {tab === "overview" && (
              <div className="space-y-5">
                <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                  <MiniStat label="Active this week" value={classStats ? `${classStats.active_7d}/${classStats.size}` : "n/a"} tone={classStats && classStats.active_7d === 0 ? "warn" : undefined} hint="did anything in the last 7 days" />
                  <MiniStat label="Right first try" value={classFirstTry === null ? "n/a" : `${classFirstTry}%`} tone={classFirstTry !== null && classFirstTry < 60 ? "warn" : undefined} hint={`class average, ${graded.length} students with 5+ questions`} />
                  <MiniStat label="Scenario score" value={classStats?.avg_scenario_score === null || !classStats ? "n/a" : `${classStats.avg_scenario_score}%`} hint={`${usage?.scenarios_completed ?? 0} scenarios completed`} />
                  <MiniStat label="Need attention" value={String(atRisk.length)} tone={atRisk.length > 0 ? "warn" : "good"} hint="see the list below" />
                </div>

                {atRisk.length > 0 && (
                  <Card className="border-neon-amber/30">
                    <h2 className="flex items-center gap-2 text-sm font-bold text-white"><AlertTriangle className="h-4 w-4 text-neon-amber" /> Students needing attention</h2>
                    <div className="mt-3 divide-y divide-border/60">
                      {atRisk.map(({ s, why }) => (
                        <Link key={s.user_id} href={`/manage/students/${s.user_id}`} className="group flex items-center gap-3 py-2 text-sm">
                          <bdi className="min-w-[140px] font-medium text-slate-100 group-hover:text-cyber-300">{s.display_name || s.handle || s.user_id.slice(0, 8)}</bdi>
                          <span className="flex-1 text-xs text-neon-amber">{why.join(" · ")}</span>
                          <ChevronRight className="h-4 w-4 text-slate-500 group-hover:text-cyber-300" />
                        </Link>
                      ))}
                    </div>
                  </Card>
                )}

                {students.length > 0 && (
                  <Card>
                    <div className="mb-3 flex items-center justify-between">
                      <h2 className="flex items-center gap-2 text-sm font-bold text-white"><Route className="h-4 w-4 text-cyber-300" /> The class along the path</h2>
                      <span className="font-mono text-xs text-slate-400">{overallPathPct}% of the curriculum on average</span>
                    </div>
                    <div className="space-y-2.5">
                      {pathProg.map(st => (
                        <div key={st.stage} className="flex items-center gap-3">
                          <span className="w-28 shrink-0 text-xs text-slate-300">{st.stage}</span>
                          <span className="h-2 flex-1 overflow-hidden rounded-full bg-bg"><span className={`block h-full ${st.stage === "Foundations" ? "bg-neon-green" : "bg-cyber-500"}`} style={{ width: `${st.percent}%` }} /></span>
                          <span className="w-20 shrink-0 text-right font-mono text-[11px] text-slate-400">{st.percent}% <span className="text-slate-500">· {st.roomCount} rooms</span></span>
                        </div>
                      ))}
                    </div>
                  </Card>
                )}

                {classStats && classStats.hardest_rooms.length > 0 && (
                  <Card>
                    <h2 className="mb-2 flex items-center gap-2 text-sm font-bold text-white"><TrendingDown className="h-4 w-4 text-severity-high" /> Where the class gets stuck</h2>
                    <ul className="space-y-1.5">
                      {classStats.hardest_rooms.map(r => (
                        <li key={r.room_id} className="flex items-center gap-3 text-xs">
                          <span className="min-w-0 flex-1 truncate text-slate-200">{r.title}</span>
                          <span className="shrink-0 font-mono text-[11px] text-slate-400">{r.completed} of {r.started} finished</span>
                          <span className={`shrink-0 font-mono text-[11px] font-bold ${r.completion_rate < 50 ? "text-severity-high" : "text-neon-amber"}`}>{r.completion_rate}%</span>
                        </li>
                      ))}
                    </ul>
                    <p className="mt-2 text-[10px] text-slate-500">Rooms at least 3 students opened, ranked by how few finished them.</p>
                  </Card>
                )}

                <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                  <MiniStat label="Total XP" value={(usage?.total_xp ?? 0).toLocaleString()} />
                  <MiniStat label="Live feed shifts" value={String(usage?.sessions ?? 0)} />
                  <MiniStat label="Rooms completed" value={String(usage?.rooms_completed ?? 0)} />
                  <MiniStat label="Scenarios completed" value={String(usage?.scenarios_completed ?? 0)} />
                </div>
              </div>
            )}

            {/* ── Skills / common mistakes ─────────────────────────────── */}
            {tab === "skills" && <SkillsPanel mode="skills" />}
            {tab === "mistakes" && <SkillsPanel mode="mistakes" />}

            {/* ── Plans and groups ─────────────────────────────────────── */}
            {tab === "plans" && (
              <div className="space-y-5">
                <LearningPlansPanel members={members} groupsRev={groupsRev} />
                <GroupsPanel members={members} onChanged={() => setGroupsRev(r => r + 1)} />
              </div>
            )}

            {/* ── Content ──────────────────────────────────────────────── */}
            {tab === "content" && (
              <div className="space-y-5">
                <MediaPanel />
                <ContentAuthoringPanel />
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

function MiniStat({ label, value, tone, hint }: { label: string; value: string; tone?: "good" | "warn"; hint?: string }) {
  return (
    <div className="rounded-lg border border-border bg-bg px-3 py-2.5">
      <p className="text-[10px] uppercase tracking-wider text-slate-400">{label}</p>
      <p className={`mt-0.5 font-mono text-lg font-bold ${tone === "warn" ? "text-neon-amber" : tone === "good" ? "text-neon-green" : "text-white"}`}>{value}</p>
      {hint && <p className="mt-0.5 text-[10px] text-slate-500">{hint}</p>}
    </div>
  );
}
