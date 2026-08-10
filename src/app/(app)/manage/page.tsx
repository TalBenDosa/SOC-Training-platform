"use client";
/**
 * Org-admin console — a college's own dashboard. Scoped entirely to the admin's
 * org by the /api/org/* routes (org id comes from their JWT, never the client),
 * so a college admin sees and touches only their own students.
 */
import { useEffect, useState } from "react";
import { Topbar } from "@/components/nav/Topbar";
import { usePageTitle } from "@/lib/hooks/usePageTitle";
import Link from "next/link";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import {
  Users, Trophy, Activity, Target, DoorOpen, UserPlus, Link2, Copy, Check, AlertTriangle, Loader2, Upload, Mail, KeyRound,
  Power, PowerOff, Trash2, Download, TrendingDown, Clock, ClipboardList, Plus, X, CalendarClock,
  Building2, ChevronRight, CalendarDays,
} from "lucide-react";
import type { OrgMember, OrgUsage } from "@/lib/org/types";
import type { StudentRow } from "@/app/api/org/analytics/route";
import type { AssignmentRow, AssignmentItem } from "@/app/api/org/assignments/route";

interface CatalogItem { kind: "room" | "scenario"; id: string; title: string; group: string; difficulty: string }

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

  const [email, setEmail] = useState("");
  const [adding, setAdding] = useState(false);

  // bulk invite (CSV / pasted list)
  const [bulkText, setBulkText] = useState("");
  const [bulkBusy, setBulkBusy] = useState(false);
  const [bulkResult, setBulkResult] = useState<string | null>(null);

  // cohort analytics (per-student progress + class signals)
  const [students, setStudents] = useState<StudentRow[]>([]);
  const [classStats, setClassStats] = useState<ClassStats | null>(null);

  // assignments (instructor-set coursework)
  const [assignments, setAssignments] = useState<AssignmentRow[]>([]);
  const [catalog, setCatalog] = useState<CatalogItem[]>([]);
  const [showNew, setShowNew] = useState(false);
  const [aTitle, setATitle] = useState("");
  const [aDue, setADue] = useState("");
  const [aInstructions, setAInstructions] = useState("");
  const [aItems, setAItems] = useState<AssignmentItem[]>([]);
  const [aSearch, setASearch] = useState("");
  const [aBusy, setABusy] = useState(false);

  // right-to-deletion requests filed by this college's students
  const [deletions, setDeletions] = useState<DeletionRequest[]>([]);
  const [dBusy, setDBusy] = useState<string | null>(null);

  // class affiliation code (0028) — the live code + when a new one is allowed
  const [classCode, setClassCode] = useState<{ code: string; expires_at: string } | null>(null);
  const [codeNextAt, setCodeNextAt] = useState<string | null>(null);
  const [codeBusy, setCodeBusy] = useState(false);

  async function load() {
    setError(null);
    const res = await fetch("/api/org/members");
    setLoading(false);
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Failed to load."); return; }
    const data = await res.json();
    setOrg(data.org); setMembers(data.members); setUsage(data.usage);
    // Per-student progress + class signals. Separate call so the roster still
    // renders if analytics is slow or unavailable.
    const anRes = await fetch("/api/org/analytics");
    if (anRes.ok) {
      const { students: rows, class: cls } = await anRes.json();
      setStudents(rows ?? []);
      setClassStats(cls ?? null);
    }
    const asRes = await fetch("/api/org/assignments");
    if (asRes.ok) {
      const { assignments: rows, catalog: cat } = await asRes.json();
      setAssignments(rows ?? []);
      setCatalog(cat ?? []);
    }
    // Right-to-deletion queue. Separate call for the same reason as analytics:
    // the roster must still render if this is slow or the table isn't migrated
    // yet on a given deployment.
    const dlRes = await fetch("/api/org/deletion-requests");
    if (dlRes.ok) {
      const { requests } = await dlRes.json();
      setDeletions(requests ?? []);
    }
    const ccRes = await fetch("/api/org/class-code");
    if (ccRes.ok) {
      const cc = await ccRes.json();
      setClassCode(cc.active ?? null);
      setCodeNextAt(cc.next_generate_at ?? null);
    }
  }

  async function generateClassCode() {
    setCodeBusy(true);
    const res = await fetch("/api/org/class-code", { method: "POST" });
    setCodeBusy(false);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { setError(data?.error ?? "Could not generate a code."); return; }
    setClassCode(data.active ?? null);
    // The cooldown starts from this generation.
    const ccRes = await fetch("/api/org/class-code");
    if (ccRes.ok) { const cc = await ccRes.json(); setCodeNextAt(cc.next_generate_at ?? null); }
    setNotice("New class code generated — valid for 24 hours.");
  }
  useEffect(() => { load(); }, []);

  async function createAssignment(e: React.FormEvent) {
    e.preventDefault();
    setABusy(true); setError(null);
    const res = await fetch("/api/org/assignments", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: aTitle, instructions: aInstructions, due_at: aDue || null, items: aItems }),
    });
    setABusy(false);
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Failed to create assignment."); return; }
    setNotice("Assignment set."); setShowNew(false);
    setATitle(""); setADue(""); setAInstructions(""); setAItems([]); setASearch("");
    load();
  }

  async function deleteAssignment(id: string) {
    const res = await fetch(`/api/org/assignments?id=${encodeURIComponent(id)}`, { method: "DELETE" });
    if (!res.ok) { setError("Failed to delete assignment."); return; }
    setAssignments(prev => prev.filter(a => a.id !== id));
  }

  const toggleItem = (it: CatalogItem) => setAItems(prev => {
    const i = prev.findIndex(p => p.kind === it.kind && p.id === it.id);
    return i >= 0 ? prev.filter((_, n) => n !== i) : [...prev, { kind: it.kind, id: it.id }];
  });

  /** Grade sheet for the college's own records / their LMS. */
  function exportCsv() {
    const header = [
      "Student", "Handle", "Status", "Role", "XP", "Level",
      "Rooms completed", "Rooms started", "Scenarios completed", "Avg scenario score",
      "Dashboard sessions", "Avg detect rate %", "Last active", "Enrolment valid until",
    ];
    const body = students.map(s => [
      s.display_name ?? s.handle ?? s.user_id.slice(0, 8),
      s.handle ?? "", s.status, s.role, String(s.xp), String(s.level),
      String(s.rooms_completed), String(s.rooms_started),
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

  async function addMember(e: React.FormEvent) {
    e.preventDefault(); setAdding(true); setError(null); setNotice(null);
    const res = await fetch("/api/org/members", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email, role: "student" }),
    });
    setAdding(false);
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Failed to add."); return; }
    setEmail(""); setNotice(`Added ${email}.`); await load();
  }

  async function setActive(userId: string, active: boolean) {
    setError(null);
    const res = await fetch("/api/org/members", {
      method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ user_id: userId, active }),
    });
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Failed to update status."); return; }
    await load();
  }

  async function removeMember(userId: string) {
    if (!confirm("Permanently remove this student from your class? Their class data is detached. This can't be undone.")) return;
    const res = await fetch("/api/org/members", {
      method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ user_id: userId }),
    });
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Failed to remove."); return; }
    await load();
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
    const res = await fetch("/api/org/deletion-requests", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: r.id, decision }),
    });
    setDBusy(null);
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Failed to action the request."); return; }
    setNotice(decision === "approve" ? `${who}'s account was deleted.` : `Request from ${who} was declined.`);
    await load();
  }

  // Pull every email-looking token out of a CSV / pasted list (any column).
  function extractEmails(text: string): string[] {
    const found = text.toLowerCase().match(/[^\s,;<>"']+@[^\s,;<>"']+\.[^\s,;<>"']+/g) ?? [];
    return [...new Set(found)];
  }
  async function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    setBulkText(prev => (prev ? prev + "\n" : "") + text);
    e.target.value = "";
  }
  async function sendBulk() {
    const emails = extractEmails(bulkText);
    setError(null); setBulkResult(null);
    if (emails.length === 0) { setError("No valid email addresses found in the list."); return; }
    setBulkBusy(true);
    const res = await fetch("/api/org/invites", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ emails, role: "student" }),
    });
    setBulkBusy(false);
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Failed to send invitations."); return; }
    const { invites } = await res.json();
    setBulkResult(`Created ${invites?.length ?? 0} invitation${invites?.length === 1 ? "" : "s"}. Emails sent where email is configured.`);
    setBulkText("");
  }

  const field = "h-10 w-full rounded-md border border-border bg-bg px-3 text-sm text-white focus:border-cyber-500/50 focus:outline-none focus:ring-2 focus:ring-cyber-500/30";
  const active = members.filter(m => m.status === "active");
  // Active first, then by XP.
  const roster = [...members].sort((a, b) =>
    (a.status === "active" ? 0 : 1) - (b.status === "active" ? 0 : 1) || (b.xp ?? 0) - (a.xp ?? 0),
  );

  return (
    <div>
      <Topbar title={org ? `Manage — ${org.name}` : "Manage class"} subtitle="Your students and their progress" />
      <div className="container mx-auto max-w-[1000px] px-6 py-6 space-y-6">
        {error && <div className="flex items-center gap-2 rounded-lg border border-severity-high/40 bg-severity-high/10 px-4 py-3 text-sm text-severity-high"><AlertTriangle className="h-4 w-4" />{error}</div>}
        {notice && <div className="rounded-lg border border-neon-green/30 bg-neon-green/10 px-4 py-3 text-sm text-neon-green">{notice}</div>}

        {loading ? (
          <div className="flex items-center gap-2 text-sm text-slate-400"><Loader2 className="h-4 w-4 animate-spin" /> Loading…</div>
        ) : (
          <>
            {/* At-a-glance banner: the college's name and its live class code,
                the two things an admin opens this page to see. The code CARD
                below keeps the generate/copy controls; this is the summary. */}
            <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-neon-cyan/30 bg-gradient-to-r from-neon-cyan/[0.07] to-transparent px-5 py-4">
              <div className="flex items-center gap-3 min-w-0">
                <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg border border-neon-cyan/30 bg-neon-cyan/10">
                  <Building2 className="h-5 w-5 text-neon-cyan" />
                </span>
                <div className="min-w-0">
                  <p className="text-[10px] uppercase tracking-wider text-slate-400">College</p>
                  <p className="truncate text-lg font-bold text-white">{org?.name ?? "—"}</p>
                </div>
              </div>
              <div className="text-right">
                <p className="text-[10px] uppercase tracking-wider text-slate-400">Class code</p>
                {classCode ? (
                  <>
                    <p className="font-mono text-xl font-bold tracking-[0.3em] text-neon-cyan">{classCode.code}</p>
                    <p className="text-[10px] text-slate-500">rotates every 24h · a student&apos;s enrolment lasts 100 days from sign-up</p>
                  </>
                ) : (
                  <p className="text-sm text-slate-400">No live code — generate one below.</p>
                )}
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
              <Stat icon={<Users className="h-4 w-4" />} label="Students" value={`${active.length}${org && org.seat_limit > 0 ? `/${org.seat_limit}` : ""}`} />
              <Stat icon={<Trophy className="h-4 w-4" />} label="Total XP" value={(usage?.total_xp ?? 0).toLocaleString()} />
              <Stat icon={<Activity className="h-4 w-4" />} label="Sessions" value={String(usage?.sessions ?? 0)} />
              <Stat icon={<Target className="h-4 w-4" />} label="Scenarios" value={String(usage?.scenarios_completed ?? 0)} />
              <Stat icon={<DoorOpen className="h-4 w-4" />} label="Rooms" value={String(usage?.rooms_completed ?? 0)} />
            </div>

            {/* The class affiliation code (0028) — now the PRIMARY way a
                student joins, so it leads the column. One live code at a time,
                24h window, one generation per day. */}
            <Card className="border-neon-cyan/30">
              <h2 className="flex items-center gap-2 text-sm font-bold text-white">
                <KeyRound className="h-4 w-4 text-neon-cyan" /> Class code
              </h2>
              <p className="mt-1 text-xs text-slate-400">
                Students register with their email + this code. It&apos;s valid for 24 hours —
                generate a fresh one each day. A student&apos;s enrolment lasts 100 days before
                they need to enter a current code again.
              </p>
              <div className="mt-4 flex flex-wrap items-center gap-3">
                {classCode ? (
                  <>
                    <span className="rounded-lg border border-neon-cyan/40 bg-neon-cyan/5 px-4 py-2 font-mono text-xl font-bold tracking-[0.3em] text-neon-cyan">
                      {classCode.code}
                    </span>
                    <span className="text-xs text-slate-400">
                      expires {new Date(classCode.expires_at).toLocaleString()}
                    </span>
                    <Button
                      variant="outline" size="sm"
                      onClick={() => { navigator.clipboard.writeText(classCode.code); setNotice("Class code copied."); }}
                    >
                      <Copy className="h-4 w-4" />
                    </Button>
                  </>
                ) : (
                  <span className="text-sm text-slate-400">No live code — generate one for today&apos;s class.</span>
                )}
                <Button
                  variant="primary" size="sm"
                  disabled={codeBusy || Boolean(codeNextAt && new Date(codeNextAt) > new Date())}
                  onClick={generateClassCode}
                >
                  {codeBusy ? "Generating…" : "Generate today's code"}
                </Button>
                {codeNextAt && new Date(codeNextAt) > new Date() && (
                  <span className="text-xs text-slate-500">
                    next generation {new Date(codeNextAt).toLocaleString()}
                  </span>
                )}
              </div>
            </Card>

            {/* The anonymous "Generate class link" that used to lead this card
                is gone (0029): students join with the class code above. What
                remains are the admin's EXPLICIT acts — attaching an existing
                account, and named email invites below. */}
            <Card>
              <h2 className="mb-3 text-sm font-bold text-white">Add students directly</h2>
              <form onSubmit={addMember} className="flex flex-wrap items-end gap-2">
                <div className="flex-1 min-w-[220px]">
                  <label className="mb-1.5 block text-xs font-semibold text-slate-400" htmlFor="mg-email">Or attach an existing account by email</label>
                  {/* Placeholder is deliberately a personal address: students
                      enrol with whatever email they actually use, and an
                      institutional one is not required anywhere. */}
                  <input id="mg-email" type="email" className={field} value={email} onChange={e => setEmail(e.target.value)} placeholder="dana.levi@gmail.com" required />
                </div>
                <Button type="submit" variant="primary" size="sm" disabled={adding}><UserPlus className="mr-1.5 h-4 w-4" />{adding ? "Adding…" : "Add"}</Button>
              </form>
            </Card>

            <Card>
              <h2 className="mb-1 flex items-center gap-2 text-sm font-bold text-white"><Upload className="h-4 w-4 text-cyber-300" /> Bulk invite (CSV or list)</h2>
              <p className="mb-3 text-xs text-slate-400">
                Upload a CSV or paste a list of student emails — each gets a personal invite emailed
                to them (where email is configured). Any email provider works; an institutional
                address isn&apos;t required. Each invite only works for the address you enter here,
                so send students the address they actually use.
              </p>
              <div className="mb-2 flex flex-wrap items-center gap-2">
                <label className="inline-flex cursor-pointer items-center gap-2 rounded-lg border border-border bg-bg px-3.5 py-2 text-xs font-bold text-slate-200 transition hover:text-white">
                  <Upload className="h-4 w-4" /> Choose CSV
                  <input type="file" accept=".csv,text/csv,text/plain" className="hidden" onChange={onFile} />
                </label>
                <span className="text-[11px] text-slate-400">or paste below</span>
              </div>
              <textarea
                value={bulkText} onChange={e => setBulkText(e.target.value)} rows={4}
                className="w-full rounded-md border border-border bg-bg px-3 py-2 text-sm text-white placeholder-slate-500 focus:border-cyber-500/50 focus:outline-none focus:ring-2 focus:ring-cyber-500/30"
                placeholder={"dana.levi@gmail.com\nomri@sapir.ac.il\nyael.cohen@outlook.com\n…"}
                aria-label="Student emails"
              />
              <div className="mt-2 flex items-center justify-between">
                <span className="text-[11px] text-slate-400">{extractEmails(bulkText).length} valid email(s) detected</span>
                <Button variant="primary" size="sm" disabled={bulkBusy || extractEmails(bulkText).length === 0} onClick={sendBulk}>
                  <Mail className="mr-1.5 h-4 w-4" /> {bulkBusy ? "Sending…" : "Send invitations"}
                </Button>
              </div>
              {bulkResult && <p className="mt-2 flex items-center gap-1.5 text-[11px] text-neon-green"><Check className="h-3.5 w-3.5" /> {bulkResult}</p>}
            </Card>

            {/* Assignments — what this cohort has actually been set to do. */}
            <Card>
              <div className="mb-3 flex items-center justify-between gap-3">
                <h2 className="flex items-center gap-2 text-sm font-bold text-white">
                  <ClipboardList className="h-4 w-4 text-cyber-300" /> Assignments
                </h2>
                <Button variant={showNew ? "outline" : "primary"} size="sm" onClick={() => setShowNew(v => !v)}>
                  {showNew ? <><X className="mr-1.5 h-4 w-4" /> Cancel</> : <><Plus className="mr-1.5 h-4 w-4" /> New assignment</>}
                </Button>
              </div>

              {showNew && (
                <form onSubmit={createAssignment} className="mb-4 space-y-3 rounded-lg border border-border bg-bg p-3">
                  <div className="flex flex-wrap gap-2">
                    <div className="flex-1 min-w-[220px]">
                      <label className="mb-1.5 block text-xs font-semibold text-slate-400" htmlFor="a-title">Title</label>
                      <input id="a-title" className={field} value={aTitle} onChange={e => setATitle(e.target.value)} placeholder="Week 3 — Windows log analysis" required />
                    </div>
                    <div>
                      <label className="mb-1.5 block text-xs font-semibold text-slate-400" htmlFor="a-due">Due (optional)</label>
                      <input id="a-due" type="date" className={field} value={aDue} onChange={e => setADue(e.target.value)} />
                    </div>
                  </div>
                  <div>
                    <label className="mb-1.5 block text-xs font-semibold text-slate-400" htmlFor="a-inst">Instructions (optional)</label>
                    <input id="a-inst" className={field} value={aInstructions} onChange={e => setAInstructions(e.target.value)} placeholder="Finish all four before the seminar." />
                  </div>

                  <div>
                    <label className="mb-1.5 block text-xs font-semibold text-slate-400" htmlFor="a-search">
                      Rooms &amp; scenarios ({aItems.length} selected)
                    </label>
                    <input id="a-search" className={field} value={aSearch} onChange={e => setASearch(e.target.value)} placeholder="Search the catalogue…" />
                    <div className="mt-2 max-h-56 overflow-y-auto rounded-md border border-border">
                      {catalog
                        .filter(c => !aSearch || c.title.toLowerCase().includes(aSearch.toLowerCase()) || c.group.toLowerCase().includes(aSearch.toLowerCase()))
                        .slice(0, 60)
                        .map(c => {
                          const picked = aItems.some(p => p.kind === c.kind && p.id === c.id);
                          return (
                            <button
                              type="button" key={`${c.kind}:${c.id}`} onClick={() => toggleItem(c)}
                              aria-pressed={picked}
                              className={`flex w-full items-center gap-2 border-b border-border/50 px-3 py-2 text-left text-xs last:border-b-0 transition ${
                                picked ? "bg-cyber-500/10 text-cyber-200" : "text-slate-300 hover:bg-bg-elevated"
                              }`}
                            >
                              <span className={`flex h-4 w-4 shrink-0 items-center justify-center rounded border ${picked ? "border-cyber-400 bg-cyber-500/30" : "border-slate-600"}`}>
                                {picked && <Check className="h-3 w-3" />}
                              </span>
                              <span className="min-w-0 flex-1 truncate">{c.title}</span>
                              <span className="shrink-0 rounded border border-slate-700 px-1.5 py-0.5 text-[9px] uppercase tracking-wider text-slate-400">
                                {c.kind === "scenario" ? "Scenario" : c.group}
                              </span>
                            </button>
                          );
                        })}
                    </div>
                  </div>

                  <Button type="submit" variant="primary" size="sm" disabled={aBusy || !aTitle.trim() || aItems.length === 0}>
                    {aBusy ? "Setting…" : `Set assignment${aItems.length ? ` (${aItems.length})` : ""}`}
                  </Button>
                </form>
              )}

              {assignments.length === 0 ? (
                <p className="text-sm text-slate-400">
                  Nothing set yet. Students currently see the whole catalogue with no direction — an assignment tells them what to do and by when.
                </p>
              ) : (
                <div className="divide-y divide-border/60">
                  {assignments.map(a => {
                    const overdue = a.due_at && Date.parse(a.due_at) < Date.now();
                    return (
                      <div key={a.id} className="flex items-start justify-between gap-3 py-2.5">
                        <div className="min-w-0">
                          <p className="truncate text-sm font-medium text-white">{a.title}</p>
                          <p className="mt-0.5 truncate text-[11px] text-slate-400">
                            {a.item_titles.length} item{a.item_titles.length === 1 ? "" : "s"}
                            {a.due_at && (
                              <span className={overdue ? "text-severity-high" : "text-slate-400"}>
                                {" · "}<CalendarClock className="inline h-3 w-3" /> due {new Date(a.due_at).toLocaleDateString("en-GB")}
                              </span>
                            )}
                          </p>
                          <p className="mt-0.5 truncate text-[11px] text-slate-500">{a.item_titles.map(t => t.title).join(" · ")}</p>
                        </div>
                        <div className="flex shrink-0 items-center gap-2">
                          {a.cohort && (
                            <span className="font-mono text-[11px] text-slate-400" title="Students who finished every item">
                              {a.cohort.completed}/{a.cohort.total} done
                            </span>
                          )}
                          <button onClick={() => deleteAssignment(a.id)} aria-label={`Delete ${a.title}`} title="Delete"
                            className="rounded p-1.5 text-slate-400 transition hover:bg-severity-high/10 hover:text-severity-high"><Trash2 className="h-4 w-4" /></button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </Card>

            {/* Right-to-deletion queue. Placed ABOVE class progress on purpose:
                these carry a 30-day statutory deadline, so they must not sit
                below the fold under analytics nobody scrolls past. Renders only
                when there is something to decide. */}
            {deletions.length > 0 && (
              <Card className="border-neon-amber/40">
                <h2 className="flex items-center gap-2 text-sm font-bold text-white">
                  <AlertTriangle className="h-4 w-4 text-neon-amber" />
                  Account deletion requests ({deletions.length})
                </h2>
                <p className="mt-1.5 text-xs text-slate-400">
                  Students exercising their right to deletion under the Privacy Protection Law.
                  You must answer within 30 days. Approving <strong className="text-slate-300">permanently
                  erases</strong> the account and removes their results from your class records.
                </p>
                <div className="mt-4 space-y-2">
                  {deletions.map(r => (
                    <div key={r.id} className="flex flex-wrap items-center gap-3 rounded-lg border border-border bg-bg-elevated px-3 py-2.5">
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm font-medium text-slate-100">
                          {r.display_name || r.handle || "Unnamed student"}
                        </p>
                        <p className="text-xs text-slate-400">
                          Requested {sinceLabel(r.requested_at)}
                          {r.days_open >= 21 && (
                            <span className="ml-2 font-semibold text-neon-amber">
                              · {30 - r.days_open} days left to answer
                            </span>
                          )}
                        </p>
                        {r.reason && <p className="mt-1 text-xs italic text-slate-400">“{r.reason}”</p>}
                      </div>
                      <div className="flex gap-2">
                        <Button size="sm" variant="danger" disabled={dBusy === r.id} onClick={() => decideDeletion(r, "approve")}>
                          {dBusy === r.id ? "Working…" : "Approve & erase"}
                        </Button>
                        <Button size="sm" variant="ghost" disabled={dBusy === r.id} onClick={() => decideDeletion(r, "reject")}>
                          Decline
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              </Card>
            )}

            {/* Class signals — the "who needs me this week" view. Only shown once
                there's a cohort to say anything about. */}
            {classStats && classStats.size > 0 && (
              <Card>
                <h2 className="mb-3 text-sm font-bold text-white">Class progress</h2>
                <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                  <MiniStat label="Avg scenario score" value={classStats.avg_scenario_score === null ? "—" : `${classStats.avg_scenario_score}%`} />
                  <MiniStat label="Avg rooms / student" value={classStats.avg_rooms_completed === null ? "—" : String(classStats.avg_rooms_completed)} />
                  <MiniStat label="Active this week" value={`${classStats.active_7d}/${classStats.size}`} tone={classStats.active_7d === 0 ? "warn" : "good"} />
                  <MiniStat
                    label="Need attention"
                    value={String(classStats.never_started + classStats.dormant_14d)}
                    tone={classStats.never_started + classStats.dormant_14d > 0 ? "warn" : "good"}
                    hint={`${classStats.never_started} never started · ${classStats.dormant_14d} quiet 14d+`}
                  />
                </div>

                {classStats.hardest_rooms.length > 0 && (
                  <div className="mt-4 border-t border-border/60 pt-3">
                    <p className="mb-2 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                      <TrendingDown className="h-3.5 w-3.5" /> Where the class gets stuck
                    </p>
                    <ul className="space-y-1.5">
                      {classStats.hardest_rooms.map(r => (
                        <li key={r.room_id} className="flex items-center gap-3 text-xs">
                          <span className="min-w-0 flex-1 truncate text-slate-200">{r.title}</span>
                          <span className="shrink-0 font-mono text-[11px] text-slate-400">{r.completed}/{r.started} finished</span>
                          <span className={`shrink-0 font-mono text-[11px] font-bold ${r.completion_rate < 50 ? "text-severity-high" : "text-neon-amber"}`}>
                            {r.completion_rate}%
                          </span>
                        </li>
                      ))}
                    </ul>
                    <p className="mt-2 text-[10px] text-slate-500">Rooms at least 3 students opened, ranked by how few finished them.</p>
                  </div>
                )}
              </Card>
            )}

            <Card>
              <div className="mb-3 flex items-center justify-between gap-3">
                <h2 className="text-sm font-bold text-white">Roster ({active.length})</h2>
                {students.length > 0 && (
                  <Button variant="outline" size="sm" onClick={exportCsv}>
                    <Download className="mr-1.5 h-4 w-4" /> Export grades (CSV)
                  </Button>
                )}
              </div>
              {roster.length === 0 ? (
                <p className="text-sm text-slate-400">No students yet. Share your class link to get started.</p>
              ) : (
                <div className="divide-y divide-border/60">
                  {roster.map((m, i) => {
                    const isActive = m.status === "active";
                    const s = students.find(x => x.user_id === m.user_id);
                    return (
                      <div key={m.user_id} className={`flex flex-wrap items-center justify-between gap-3 py-2.5 ${isActive ? "" : "opacity-60"}`}>
                        <div className="flex items-center gap-3 min-w-0">
                          <span className="w-5 shrink-0 text-center font-mono text-[11px] text-slate-500">{isActive ? i + 1 : "—"}</span>
                          {/* Name links to the per-student drill-down (timeline,
                              per-scenario score + time, decision latency). */}
                          <Link href={`/manage/students/${m.user_id}`} className="group min-w-0">
                            <p className="flex items-center gap-1 truncate text-sm font-medium text-white group-hover:text-cyber-300">
                              {m.display_name || m.handle || m.user_id.slice(0, 8)}
                              <ChevronRight className="h-3.5 w-3.5 shrink-0 text-slate-600 transition group-hover:translate-x-0.5 group-hover:text-cyber-300" />
                            </p>
                            <p className="truncate font-mono text-[11px] text-slate-400">
                              {m.handle ? `@${m.handle}` : ""} · {m.role}
                              {s?.joined_at ? <> · <CalendarDays className="inline h-3 w-3" /> joined {new Date(s.joined_at).toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "2-digit" })}</> : null}
                            </p>
                          </Link>
                          <span className={`shrink-0 rounded-full border px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider ${
                            isActive ? "border-neon-green/30 bg-neon-green/10 text-neon-green" : "border-slate-600 bg-slate-800/60 text-slate-400"
                          }`}>{isActive ? "Active" : "Inactive"}</span>
                        </div>

                        <div className="flex items-center gap-3">
                          {/* Per-student progress — the drill-down an instructor
                              running a semester actually needs. */}
                          {s && (
                            <div className="flex items-center gap-3 font-mono text-[11px] text-slate-400">
                              <span title="Rooms completed"><DoorOpen className="mr-1 inline h-3 w-3" />{s.rooms_completed}</span>
                              <span title="Scenarios completed"><Target className="mr-1 inline h-3 w-3" />{s.scenarios_completed}</span>
                              <span title="Average scenario score" className={s.scenario_avg_score !== null && s.scenario_avg_score < 60 ? "text-severity-high" : ""}>
                                {s.scenario_avg_score === null ? "—" : `${s.scenario_avg_score}%`}
                              </span>
                              <span
                                title={s.last_active_at ? `Last active ${new Date(s.last_active_at).toLocaleString()}` : "Never signed in"}
                                className={!s.last_active_at || Date.now() - Date.parse(s.last_active_at) >= 14 * 86_400_000 ? "text-neon-amber" : ""}
                              >
                                <Clock className="mr-1 inline h-3 w-3" />{sinceLabel(s.last_active_at)}
                              </span>
                              {/* The 100-day affiliation clock (0028). Quiet
                                  until it matters: plain until 14 days out,
                                  amber then, red once lapsed — at which point
                                  the student is locked out until they enter a
                                  current class code. */}
                              {s.affiliation_expires_at && (() => {
                                const daysLeft = Math.ceil((Date.parse(s.affiliation_expires_at) - Date.now()) / 86_400_000);
                                return (
                                  <span
                                    title={`Enrolment ${daysLeft < 0 ? "lapsed" : `valid until ${new Date(s.affiliation_expires_at).toLocaleDateString()}`} — renewed with a current class code`}
                                    className={daysLeft < 0 ? "font-bold text-severity-high" : daysLeft <= 14 ? "text-neon-amber" : ""}
                                  >
                                    <KeyRound className="mr-1 inline h-3 w-3" />
                                    {daysLeft < 0 ? "lapsed" : `${daysLeft}d`}
                                  </span>
                                );
                              })()}
                            </div>
                          )}
                          <span className="font-mono text-xs font-bold text-cyber-300">{(m.xp ?? 0).toLocaleString()} XP</span>
                          {isActive ? (
                            <button onClick={() => setActive(m.user_id, false)} aria-label={`Deactivate ${m.handle ?? "student"}`} title="Deactivate"
                              className="rounded p-1.5 text-slate-400 transition hover:bg-neon-amber/10 hover:text-neon-amber"><PowerOff className="h-4 w-4" /></button>
                          ) : (
                            <button onClick={() => setActive(m.user_id, true)} aria-label={`Activate ${m.handle ?? "student"}`} title="Activate"
                              className="rounded p-1.5 text-slate-400 transition hover:bg-neon-green/10 hover:text-neon-green"><Power className="h-4 w-4" /></button>
                          )}
                          <button onClick={() => removeMember(m.user_id)} aria-label={`Remove ${m.handle ?? "student"}`} title="Delete"
                            className="rounded p-1.5 text-slate-400 transition hover:bg-severity-high/10 hover:text-severity-high"><Trash2 className="h-4 w-4" /></button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </Card>
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
      <p className={`mt-0.5 font-mono text-lg font-bold ${
        tone === "warn" ? "text-neon-amber" : tone === "good" ? "text-neon-green" : "text-white"
      }`}>{value}</p>
      {hint && <p className="mt-0.5 text-[10px] text-slate-500">{hint}</p>}
    </div>
  );
}

function Stat({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  return (
    <Card className="py-3">
      <div className="flex items-center gap-1.5 text-slate-400">{icon}<span className="text-[10px] uppercase tracking-wider">{label}</span></div>
      <p className="mt-1 font-mono text-lg font-bold text-white">{value}</p>
    </Card>
  );
}
