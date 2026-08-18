"use client";
/**
 * Org-admin console — a college's own dashboard. Scoped entirely to the admin's
 * org by the /api/org/* routes (org id comes from their JWT, never the client),
 * so a college admin sees and touches only their own students.
 *
 * UI language: HEBREW + RTL (PM audit F10). The buyer for this screen is an
 * Israeli college; the instructor-facing console is the thing they see in a
 * sales demo, so it reads right-to-left in Hebrew. `dir="rtl"` sits on the
 * CONTENT container, not the shared Topbar (kept LTR, consistent app-wide).
 * Inherently-LTR data — emails, the class code, @handles — carry dir="ltr" so
 * they stay readable inside the RTL layout.
 */
import { useEffect, useState } from "react";
import { Topbar } from "@/components/nav/Topbar";
import { usePageTitle } from "@/lib/hooks/usePageTitle";
import Link from "next/link";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import {
  Users, Trophy, Activity, Target, DoorOpen, Copy, AlertTriangle, Loader2, KeyRound,
  Power, PowerOff, Trash2, Download, TrendingDown, Building2, ChevronLeft, Route,
} from "lucide-react";
import type { OrgMember, OrgUsage } from "@/lib/org/types";
import type { StudentRow } from "@/app/api/org/analytics/route";
import { cohortPathProgress, studentPathPercent } from "@/lib/org/pathProgress";
import { AssignmentsPanel } from "@/components/manage/AssignmentsPanel";

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

/** "לפני 3 ימים" / "היום" — מדריך סורק אחרי איחור, לא אחרי חותמת-זמן מדויקת. */
function sinceLabel(iso: string | null): string {
  if (!iso) return "מעולם";
  const days = Math.floor((Date.now() - Date.parse(iso)) / 86_400_000);
  if (days <= 0) return "היום";
  if (days === 1) return "לפני יום";
  return `לפני ${days} ימים`;
}

/** RFC-4180-ish escaping: quote everything, double any inner quotes. */
function toCsv(rows: string[][]): string {
  return rows.map(r => r.map(c => `"${String(c ?? "").replace(/"/g, '""')}"`).join(",")).join("\r\n");
}

export default function ManagePage() {
  usePageTitle("ניהול כיתה");
  const [org, setOrg] = useState<OrgLite | null>(null);
  const [members, setMembers] = useState<Member[]>([]);
  const [usage, setUsage] = useState<OrgUsage | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  // cohort analytics (per-student progress + class signals)
  const [students, setStudents] = useState<StudentRow[]>([]);
  const [classStats, setClassStats] = useState<ClassStats | null>(null);

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
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "הטעינה נכשלה."); return; }
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
    if (!res.ok) { setError(data?.error ?? "לא ניתן היה ליצור קוד."); return; }
    setClassCode(data.active ?? null);
    // The cooldown starts from this generation.
    const ccRes = await fetch("/api/org/class-code");
    if (ccRes.ok) { const cc = await ccRes.json(); setCodeNextAt(cc.next_generate_at ?? null); }
    setNotice("נוצר קוד כיתה חדש — תקף ל-24 שעות.");
  }
  useEffect(() => { load(); }, []);

  /** Grade sheet for the college's own records / their LMS. Headers stay English
   *  for LMS/spreadsheet interoperability (the on-screen console is Hebrew). */
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

  async function setActive(userId: string, active: boolean) {
    setError(null);
    const res = await fetch("/api/org/members", {
      method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ user_id: userId, active }),
    });
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "עדכון הסטטוס נכשל."); return; }
    await load();
  }

  async function removeMember(userId: string) {
    if (!confirm("להסיר את התלמיד הזה מהכיתה לצמיתות? נתוני-הכיתה שלו מנותקים. אי-אפשר לבטל.")) return;
    const res = await fetch("/api/org/members", {
      method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ user_id: userId }),
    });
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "ההסרה נכשלה."); return; }
    await load();
  }

  /**
   * Decide a right-to-deletion request. Approving ERASES the student's account
   * and everything cascading from it — hence the explicit confirm naming the
   * student, separate from the generic "remove from class" above, which only
   * detaches them and leaves the account intact.
   */
  async function decideDeletion(r: DeletionRequest, decision: "approve" | "reject") {
    const who = r.display_name || r.handle || "התלמיד הזה";
    if (decision === "approve" && !confirm(
      `למחוק לצמיתות את החשבון של ${who} ואת כל נתוני-הלמידה שלו?\n\n` +
      `זה ממלא את בקשת-המחיקה החוקית שלו ואי-אפשר לבטל. ` +
      `התוצאות שלו לא יופיעו יותר ברשומות הכיתה שלך.`,
    )) return;

    setDBusy(r.id);
    const res = await fetch("/api/org/deletion-requests", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: r.id, decision }),
    });
    setDBusy(null);
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "הטיפול בבקשה נכשל."); return; }
    setNotice(decision === "approve" ? `החשבון של ${who} נמחק.` : `הבקשה מ-${who} נדחתה.`);
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

  // Named at-risk students — never started, quiet 14d+, or failing (<60% with
  // graded work). The class card already COUNTS these; this surfaces WHO.
  const atRisk = students.filter(s => {
    if (s.status !== "active") return false;
    const neverStarted = s.rooms_started === 0 && s.scenarios_completed === 0 && s.sessions === 0;
    const dormant = s.last_active_at ? Date.now() - Date.parse(s.last_active_at) >= 14 * 86_400_000 : false;
    const failing = s.task_accuracy !== null && s.tasks_graded > 0 && s.task_accuracy < 60;
    return neverStarted || dormant || failing;
  });

  return (
    <div>
      <Topbar title={org ? `ניהול — ${org.name}` : "ניהול כיתה"} subtitle="התלמידים שלך וההתקדמות שלהם" />
      <div dir="rtl" className="container mx-auto max-w-[1000px] px-6 py-6 space-y-6">
        {error && <div className="flex items-center gap-2 rounded-lg border border-severity-high/40 bg-severity-high/10 px-4 py-3 text-sm text-severity-high"><AlertTriangle className="h-4 w-4" />{error}</div>}
        {notice && <div className="rounded-lg border border-neon-green/30 bg-neon-green/10 px-4 py-3 text-sm text-neon-green">{notice}</div>}

        {loading ? (
          <div className="flex items-center gap-2 text-sm text-slate-400"><Loader2 className="h-4 w-4 animate-spin" /> טוען…</div>
        ) : (
          <>
            {/* At-a-glance banner: the college's name and its live class code,
                the two things an admin opens this page to see. The code CARD
                below keeps the generate/copy controls; this is the summary. */}
            <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-neon-cyan/30 bg-gradient-to-l from-neon-cyan/[0.07] to-transparent px-5 py-4">
              <div className="flex items-center gap-3 min-w-0">
                <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg border border-neon-cyan/30 bg-neon-cyan/10">
                  <Building2 className="h-5 w-5 text-neon-cyan" />
                </span>
                <div className="min-w-0">
                  <p className="text-[10px] uppercase tracking-wider text-slate-400">מכללה</p>
                  <p className="truncate text-lg font-bold text-white">{org?.name ?? "—"}</p>
                </div>
              </div>
              <div className="text-left">
                <p className="text-[10px] uppercase tracking-wider text-slate-400">קוד כיתה</p>
                {classCode ? (
                  <>
                    <p dir="ltr" className="font-mono text-xl font-bold tracking-[0.3em] text-neon-cyan">{classCode.code}</p>
                    <p className="text-[10px] text-slate-500">מתחלף כל 24 שעות · שיוך התלמיד נמשך 100 יום מההרשמה</p>
                  </>
                ) : (
                  <p className="text-sm text-slate-400">אין קוד פעיל — צור אחד למטה.</p>
                )}
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
              <Stat icon={<Users className="h-4 w-4" />} label="תלמידים" value={`${active.length}${org && org.seat_limit > 0 ? `/${org.seat_limit}` : ""}`} />
              <Stat icon={<Trophy className="h-4 w-4" />} label="סה״כ XP" value={(usage?.total_xp ?? 0).toLocaleString()} />
              <Stat icon={<Activity className="h-4 w-4" />} label="מפגשים" value={String(usage?.sessions ?? 0)} />
              <Stat icon={<Target className="h-4 w-4" />} label="תרחישים" value={String(usage?.scenarios_completed ?? 0)} />
              <Stat icon={<DoorOpen className="h-4 w-4" />} label="חדרים" value={String(usage?.rooms_completed ?? 0)} />
            </div>

            {/* Where the cohort is along the graded path. The three stages are
                the rooms' own difficulty tiers; each bar is the % of that stage's
                rooms the class has cleared on average. */}
            {students.length > 0 && (
              <Card>
                <div className="mb-3 flex items-center justify-between">
                  <h2 className="flex items-center gap-2 text-sm font-bold text-white">
                    <Route className="h-4 w-4 text-cyber-300" /> הכיתה לאורך המסלול
                  </h2>
                  <span className="font-mono text-xs text-slate-400">{overallPathPct}% מהתכנית</span>
                </div>
                <div className="space-y-2.5">
                  {pathProg.map(st => (
                    <div key={st.stage} className="flex items-center gap-3">
                      <span className="w-28 shrink-0 text-xs text-slate-300">{st.stage}</span>
                      <span className="h-2 flex-1 overflow-hidden rounded-full bg-bg">
                        <span
                          className={`block h-full ${st.stage === "Foundations" ? "bg-neon-green" : "bg-cyber-500"}`}
                          style={{ width: `${st.percent}%` }}
                        />
                      </span>
                      <span className="w-16 shrink-0 text-left font-mono text-[11px] text-slate-400">
                        {st.percent}% <span className="text-slate-600">· {st.roomCount}</span>
                      </span>
                    </div>
                  ))}
                </div>
                <p className="mt-2 text-[10px] text-slate-500">ממוצע על פני {students.length} תלמידים; המספר בסוף הוא כמה חדרים כל שלב מכיל.</p>
              </Card>
            )}

            {/* The class affiliation code (0028) — now the PRIMARY way a
                student joins, so it leads the column. One live code at a time,
                24h window, one generation per day. */}
            <Card className="border-neon-cyan/30">
              <h2 className="flex items-center gap-2 text-sm font-bold text-white">
                <KeyRound className="h-4 w-4 text-neon-cyan" /> קוד כיתה
              </h2>
              <p className="mt-1 text-xs text-slate-400">
                התלמידים נרשמים עם האימייל שלהם + הקוד הזה. הוא תקף ל-24 שעות —
                צור אחד חדש בכל יום. שיוך התלמיד נמשך 100 יום לפני שהוא צריך
                להזין קוד עדכני שוב.
              </p>
              <div className="mt-4 flex flex-wrap items-center gap-3">
                {classCode ? (
                  <>
                    <span dir="ltr" className="rounded-lg border border-neon-cyan/40 bg-neon-cyan/5 px-4 py-2 font-mono text-xl font-bold tracking-[0.3em] text-neon-cyan">
                      {classCode.code}
                    </span>
                    <span className="text-xs text-slate-400">
                      פג בתאריך {new Date(classCode.expires_at).toLocaleString("he-IL")}
                    </span>
                    <Button
                      variant="outline" size="sm"
                      onClick={() => { navigator.clipboard.writeText(classCode.code); setNotice("קוד הכיתה הועתק."); }}
                    >
                      <Copy className="h-4 w-4" />
                    </Button>
                  </>
                ) : (
                  <span className="text-sm text-slate-400">אין קוד פעיל — צור אחד לכיתה של היום.</span>
                )}
                <Button
                  variant="primary" size="sm"
                  disabled={codeBusy || Boolean(codeNextAt && new Date(codeNextAt) > new Date())}
                  onClick={generateClassCode}
                >
                  {codeBusy ? "יוצר…" : "צור את הקוד להיום"}
                </Button>
                {codeNextAt && new Date(codeNextAt) > new Date() && (
                  <span className="text-xs text-slate-500">
                    יצירה הבאה {new Date(codeNextAt).toLocaleString("he-IL")}
                  </span>
                )}
              </div>
            </Card>

            {/* The anonymous "Generate class link" that used to lead this card
                is gone (0029): students join with the class code above. What
                remains are the admin's EXPLICIT acts — attaching an existing
                account, and named email invites below. */}
            {/* Right-to-deletion queue. Placed ABOVE class progress on purpose:
                these carry a 30-day statutory deadline, so they must not sit
                below the fold under analytics nobody scrolls past. Renders only
                when there is something to decide. */}
            {deletions.length > 0 && (
              <Card className="border-neon-amber/40">
                <h2 className="flex items-center gap-2 text-sm font-bold text-white">
                  <AlertTriangle className="h-4 w-4 text-neon-amber" />
                  בקשות למחיקת חשבון ({deletions.length})
                </h2>
                <p className="mt-1.5 text-xs text-slate-400">
                  תלמידים המממשים את זכותם למחיקה לפי חוק הגנת הפרטיות.
                  עליך לענות תוך 30 יום. אישור <strong className="text-slate-300">מוחק
                  לצמיתות</strong> את החשבון ומסיר את תוצאותיו מרשומות הכיתה שלך.
                </p>
                <div className="mt-4 space-y-2">
                  {deletions.map(r => (
                    <div key={r.id} className="flex flex-wrap items-center gap-3 rounded-lg border border-border bg-bg-elevated px-3 py-2.5">
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm font-medium text-slate-100">
                          {r.display_name || r.handle || "תלמיד ללא שם"}
                        </p>
                        <p className="text-xs text-slate-400">
                          התבקש {sinceLabel(r.requested_at)}
                          {r.days_open >= 21 && (
                            <span className="mr-2 font-semibold text-neon-amber">
                              · נותרו {30 - r.days_open} ימים לענות
                            </span>
                          )}
                        </p>
                        {r.reason && <p className="mt-1 text-xs italic text-slate-400">“{r.reason}”</p>}
                      </div>
                      <div className="flex gap-2">
                        <Button size="sm" variant="danger" disabled={dBusy === r.id} onClick={() => decideDeletion(r, "approve")}>
                          {dBusy === r.id ? "מבצע…" : "אשר ומחק"}
                        </Button>
                        <Button size="sm" variant="ghost" disabled={dBusy === r.id} onClick={() => decideDeletion(r, "reject")}>
                          דחה
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
                <h2 className="mb-3 text-sm font-bold text-white">התקדמות הכיתה</h2>
                <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                  <MiniStat label="ציון תרחיש ממוצע" value={classStats.avg_scenario_score === null ? "—" : `${classStats.avg_scenario_score}%`} />
                  <MiniStat label="חדרים ממוצע / תלמיד" value={classStats.avg_rooms_completed === null ? "—" : String(classStats.avg_rooms_completed)} />
                  <MiniStat label="פעילים השבוע" value={`${classStats.active_7d}/${classStats.size}`} tone={classStats.active_7d === 0 ? "warn" : "good"} />
                  <MiniStat
                    label="דורשים תשומת לב"
                    value={String(classStats.never_started + classStats.dormant_14d)}
                    tone={classStats.never_started + classStats.dormant_14d > 0 ? "warn" : "good"}
                    hint={`${classStats.never_started} לא התחילו · ${classStats.dormant_14d} שקטים 14 ימ+`}
                  />
                </div>

                {classStats.hardest_rooms.length > 0 && (
                  <div className="mt-4 border-t border-border/60 pt-3">
                    <p className="mb-2 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                      <TrendingDown className="h-3.5 w-3.5" /> איפה הכיתה נתקעת
                    </p>
                    <ul className="space-y-1.5">
                      {classStats.hardest_rooms.map(r => (
                        <li key={r.room_id} className="flex items-center gap-3 text-xs">
                          <span className="min-w-0 flex-1 truncate text-slate-200">{r.title}</span>
                          <span className="shrink-0 font-mono text-[11px] text-slate-400">{r.completed}/{r.started} סיימו</span>
                          <span className={`shrink-0 font-mono text-[11px] font-bold ${r.completion_rate < 50 ? "text-severity-high" : "text-neon-amber"}`}>
                            {r.completion_rate}%
                          </span>
                        </li>
                      ))}
                    </ul>
                    <p className="mt-2 text-[10px] text-slate-500">חדרים שלפחות 3 תלמידים פתחו, מדורגים לפי כמה מעטים סיימו אותם.</p>
                  </div>
                )}
              </Card>
            )}

            {/* WHO needs attention, by name — the class card counts them, this
                names them and links straight to each drill-down. */}
            {atRisk.length > 0 && (
              <Card className="border-neon-amber/30">
                <h2 className="flex items-center gap-2 text-sm font-bold text-white">
                  <AlertTriangle className="h-4 w-4 text-neon-amber" /> תלמידים הזקוקים לתשומת לב ({atRisk.length})
                </h2>
                <div className="mt-3 flex flex-wrap gap-2">
                  {atRisk.map(s => {
                    const why = s.rooms_started === 0 && s.scenarios_completed === 0 && s.sessions === 0
                      ? "לא התחיל"
                      : s.last_active_at && Date.now() - Date.parse(s.last_active_at) >= 14 * 86_400_000
                        ? "שקט 14 ימ+"
                        : "ציון נמוך";
                    return (
                      <Link key={s.user_id} href={`/manage/students/${s.user_id}`}
                        className="inline-flex items-center gap-2 rounded-lg border border-border bg-bg-elevated px-2.5 py-1.5 text-xs text-slate-200 transition hover:border-neon-amber/50">
                        <span className="font-medium">{s.display_name || s.handle || s.user_id.slice(0, 8)}</span>
                        <span className="text-[10px] text-neon-amber">{why}</span>
                      </Link>
                    );
                  })}
                </div>
              </Card>
            )}

            <AssignmentsPanel />

            <Card className="overflow-hidden p-0">
              <div className="flex items-center justify-between gap-3 px-4 py-3">
                <h2 className="text-sm font-bold text-white">רשימת התלמידים ({active.length})</h2>
                {students.length > 0 && (
                  <Button variant="outline" size="sm" onClick={exportCsv}>
                    <Download className="ml-1.5 h-4 w-4" /> ייצוא ציונים (CSV)
                  </Button>
                )}
              </div>
              {roster.length === 0 ? (
                <p className="px-4 pb-4 text-sm text-slate-400">אין עדיין תלמידים. שתף את קוד הכיתה של היום כדי שיירשמו.</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-right text-sm">
                    <thead>
                      <tr className="border-y border-border text-[11px] uppercase tracking-wider text-slate-400">
                        <th className="px-4 py-2.5 font-medium">תלמיד</th>
                        <th className="px-4 py-2.5 font-medium">אימייל</th>
                        <th className="px-4 py-2.5 font-medium" title="תשובות נכונות בכל המשימות המדורגות">ציון</th>
                        <th className="px-4 py-2.5 font-medium" title="חלק מהתכנית המדורגת שהושלם">מסלול</th>
                        <th className="px-4 py-2.5 font-medium" title="שיעור זיהוי ממוצע בדשבורד החי">זיהוי</th>
                        <th className="px-4 py-2.5 font-medium">XP</th>
                        <th className="px-4 py-2.5 font-medium">פעילות אחרונה</th>
                        <th className="px-4 py-2.5 text-left font-medium">פעולות</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border/60">
                      {roster.map(m => {
                        const isActive = m.status === "active";
                        const s = students.find(x => x.user_id === m.user_id);
                        return (
                          <tr key={m.user_id} className={`transition hover:bg-white/[0.02] ${isActive ? "" : "opacity-60"}`}>
                            {/* Full name → per-student drill-down (progress, mistakes, timing) */}
                            <td className="px-4 py-2.5">
                              <Link href={`/manage/students/${m.user_id}`} className="group inline-flex items-center gap-1">
                                <span className="font-medium text-white group-hover:text-cyber-300">{m.display_name || m.handle || m.user_id.slice(0, 8)}</span>
                                <ChevronLeft className="h-3.5 w-3.5 text-slate-600 transition group-hover:-translate-x-0.5 group-hover:text-cyber-300" />
                              </Link>
                              <p dir="ltr" className="text-right font-mono text-[10px] text-slate-500">{m.handle ? `@${m.handle} · ` : ""}{m.role}{isActive ? "" : " · inactive"}</p>
                            </td>
                            <td dir="ltr" className="px-4 py-2.5 text-right font-mono text-[12px] text-slate-300">{s?.email ?? "—"}</td>
                            <td className={`px-4 py-2.5 font-mono ${s && s.task_accuracy !== null && s.task_accuracy < 60 ? "text-severity-high" : "text-slate-200"}`}
                              title={s && s.tasks_graded ? `${s.task_accuracy}% נכונות ב-${s.tasks_graded} משימות מדורגות` : "אין עדיין משימות מדורגות"}>
                              {s && s.task_accuracy !== null ? `${s.task_accuracy}%` : "—"}
                            </td>
                            <td className="px-4 py-2.5">
                              {s ? (
                                <div className="flex items-center gap-2" title={`${s.rooms_completed} חדרים הושלמו`}>
                                  <span className="h-1.5 w-14 overflow-hidden rounded-full bg-bg">
                                    <span className="block h-full bg-cyber-500" style={{ width: `${studentPathPercent(s.completed_room_ids)}%` }} />
                                  </span>
                                  <span className="font-mono text-[11px] text-slate-400">{studentPathPercent(s.completed_room_ids)}%</span>
                                </div>
                              ) : <span className="text-slate-600">—</span>}
                            </td>
                            <td className="px-4 py-2.5 font-mono text-[12px] text-slate-300" title="שיעור זיהוי ממוצע בדשבורד החי">
                              {s && s.avg_detect_rate !== null ? `${s.avg_detect_rate}%` : "—"}
                            </td>
                            <td className="px-4 py-2.5 font-mono font-bold text-cyber-300">{(m.xp ?? 0).toLocaleString()}</td>
                            <td className={`px-4 py-2.5 text-[12px] ${!s?.last_active_at ? "text-slate-600" : Date.now() - Date.parse(s.last_active_at) >= 14 * 86_400_000 ? "text-neon-amber" : "text-slate-400"}`}>
                              {sinceLabel(s?.last_active_at ?? null)}
                            </td>
                            <td className="px-4 py-2.5">
                              <div className="flex items-center justify-end gap-1">
                                {isActive ? (
                                  <button onClick={() => setActive(m.user_id, false)} aria-label={`השבת את ${m.handle ?? "התלמיד"}`} title="סמן כלא-פעיל"
                                    className="rounded p-1.5 text-slate-400 transition hover:bg-neon-amber/10 hover:text-neon-amber"><PowerOff className="h-4 w-4" /></button>
                                ) : (
                                  <button onClick={() => setActive(m.user_id, true)} aria-label={`הפעל את ${m.handle ?? "התלמיד"}`} title="סמן כפעיל"
                                    className="rounded p-1.5 text-slate-400 transition hover:bg-neon-green/10 hover:text-neon-green"><Power className="h-4 w-4" /></button>
                                )}
                                <button onClick={() => removeMember(m.user_id)} aria-label={`הסר את ${m.handle ?? "התלמיד"}`} title="הסר מהכיתה"
                                  className="rounded p-1.5 text-slate-400 transition hover:bg-severity-high/10 hover:text-severity-high"><Trash2 className="h-4 w-4" /></button>
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
