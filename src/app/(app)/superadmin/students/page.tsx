"use client";
/**
 * Platform-wide student list (super-admin). Every member across every
 * environment in one filterable table — the global view the per-org roster and
 * org-detail Members list can't give. Backed by GET /api/superadmin/students
 * (requireSuperAdmin, cross-tenant).
 */
import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { Topbar } from "@/components/nav/Topbar";
import { usePageTitle } from "@/lib/hooks/usePageTitle";
import { Card } from "@/components/ui/Card";
import { ArrowLeft, Loader2, AlertTriangle, Users, Search } from "lucide-react";
import type { GlobalStudentRow } from "@/app/api/superadmin/students/route";

function since(iso: string | null): string {
  if (!iso) return "never";
  const days = Math.floor((Date.now() - Date.parse(iso)) / 86_400_000);
  if (days <= 0) return "today";
  if (days === 1) return "yesterday";
  if (days < 30) return `${days}d ago`;
  return new Date(iso).toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "2-digit" });
}

export default function SuperadminStudentsPage() {
  usePageTitle("All students");
  const [students, setStudents] = useState<GlobalStudentRow[] | null>(null);
  const [orgs, setOrgs] = useState<Array<{ id: string; name: string }>>([]);
  const [error, setError] = useState<string | null>(null);
  const [orgFilter, setOrgFilter] = useState("all");
  const [roleFilter, setRoleFilter] = useState("student");
  const [q, setQ] = useState("");

  useEffect(() => {
    fetch("/api/superadmin/students")
      .then(async r => (r.ok ? r.json() : Promise.reject((await r.json().catch(() => ({})))?.error ?? "Failed to load.")))
      .then(d => { setStudents(d.students ?? []); setOrgs(d.orgs ?? []); })
      .catch(e => setError(String(e)));
  }, []);

  const rows = useMemo(() => {
    if (!students) return [];
    const needle = q.trim().toLowerCase();
    return students.filter(s =>
      (orgFilter === "all" || s.org_id === orgFilter) &&
      (roleFilter === "all" || s.role === roleFilter) &&
      (!needle || (s.display_name ?? "").toLowerCase().includes(needle) || (s.handle ?? "").toLowerCase().includes(needle) || s.org_name.toLowerCase().includes(needle)),
    );
  }, [students, orgFilter, roleFilter, q]);

  const entered = rows.filter(r => r.last_active_at).length;
  const control = "h-9 rounded-md border border-border bg-bg px-3 text-sm text-white focus:border-cyber-500/50 focus:outline-none focus:ring-2 focus:ring-cyber-500/30";

  return (
    <div>
      <Topbar title="All students" subtitle="Every learner across every environment" />
      <div className="container mx-auto max-w-[1100px] px-6 py-6 space-y-5">
        <Link href="/superadmin" className="inline-flex items-center gap-1.5 text-sm text-slate-400 transition hover:text-white">
          <ArrowLeft className="h-4 w-4" /> Back to organizations
        </Link>

        {error && <div className="flex items-center gap-2 rounded-lg border border-severity-high/40 bg-severity-high/10 px-4 py-3 text-sm text-severity-high"><AlertTriangle className="h-4 w-4" />{error}</div>}

        {students === null ? (
          <div className="flex items-center gap-2 text-sm text-slate-400"><Loader2 className="h-4 w-4 animate-spin" /> Loading…</div>
        ) : (
          <>
            {/* filters */}
            <div className="flex flex-wrap items-center gap-3">
              <div className="relative flex-1 min-w-[200px]">
                <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
                <input value={q} onChange={e => setQ(e.target.value)} placeholder="Search name, handle or college…" className={`${control} w-full pl-8`} />
              </div>
              <select value={orgFilter} onChange={e => setOrgFilter(e.target.value)} className={control} aria-label="Filter by college">
                <option value="all">All colleges</option>
                {orgs.map(o => <option key={o.id} value={o.id}>{o.name}</option>)}
              </select>
              <select value={roleFilter} onChange={e => setRoleFilter(e.target.value)} className={control} aria-label="Filter by role">
                <option value="student">Students</option>
                <option value="instructor">Instructors</option>
                <option value="org_admin">Org admins</option>
                <option value="all">All roles</option>
              </select>
            </div>

            <p className="flex items-center gap-2 text-sm text-slate-400">
              <Users className="h-4 w-4 text-cyber-300" />
              <span className="font-bold text-white">{rows.length}</span> shown · <span className="font-bold text-white">{entered}</span> have entered the system
            </p>

            <Card className="overflow-hidden p-0">
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead>
                    <tr className="border-b border-border text-[11px] uppercase tracking-wider text-slate-400">
                      <th className="px-4 py-2.5 font-medium">Student</th>
                      <th className="px-4 py-2.5 font-medium">Email</th>
                      <th className="px-4 py-2.5 font-medium">College</th>
                      <th className="px-4 py-2.5 font-medium">Rooms</th>
                      <th className="px-4 py-2.5 font-medium">Scenarios</th>
                      <th className="px-4 py-2.5 font-medium">Avg</th>
                      <th className="px-4 py-2.5 font-medium">Mistakes</th>
                      <th className="px-4 py-2.5 font-medium">XP</th>
                      <th className="px-4 py-2.5 font-medium">Last active</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/60">
                    {rows.length === 0 ? (
                      <tr><td colSpan={9} className="px-4 py-6 text-center text-sm text-slate-400">No students match these filters.</td></tr>
                    ) : rows.map(s => (
                      <tr key={`${s.org_id}-${s.user_id}`} className="hover:bg-white/[0.02]">
                        <td className="px-4 py-2.5">
                          <p className="font-medium text-white">{s.display_name || s.handle || s.user_id.slice(0, 8)}</p>
                          <p className="font-mono text-[11px] text-slate-500">{s.handle ? `@${s.handle}` : ""} · {s.role}{s.status !== "active" ? ` · ${s.status}` : ""}</p>
                        </td>
                        <td className="px-4 py-2.5 font-mono text-[12px] text-slate-300">{s.email ?? "—"}</td>
                        <td className="px-4 py-2.5 text-slate-300">{s.org_name}</td>
                        <td className="px-4 py-2.5 font-mono text-slate-400">{s.rooms_completed}/{s.rooms_started}</td>
                        <td className="px-4 py-2.5 font-mono text-slate-400">{s.scenarios_completed}</td>
                        <td className={`px-4 py-2.5 font-mono ${s.scenario_avg_score !== null && s.scenario_avg_score < 60 ? "text-severity-high" : "text-slate-300"}`}>{s.scenario_avg_score === null ? "—" : `${s.scenario_avg_score}%`}</td>
                        <td className={`px-4 py-2.5 font-mono ${s.mistakes > 0 ? "text-neon-amber" : "text-slate-500"}`}>{s.mistakes}</td>
                        <td className="px-4 py-2.5 font-mono text-cyber-300">{s.xp.toLocaleString()}</td>
                        <td className={`px-4 py-2.5 text-[12px] ${!s.last_active_at ? "text-slate-600" : Date.now() - Date.parse(s.last_active_at) >= 14 * 86_400_000 ? "text-neon-amber" : "text-slate-400"}`}>{since(s.last_active_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          </>
        )}
      </div>
    </div>
  );
}
