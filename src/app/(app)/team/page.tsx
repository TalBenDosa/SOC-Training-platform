"use client";
/**
 * Team-SOC training — index (Phase 0.3). Staff see the Session Builder (pick a
 * company + difficulty + optional storyline, invite org members with roles);
 * everyone sees the sessions they belong to and can enter the lobby. The exercise
 * itself lives at /team/[id].
 *
 * Exercise-report #18: the builder now says exactly why "Create & open lobby" is
 * disabled (builderStatus), searches the roster, names the org it invites from
 * (candidates are scoped server-side to the caller's org — /api/team/candidates),
 * shows a loading state instead of a false "No active members", and lets staff
 * pin the storyline (team_sessions.scenario_id, already in the schema).
 */
import { parseTenant, TENANT_TEMPLATE } from "@/lib/team/tenant";
import { useEffect, useMemo, useRef, useState } from "react";
import { StackPicker, stackDelta } from "@/components/training/StackPicker";
import { EnvironmentPicker } from "@/components/training/EnvironmentPicker";
import { DEFAULT_ENV, type TeamEnv } from "@/lib/team/environment";
import type { Stack } from "@/lib/logs/native/stack";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { usePageTitle } from "@/lib/hooks/usePageTitle";
import { useOrgContext } from "@/lib/auth/useOrgContext";
import { COMPANY_PROFILES } from "@/lib/sim/companyProfilesMeta";
import { Users, Plus, Loader2, AlertTriangle, ChevronRight, Radio, Search, Building2 } from "lucide-react";
import { builderStatus, filterCandidates, looksLikeEmail, MAX_INVITES, type Candidate } from "./_lib/builder";

type Diff = "easy" | "medium" | "hard";
// Team role set: T1 & T2 take MANY players; T3 and the SOC Manager are single-seat.
const PLAY_ROLES = [
  { id: "t1", label: "Tier-1 Triage" }, { id: "t2", label: "Tier-2 Investigator" },
  { id: "t3", label: "Tier-3 / Threat Hunter" }, { id: "mgr", label: "SOC Manager" },
];
const SINGLE_SEAT = new Set(["t3", "mgr"]); // at most one participant each
const ORG_ROLE_LABEL: Record<string, string> = { org_admin: "admin", instructor: "instructor", student: "student" };

interface SessionRow {
  id: string; company_id: string; tenant_name?: string | null; difficulty: string; status: string; created_at: string;
  my_role: string | null; player_count: number; ready_count: number;
}
interface OrgInfo { id: string; name: string; is_root: boolean }
interface Storyline { id: string; title: string; complexity: string; steps: number }

const STATUS_STYLE: Record<string, string> = {
  lobby: "border-neon-amber/40 bg-neon-amber/10 text-neon-amber",
  running: "border-neon-green/40 bg-neon-green/10 text-neon-green",
  paused: "border-cyber-500/40 bg-cyber-500/10 text-cyber-300",
  ended: "border-slate-600 bg-slate-800/60 text-slate-400",
  debriefed: "border-slate-600 bg-slate-800/60 text-slate-400",
};

export default function TeamIndexPage() {
  usePageTitle("Team training");
  const router = useRouter();
  const { isPlatformAdmin, orgRole, orgName } = useOrgContext();
  const isStaff = isPlatformAdmin || orgRole === "org_admin" || orgRole === "instructor";
  // Org admins, instructors and platform admins can open a lobby
  // (POST /api/team/sessions → requireOrgStaff), so every staff role gets the builder.
  const canCreate = isStaff;

  const [sessions, setSessions] = useState<SessionRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // builder state
  // The exercise runs as the instructor's own organization: its English name is the domain
  // (acme → acme.com); employees, roles and every log are generated under it. Its environment
  // (platforms it runs, industry) and products decide the attacks drawn — the Live-SOC companies
  // stay on the dashboard.
  const company = TENANT_TEMPLATE;
  const [orgNameInput, setOrgNameInput] = useState("");
  const tenantCheck = orgNameInput.trim() ? parseTenant(orgNameInput) : null;
  const tenant = tenantCheck && !("error" in tenantCheck) ? tenantCheck : null;
  const [difficulty, setDifficulty] = useState<Diff>("medium");
  const [storylines, setStorylines] = useState<Storyline[] | null>(null);
  const [storyline, setStoryline] = useState("");   // "" = random pick at start
  // QA L3: a pinned storyline that stops fitting (company / difficulty / products changed)
  // falls back to Random — and the builder now SAYS so instead of clearing it silently.
  const [storyNote, setStoryNote] = useState<string | null>(null);
  const pickedStory = useRef<{ id: string; title: string } | null>(null);
  // Security products the session runs on (spec §3); empty = the company's own.
  const [stack, setStack] = useState<Stack>({});
  const stackParam = JSON.stringify(stackDelta(company, stack));
  const [env, setEnv] = useState<TeamEnv>({ ...DEFAULT_ENV, platforms: [...DEFAULT_ENV.platforms] });
  const envParam = JSON.stringify(env);
  const [roster, setRoster] = useState<Candidate[] | null>(null);   // null = not loaded yet
  const [rosterError, setRosterError] = useState<string | null>(null);
  const [org, setOrg] = useState<OrgInfo | null>(null);
  const [query, setQuery] = useState("");
  const [emailMatch, setEmailMatch] = useState<{ q: string; user_id: string | null } | null>(null);
  const [picked, setPicked] = useState<Record<string, string>>({}); // user_id -> role
  const [creating, setCreating] = useState(false);

  async function load() {
    setError(null);
    const res = await fetch("/api/team/sessions").catch(() => null);   // P5-07: a network drop left "Loading…" forever
    setLoading(false);
    if (!res) { setError("Couldn't reach the server — check your connection and reload."); return; }
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Failed to load."); return; }
    setSessions((await res.json()).sessions ?? []);
  }
  async function loadRoster() {
    setRosterError(null);
    const res = await fetch("/api/team/candidates").catch(() => null);
    if (!res || !res.ok) {
      setRosterError((await res?.json().catch(() => ({})))?.error ?? "network error");
      setRoster([]);
      return;
    }
    const data = await res.json();
    setOrg(data.org ?? null);
    setRoster(data.members ?? []);
  }
  useEffect(() => { load(); }, []);
  useEffect(() => { if (canCreate) loadRoster(); }, [canCreate]);

  // Storylines that fit the organization's environment, products and difficulty (staff-only list).
  useEffect(() => {
    if (!canCreate) return;
    let cancelled = false;
    setStorylines(null);
    fetch(`/api/team/storylines?company=${encodeURIComponent(company)}&difficulty=${difficulty}&stack=${encodeURIComponent(stackParam)}&env=${encodeURIComponent(envParam)}`)
      .then(r => (r.ok ? r.json() : { storylines: [] }))
      .then(d => {
        if (cancelled) return;
        const list: Storyline[] = d.storylines ?? [];
        setStorylines(list);
        const cur = pickedStory.current;
        if (cur && !list.some(s => s.id === cur.id)) {
          pickedStory.current = null;
          setStoryline("");
          setStoryNote(`“${cur.title}” doesn't fit this environment, difficulty and products — the storyline is back to Random.`);
        }
      })
      .catch(() => { if (!cancelled) setStorylines([]); });
    return () => { cancelled = true; };
  }, [canCreate, company, difficulty, stackParam, envParam]);

  // A full e-mail in the search box → exact server-side match within the org
  // (the list itself never carries addresses). Debounced; POST keeps it out of URLs.
  useEffect(() => {
    const q = query.trim();
    if (!canCreate || !looksLikeEmail(q)) { setEmailMatch(null); return; }
    const t = setTimeout(async () => {
      const res = await fetch("/api/team/candidates", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email: q }),
      }).catch(() => null);
      const data = res && res.ok ? await res.json().catch(() => ({})) : {};
      setEmailMatch({ q, user_id: typeof data.user_id === "string" ? data.user_id : null });
    }, 350);
    return () => clearTimeout(t);
  }, [query, canCreate]);

  const emailMode = looksLikeEmail(query);
  const emailId = emailMatch && emailMatch.q === query.trim() ? emailMatch.user_id : null;
  const visible = useMemo(
    () => (roster ? filterCandidates(roster, query, picked, emailId) : []),
    [roster, query, picked, emailId],
  );
  const orgLabel = org?.name ?? orgName ?? null;
  const status = builderStatus({
    rosterLoading: roster === null, rosterError, rosterCount: roster?.length ?? 0, orgName: orgLabel, picked,
  });
  const roleCounts = PLAY_ROLES
    .map(r => ({ ...r, n: Object.values(picked).filter(v => v === r.id).length }))
    .filter(r => r.n > 0);

  function togglePick(userId: string) {
    setPicked(p => {
      const c = { ...p };
      if (c[userId]) delete c[userId]; else c[userId] = "t1";
      return c;
    });
  }

  // Enforce single-seat roles (T3, Manager): block a second assignment.
  function setRole(userId: string, role: string) {
    if (SINGLE_SEAT.has(role) && Object.entries(picked).some(([u, r]) => u !== userId && r === role)) {
      const lbl = PLAY_ROLES.find(r => r.id === role)?.label ?? role;
      setError(`${lbl} takes a single participant — it's already assigned.`);
      return;
    }
    setError(null);
    setPicked(p => ({ ...p, [userId]: role }));
  }

  async function createSession() {
    if (!tenant) { setError(tenantCheck && "error" in tenantCheck ? tenantCheck.error : "Enter your organization's name in English — it becomes the exercise's domain."); return; }
    if (!status.canCreate) { setError(status.blocker); return; }
    const invites = Object.entries(picked).map(([user_id, role]) => ({ user_id, role }));
    setCreating(true); setError(null);
    const res = await fetch("/api/team/sessions", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tenant_name: tenant.name, difficulty, invites, env, stack: stackDelta(company, stack), ...(storyline ? { scenario_id: storyline } : {}) }),
    }).catch(() => null);
    setCreating(false);
    if (!res) { setError("Couldn't reach the server — check your connection and try again."); return; }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { setError(data?.error ?? "Could not create the session."); return; }
    router.push(`/team/${data.id}`);
  }

  const companyName = (s: { company_id: string; tenant_name?: string | null }) => s.tenant_name ?? COMPANY_PROFILES.find(c => c.id === s.company_id)?.name ?? s.company_id;

  return (
    <div>
      <Topbar title="Team training" subtitle="Run a shared SOC incident with your team" />
      <div className="container mx-auto max-w-[1000px] px-6 py-6 space-y-6">
        {error && (
          <div className="flex items-center gap-2 rounded-lg border border-severity-high/40 bg-severity-high/10 px-4 py-3 text-sm text-severity-high">
            <AlertTriangle className="h-4 w-4" />{error}
          </div>
        )}


        {canCreate && (
          <Card>
            <h2 className="flex items-center gap-2 text-sm font-bold text-white">
              <Plus className="h-4 w-4 text-cyber-300" /> New team exercise
            </h2>
            <div className="mt-4 grid gap-4 sm:grid-cols-3">
              <label className="block text-sm" htmlFor="team-org-name">
                <span className="mb-1 block text-xs uppercase tracking-wider text-slate-400">Organization (English)</span>
                <input id="team-org-name" value={orgNameInput} onChange={e => setOrgNameInput(e.target.value)} dir="ltr" lang="en"
                  placeholder="e.g. acme or acme-labs.io" autoComplete="off" spellCheck={false} maxLength={44}
                  aria-invalid={!!(tenantCheck && "error" in tenantCheck)} aria-describedby="team-org-help"
                  className={`w-full rounded-lg border bg-bg px-3 py-2 text-sm text-slate-200 focus:outline-none ${tenantCheck && "error" in tenantCheck ? "border-severity-high/60" : "border-border focus:border-cyber-500/50"}`} />
                <span id="team-org-help" className={`mt-1 block text-[11px] ${tenantCheck && "error" in tenantCheck ? "text-severity-high" : "text-slate-500"}`}>
                  {tenantCheck && "error" in tenantCheck ? tenantCheck.error
                    : tenant ? <>Domain <span className="font-mono text-slate-300">{tenant.domain}</span> · realm <span className="font-mono text-slate-300">{tenant.netbios}</span> — employees and roles are generated for it</>
                    : "Becomes the exercise's domain. Employees, roles and all logs are generated under it."}
                </span>
              </label>
              <label className="block text-sm">
                <span className="mb-1 block text-xs uppercase tracking-wider text-slate-400">Difficulty</span>
                <select value={difficulty} onChange={e => setDifficulty(e.target.value as Diff)}
                  className="w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm text-slate-200 focus:border-cyber-500/50 focus:outline-none">
                  <option value="easy">Easy</option><option value="medium">Medium</option><option value="hard">Hard</option>
                </select>
              </label>
              <label className="block text-sm">
                <span className="mb-1 block text-xs uppercase tracking-wider text-slate-400">Storyline</span>
                <select value={storyline} disabled={storylines === null}
                  onChange={e => {
                    const v = e.target.value;
                    setStoryline(v); setStoryNote(null);
                    const t = (storylines ?? []).find(s => s.id === v);
                    pickedStory.current = t ? { id: t.id, title: t.title } : null;
                  }}
                  className="w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm text-slate-200 disabled:opacity-50 focus:border-cyber-500/50 focus:outline-none">
                  <option value="">{storylines === null ? "Loading storylines…" : "Random — picked at start"}</option>
                  {(storylines ?? []).map(s => <option key={s.id} value={s.id}>{s.title}</option>)}
                </select>
              </label>
            </div>
            <div className="mt-3 space-y-2">
              <EnvironmentPicker value={env} onChange={setEnv} storyCount={storylines?.length ?? null} idPrefix="team-env" />
              <StackPicker companyId={company} value={stack} onChange={setStack} idPrefix="team-stack" />
            </div>
            {storyNote && <p role="status" className="mt-1.5 rounded-lg border border-neon-amber/30 bg-neon-amber/[0.06] px-3 py-1.5 text-[11px] text-neon-amber">{storyNote}</p>}
            <p className="mt-1.5 text-[11px] text-slate-500">
              The storyline is the primary incident the team investigates{difficulty === "easy" ? "" : " (medium and hard add a second, random concurrent incident)"}. Only staff see its name — players have to work it out.
            </p>

            <div className="mt-4">
              <div className="mb-1 flex flex-wrap items-baseline justify-between gap-2">
                <p className="text-xs uppercase tracking-wider text-slate-400">Invite &amp; assign roles</p>
                {orgLabel && (
                  <p className="inline-flex items-center gap-1 text-[11px] text-slate-400">
                    <Building2 className="h-3 w-3" aria-hidden /> Inviting from <span className="font-semibold text-slate-200">{orgLabel}</span>
                    {roster && !rosterError && <span className="text-slate-500">· {roster.length} active member{roster.length === 1 ? "" : "s"}</span>}
                  </p>
                )}
              </div>
              <p className="mb-2 text-[11px] text-slate-500">
                Tier-1 &amp; Tier-2 can hold several analysts each · Tier-3 and SOC Manager are single-seat · up to {MAX_INVITES} invitees now, more from inside the lobby.
              </p>
              {isPlatformAdmin && (
                <p className="mb-2 text-[11px] text-slate-500">
                  {org?.is_root
                    ? "You're in the Main environment (platform-level accounts). To run an exercise for a college, switch to its environment in the sidebar first."
                    : "Super-admin: the session is created in this environment. Switch environments in the sidebar to run one for another college."}
                </p>
              )}

              {roster === null ? (
                <div className="flex items-center gap-2 py-2 text-sm text-slate-400"><Loader2 className="h-4 w-4 animate-spin" /> Loading members…</div>
              ) : rosterError ? (
                <p className="text-sm text-severity-high">Couldn&apos;t load members: {rosterError}</p>
              ) : roster.length === 0 ? (
                <p className="text-sm text-slate-400">No other active members in {orgLabel ?? "your organisation"} yet. Add students to your class first.</p>
              ) : (
                <>
                  <div className="relative mb-2">
                    <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" aria-hidden />
                    <input value={query} onChange={e => setQuery(e.target.value)} type="search"
                      aria-label="Search members by name, handle or e-mail"
                      placeholder="Search by name, @handle or full e-mail…"
                      className="w-full rounded-lg border border-border bg-bg py-2 pl-8 pr-3 text-sm text-slate-200 placeholder:text-slate-600 focus:border-cyber-500/50 focus:outline-none" />
                  </div>
                  {emailMode && emailMatch?.q === query.trim() && !emailId && (
                    <p className="mb-2 text-[11px] text-slate-500">No active member of {orgLabel ?? "your organisation"} has that e-mail.</p>
                  )}
                  {!emailMode && query.trim() && visible.length === 0 && (
                    <p className="mb-2 text-[11px] text-slate-500">No member matches &ldquo;{query.trim()}&rdquo;.</p>
                  )}
                  <div className="max-h-[360px] space-y-1.5 overflow-y-auto pr-1">
                    {visible.map(m => {
                      const on = !!picked[m.user_id];
                      return (
                        <div key={m.user_id} className={`flex items-center gap-3 rounded-lg border px-3 py-2 transition ${on ? "border-cyber-500/40 bg-cyber-500/[0.06]" : "border-border"}`}>
                          <input type="checkbox" checked={on} onChange={() => togglePick(m.user_id)} className="h-4 w-4 accent-cyber-500"
                            aria-label={`Invite ${m.display_name || m.handle || "member"}`} />
                          <span className="min-w-0 flex-1 truncate text-sm text-slate-200">
                            {m.display_name || m.handle || m.user_id.slice(0, 8)}
                            {m.handle && <span className="ml-1 font-mono text-[11px] text-slate-500">@{m.handle}</span>}
                            {m.role && m.role !== "student" && <span className="ml-1.5 rounded border border-border px-1 py-px text-[9px] uppercase tracking-wider text-slate-500">{ORG_ROLE_LABEL[m.role] ?? m.role}</span>}
                          </span>
                          <select value={picked[m.user_id] ?? "t1"} disabled={!on}
                            onChange={e => setRole(m.user_id, e.target.value)}
                            aria-label="Exercise role"
                            className="rounded-md border border-border bg-bg px-2 py-1 text-xs text-slate-200 disabled:opacity-40 focus:border-cyber-500/50 focus:outline-none">
                            {PLAY_ROLES.map(r => <option key={r.id} value={r.id}>{r.label}{SINGLE_SEAT.has(r.id) ? " · 1 seat" : " · multi"}</option>)}
                          </select>
                        </div>
                      );
                    })}
                  </div>
                </>
              )}
            </div>

            {status.warnings.map(w => (
              <p key={w} className="mt-3 rounded-lg border border-neon-amber/30 bg-neon-amber/[0.06] px-3 py-2 text-[11px] text-neon-amber">⚠ {w}</p>
            ))}
            <div className="mt-4 flex flex-wrap items-center gap-3">
              <Button variant="primary" size="sm" disabled={creating || !status.canCreate} onClick={createSession}
                aria-describedby="team-create-hint">
                {creating ? <Loader2 className="mr-1.5 h-4 w-4 animate-spin" /> : <Plus className="mr-1.5 h-4 w-4" />}
                Create &amp; open lobby
              </Button>
              {/* #18: say exactly why the button is disabled and what to do. */}
              <span id="team-create-hint" role="status" className={`min-w-0 flex-1 text-xs ${status.canCreate ? "text-slate-500" : "text-neon-amber"}`}>
                {status.blocker ?? `${roleCounts.map(r => `${r.n}× ${r.label}`).join(" · ")}. You'll run it as instructor; each invitee clicks Ready in the lobby, then you press Start.`}
              </span>
            </div>
          </Card>
        )}

        <Card className="overflow-hidden p-0">
          <div className="px-4 py-3">
            <h2 className="flex items-center gap-2 text-sm font-bold text-white"><Users className="h-4 w-4 text-cyber-300" /> Your sessions</h2>
          </div>
          {loading ? (
            <div className="flex items-center gap-2 px-4 pb-4 text-sm text-slate-400"><Loader2 className="h-4 w-4 animate-spin" /> Loading…</div>
          ) : sessions.length === 0 ? (
            <p className="px-4 pb-4 text-sm text-slate-400">No team sessions yet.{isStaff ? " Create one above." : " You'll see exercises here once your instructor invites you."}</p>
          ) : (
            <div className="divide-y divide-border/60">
              {sessions.map(s => {
                // Closed sessions (ended/debriefed) can't be entered — they're a
                // record only. Live/lobby/paused stay enterable.
                const closed = s.status === "ended" || s.status === "debriefed";
                const inner = (
                  <>
                    <span className={`rounded-full border px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider ${STATUS_STYLE[s.status] ?? STATUS_STYLE.ended}`}>
                      {s.status === "running" ? <span className="inline-flex items-center gap-1"><Radio className="h-2.5 w-2.5" />live</span> : closed ? "closed" : s.status}
                    </span>
                    <div className="min-w-0 flex-1">
                      <p className={`truncate text-sm font-medium ${closed ? "text-slate-400" : "text-white"}`}>{companyName(s)}</p>
                      <p className="font-mono text-[11px] text-slate-500">
                        {s.difficulty} · {s.ready_count}/{s.player_count} ready
                        {s.my_role && s.my_role !== "instructor" && <span className="ml-1 text-cyber-300">· you: {s.my_role}</span>}
                        {s.my_role === "instructor" && <span className="ml-1 text-neon-amber">· you: instructor</span>}
                      </p>
                    </div>
                    {closed
                      ? <span className="shrink-0 rounded-md border border-border px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-cyber-300">Shift review</span>
                      : <ChevronRight className="h-4 w-4 text-slate-600" aria-hidden />}
                  </>
                );
                // U7: the whole row is the link. Closed sessions open their read-only
                // shift review (the room itself renders only the report once ended).
                return (
                  <Link key={s.id} href={`/team/${s.id}`}
                    aria-label={closed ? `${companyName(s)} — closed, open shift review` : `${companyName(s)} — ${s.status}, open session`}
                    className="flex items-center gap-3 px-4 py-3 transition hover:bg-white/[0.02] focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyber-500/60">{inner}</Link>
                );
              })}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
