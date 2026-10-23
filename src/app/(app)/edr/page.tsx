"use client";
/**
 * Standalone EDR console — investigate a host the way an analyst does on
 * CrowdStrike Falcon / Defender for Endpoint: walk the process ANCESTRY tree,
 * read command lines, look up hashes, then decide (isolate the payload, or
 * resolve as benign). Data is self-contained (src/lib/edr/investigations.ts);
 * hash lookups hit the real hashDatabase so "Look up hash" returns a genuine
 * verdict.
 */
import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { usePageTitle } from "@/lib/hooks/usePageTitle";
import { EDR_INVESTIGATIONS, type EdrInvestigation } from "@/lib/edr/investigations";
import { isTrainingActive, TRAINING_EVENT, TRAINING_KEY } from "@/lib/sim/trainingSession";
import { teamEndedKey, teamSessionClosed, teamSessionMarkedEnded } from "@/lib/team/edrLock";
import { EdrConsole } from "@/components/edr/EdrConsole";
import { useTeamHeartbeat } from "@/lib/team/useTeamHeartbeat";
import { useTeamIsolation } from "@/lib/team/useTeamIsolation";

export default function EdrConsolePage() {
  usePageTitle("EDR Console");
  const router = useRouter();
  // A plain client component (no useSearchParams / Suspense) so the page hydrates
  // normally on a hard load or refresh — an earlier Suspense-wrapped
  // useSearchParams left the console rendered but NON-interactive after a direct
  // navigation. The deep-link (?case=…) is read post-mount instead, which also
  // avoids any server/client hydration mismatch.
  const [allowed, setAllowed] = useState<boolean | null>(null); // null = still checking
  // A team room may stash several hosts (one case per escalated endpoint) → the Incidents list.
  const [liveInvs, setLiveInvs] = useState<EdrInvestigation[] | null>(null);
  const [invId, setInvId] = useState<string | null>(null); // set from ?case; null → Incidents list
  // Opened from a live Team-SOC room (?team=<id>): keep the analyst "present" for
  // the server-side lifecycle while they investigate here — T2/T3 can spend
  // minutes in this tab, and the room's own tab is then hidden/throttled.
  const [teamSession, setTeamSession] = useState<string | null>(null);
  const [teamRole, setTeamRole] = useState<string | null>(null);
  // Set once the shift or team exercise this console belongs to is over.
  const [closed, setClosed] = useState<"shift" | "team" | null>(null);
  useTeamHeartbeat(closed ? null : teamSession);
  const teamIsolation = useTeamIsolation(teamSession, teamRole);

  // SOC Dashboard shift: the Dashboard drops the "training active" flag on every way a shift
  // ends (auto-advance, company switch, leaving the Dashboard); this tab follows it live, and
  // opens again if the Dashboard resumes the shift (a refresh mid-shift).
  useEffect(() => {
    if (!allowed || teamSession) return;
    const sync = () => setClosed(isTrainingActive() ? null : "shift");
    const onStorage = (ev: StorageEvent) => { if (ev.key === null || ev.key === TRAINING_KEY) sync(); };
    window.addEventListener("storage", onStorage);
    window.addEventListener(TRAINING_EVENT, sync);
    return () => { window.removeEventListener("storage", onStorage); window.removeEventListener(TRAINING_EVENT, sync); };
  }, [allowed, teamSession]);

  // Team exercise: closed when the room marks the session over (instant, via storage) or when
  // the server says it ended / the analyst was removed (polled, and on returning to the tab).
  useEffect(() => {
    if (!teamSession) return;
    let stop = false;
    const check = async () => {
      if (stop) return;
      if (teamSessionMarkedEnded(teamSession)) { setClosed("team"); return; }
      try {
        const res = await fetch(`/api/team/sessions/${teamSession}`, { cache: "no-store" });
        const body = res.ok ? await res.json().catch(() => null) : null;
        if (!stop && teamSessionClosed(res.status, body?.session?.status)) setClosed("team");
      } catch { /* offline: try again on the next tick */ }
    };
    void check();
    const iv = setInterval(check, 20_000);
    const onStorage = (ev: StorageEvent) => { if (ev.key === teamEndedKey(teamSession)) setClosed("team"); };
    const onVisible = () => { if (document.visibilityState === "visible") void check(); };
    window.addEventListener("storage", onStorage);
    document.addEventListener("visibilitychange", onVisible);
    return () => { stop = true; clearInterval(iv); window.removeEventListener("storage", onStorage); document.removeEventListener("visibilitychange", onVisible); };
  }, [teamSession]);

  useEffect(() => {
    // The EDR console is ONLY reachable from an active shift — the student must
    // have pressed Start Training on the Dashboard. No shift → bounce back to
    // the Dashboard (there's nothing to investigate on the endpoint yet).
    // EXCEPTION (team exercise, G-05): a deep-link carrying ?team=<sessionId>
    // comes from a live Team-SOC room, which is its own "active shift" — the team
    // page stashed the investigation in localStorage before opening this tab, so
    // allow it through instead of bouncing to the single-player dashboard.
    const params = new URLSearchParams(window.location.search);
    const teamCtx = params.get("team");
    if (!isTrainingActive() && !teamCtx) { router.replace("/dashboard"); return; }
    setAllowed(true);
    if (teamCtx && /^[0-9a-fA-F-]{36}$/.test(teamCtx)) setTeamSession(teamCtx);
    const r = params.get("r");
    if (r && /^[a-z0-9]{1,16}$/.test(r)) setTeamRole(r);   // display only: the server gates the action
    // Deep-link from the SOC Dashboard: /edr?case=<id> opens that host, the
    // "Investigate in EDR" pivot. case=live loads the EdrInvestigation the
    // Dashboard (or a team room) generated from the attack running in the feed.
    const requested = params.get("case");
    // A bare /edr during a shift is the live console too (the static practice cases open
    // only by their explicit ?case=<id>).
    if (requested === "live" || !requested) {
      // localStorage (shared across tabs) — the opener stashed it here so this EDR
      // tab can read the live attack it generated. A team room passes ?u=<user id>
      // and stashes under a PER-USER key so two analysts don't clobber each other
      // (B8); the dashboard's single-player key is the fallback.
      const u = params.get("u");
      const keys = [...(u ? [`edr_live_investigation_${u}`] : []), "edr_live_investigation"];
      const read = (): EdrInvestigation[] => {
        try {
          const raw = keys.map(k => localStorage.getItem(k)).find(Boolean) ?? "null";
          const stashed = JSON.parse(raw);
          return (Array.isArray(stashed) ? stashed : [stashed]).filter((x: EdrInvestigation | null) => x?.id);
        } catch { return []; }
      };
      // A live shift shows ONLY the shift's own hosts, built from logs already in the SIEM
      // feed. Before the attack reaches an endpoint that is an empty list, never the
      // built-in practice cases (their hosts belong to no company and no SIEM log backs them).
      const first = read();
      setLiveInvs(first);
      setInvId(first.length === 1 ? first[0].id : null);
      // The Dashboard re-stashes as each new endpoint log reaches the feed: follow it live.
      const onStorage = (ev: StorageEvent) => { if (ev.key && keys.includes(ev.key)) setLiveInvs(read()); };
      window.addEventListener("storage", onStorage);
      return () => window.removeEventListener("storage", onStorage);
    }
    if (requested && EDR_INVESTIGATIONS.some(i => i.id === requested)) setInvId(requested);
  }, [router]);

  const investigations = useMemo(
    // In a live shift the analyst investigates the CURRENT incident's host only —
    // showing the unrelated built-in practice cases (FIN-WS-07, RES-SRV-02, …)
    // alongside it cluttered the case-switcher and broke the "one incident, its
    // own isolated case" model. The built-in EDR_INVESTIGATIONS stay as the
    // standalone-practice set, shown only when there is no live attack to walk.
    () => (liveInvs ?? EDR_INVESTIGATIONS),
    [liveInvs],
  );
  if (!allowed) return null; // checking access / redirecting to the Dashboard
  // The shift (or team exercise) this console belongs to is over: nothing more to investigate.
  if (closed) return <EdrClosed reason={closed} teamSession={teamSession} />;
  // A live shift stashed one investigation → open it directly; otherwise (no
  // ?case) fall to the Incidents management page over the built-in practice set.
  // A live shift (or team room) pops a red alert for every new detection; the practice cases don't.
  return <EdrConsole investigations={investigations} initialCaseId={invId ?? undefined} teamIsolation={teamIsolation} liveAlerts={liveInvs !== null} />;
}

function EdrClosed({ reason, teamSession }: { reason: "shift" | "team"; teamSession: string | null }) {
  const team = reason === "team";
  return (
    <div className="flex min-h-[60vh] items-center justify-center p-6">
      <div role="status" className="max-w-md rounded-xl border border-border bg-bg-panel p-6 text-center">
        <h1 className="text-lg font-bold text-white">{team ? "The team exercise has ended" : "The shift has ended"}</h1>
        <p className="mt-2 text-sm text-slate-400">
          {team
            ? "The EDR console is closed for this session. Go back to the team room for the shift review."
            : "The EDR console is only open during a live shift. Start a new shift on the SOC Dashboard to investigate again."}
        </p>
        <a href={team && teamSession ? `/team/${teamSession}` : "/dashboard"}
          className="mt-4 inline-block rounded-lg bg-cyber-500 px-4 py-2 text-sm font-semibold text-[var(--on-accent)] hover:bg-cyber-400">
          {team ? "Back to the team room" : "Back to the SOC Dashboard"}
        </a>
      </div>
    </div>
  );
}
