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
import { isTrainingActive } from "@/lib/sim/trainingSession";
import { EdrConsole } from "@/components/edr/EdrConsole";
import { useTeamHeartbeat } from "@/lib/team/useTeamHeartbeat";

export default function EdrConsolePage() {
  usePageTitle("EDR Console");
  const router = useRouter();
  // A plain client component (no useSearchParams / Suspense) so the page hydrates
  // normally on a hard load or refresh — an earlier Suspense-wrapped
  // useSearchParams left the console rendered but NON-interactive after a direct
  // navigation. The deep-link (?case=…) is read post-mount instead, which also
  // avoids any server/client hydration mismatch.
  const [allowed, setAllowed] = useState<boolean | null>(null); // null = still checking
  const [liveInv, setLiveInv] = useState<EdrInvestigation | null>(null);
  const [invId, setInvId] = useState<string | null>(null); // set from ?case; null → Incidents list
  // Opened from a live Team-SOC room (?team=<id>): keep the analyst "present" for
  // the server-side lifecycle while they investigate here — T2/T3 can spend
  // minutes in this tab, and the room's own tab is then hidden/throttled.
  const [teamSession, setTeamSession] = useState<string | null>(null);
  useTeamHeartbeat(teamSession);

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
    // Deep-link from the SOC Dashboard: /edr?case=<id> opens that host, the
    // "Investigate in EDR" pivot. case=live loads the EdrInvestigation the
    // Dashboard (or a team room) generated from the attack running in the feed.
    const requested = params.get("case");
    if (requested === "live") {
      try {
        // localStorage (shared across tabs) — the opener stashed it here so this EDR
        // tab can read the live attack it generated. A team room passes ?u=<user id>
        // and stashes under a PER-USER key so two analysts don't clobber each other
        // (B8); the dashboard's single-player key is the fallback.
        const u = params.get("u");
        const raw = (u && localStorage.getItem(`edr_live_investigation_${u}`)) || localStorage.getItem("edr_live_investigation") || "null";
        const stashed = JSON.parse(raw);
        if (stashed?.id) { setLiveInv(stashed); setInvId(stashed.id); return; }
      } catch { /* fall through to a static case */ }
    }
    if (requested && EDR_INVESTIGATIONS.some(i => i.id === requested)) setInvId(requested);
  }, [router]);

  const investigations = useMemo(
    // In a live shift the analyst investigates the CURRENT incident's host only —
    // showing the unrelated built-in practice cases (FIN-WS-07, RES-SRV-02, …)
    // alongside it cluttered the case-switcher and broke the "one incident, its
    // own isolated case" model. The built-in EDR_INVESTIGATIONS stay as the
    // standalone-practice set, shown only when there is no live attack to walk.
    () => (liveInv ? [liveInv] : EDR_INVESTIGATIONS),
    [liveInv],
  );
  if (!allowed) return null; // checking access / redirecting to the Dashboard
  // A live shift stashed one investigation → open it directly; otherwise (no
  // ?case) fall to the Incidents management page over the built-in practice set.
  return <EdrConsole investigations={investigations} initialCaseId={invId ?? undefined} />;
}
