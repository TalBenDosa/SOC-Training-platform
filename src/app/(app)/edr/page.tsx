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
  const [invId, setInvId] = useState(EDR_INVESTIGATIONS[0].id);

  useEffect(() => {
    // The EDR console is ONLY reachable from an active shift — the student must
    // have pressed Start Training on the Dashboard. No shift → bounce back to
    // the Dashboard (there's nothing to investigate on the endpoint yet).
    if (!isTrainingActive()) { router.replace("/dashboard"); return; }
    setAllowed(true);
    // Deep-link from the SOC Dashboard: /edr?case=<id> opens that host, the
    // "Investigate in EDR" pivot. case=live loads the EdrInvestigation the
    // Dashboard generated from the attack running in the feed (sessionStorage).
    const requested = new URLSearchParams(window.location.search).get("case");
    if (requested === "live") {
      try {
        // localStorage (shared across tabs) — the Dashboard stashed it here so
        // this EDR tab can read the live attack it generated.
        const stashed = JSON.parse(localStorage.getItem("edr_live_investigation") || "null");
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
  const inv = investigations.find(i => i.id === invId) ?? investigations[0];
  if (!allowed) return null; // checking access / redirecting to the Dashboard
  return <EdrConsole key={inv.id} inv={inv} investigations={investigations} onSwitch={setInvId} invId={inv.id} />;
}
