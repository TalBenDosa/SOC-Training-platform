"use client";
import React, { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import { LibraryCard } from "@/components/ui/LibraryCard";
// Client-safe list only. "@/lib/sim/scenarios" bundles every scenario pack —
// questions, answers, IOCs — so importing it here published the answer keys.
import { SCENARIOS_META as SCENARIOS } from "@/lib/sim/scenariosMeta";
import { getRoomProgress, getScenarioHistory, PROGRESS_HYDRATED_EVENT, XP_CHANGED_EVENT } from "@/lib/storage/progress";
import { fetchPublishedScenarios } from "@/lib/content/publicContent";
import { SCENARIO_PREP } from "@/lib/scenarios/prep";
import { bestScoresBySlug, matchesDoneFilter, DONE_FILTERS, type DoneFilter } from "@/lib/scenarios/completion";
import { ROOMS_META } from "@/data/roomsMeta";
import { AssignedChip } from "@/components/plans/AssignedChip";
import { useAssignedItems } from "@/lib/plans/useAssigned";
import {
  Sparkles, ShieldQuestion, Cloud, Mail, KeyRound, Lock, UserX,
  BotIcon, EyeOff, GraduationCap, Target, ArrowRight,
} from "lucide-react";

// ── Readiness map ──────────────────────────────────────────────────────────
// Scenarios were launchable from day 1 regardless of what the learner had
// studied — the 65% mastery gate that governs Rooms stopped at the door of the
// most meaningful practice on the platform. This maps the scenarios that assume
// specific prior knowledge to the rooms that teach it, and the card shows a
// SOFT "recommended first" hint (never a hard lock — self-paced learners keep
// full freedom). Beginner scenarios are intentionally unmapped: no hint.
// Real room titles for the "recommended first" hint, from the client-safe meta —
// so every prerequisite renders its actual room name (F-10). SCENARIO_PREP now
// lives in @/lib/scenarios/prep (shared with the integrity gate) and covers all 67.
const ROOM_TITLE: Record<string, string> = Object.fromEntries(ROOMS_META.map(r => [r.id, r.title]));

// ─── Types ─────────────────────────────────────────────────────────────────────

interface PublishedScenario {
  id: string;
  title: string;
  threat_actor: string;
  attack_kind: string;
  difficulty: string;
  narrative: string;
  events: unknown[];
  published_at: string;
  // Org-authored scenarios (migration 0040/0041) carry these instead; they route
  // to the safe server-graded /scenarios/[id] path rather than the client preview.
  kind?: string;
  scenario_id?: string;
  briefing?: string;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const ICON: Record<string, React.ElementType> = {
  phishing_to_exfil: Mail,
  identity_bec:      KeyRound,
  ransomware:        Lock,
  oauth_persistence: Cloud,
  insider_threat:    UserX,
};

function diffPill(d: string): string {
  switch (d) {
    case "expert":       return "rounded border border-severity-critical/40 bg-severity-critical/10 px-2 py-0.5 text-[10px] font-bold uppercase text-severity-critical";
    case "advanced":     return "rounded border border-severity-high/40 bg-severity-high/10 px-2 py-0.5 text-[10px] font-bold uppercase text-severity-high";
    case "intermediate": return "rounded border border-severity-medium/40 bg-severity-medium/10 px-2 py-0.5 text-[10px] font-bold uppercase text-severity-medium";
    default:             return "rounded border border-cyber-500/40 bg-cyber-500/10 px-2 py-0.5 text-[10px] font-bold uppercase text-cyber-300";
  }
}

// ─── Page ──────────────────────────────────────────────────────────────────────

export default function ScenariosPage() {
  const router = useRouter();
  const [hidden, setHidden]       = useState<string[]>([]);
  const [published, setPublished] = useState<PublishedScenario[]>([]);
  const [doneRooms, setDoneRooms] = useState<Set<string>>(new Set());
  // FB-006: best score per completed scenario slug, so the list can mark what's done.
  const [bestScore, setBestScore] = useState<Record<string, number>>({});
  // FB-006: "Show: All / Not done / Completed" filter over built-in + custom scenarios.
  const [doneFilter, setDoneFilter] = useState<DoneFilter>("all");
  // "Assigned" chips (one cached request); empty for solo learners.
  const assigned = useAssignedItems();

  // Learner progress read through the storage facade. MUST re-run after the
  // signed-in remote backend is installed: on a hard load (refresh, new tab,
  // landing here first) this page mounts while the backend is still the empty
  // guest/localStorage one, so a mount-only read saw "no history" and the
  // Completed badge never appeared even though scenario_history had the rows
  // (FB-006 root cause). Also re-read when XP changes (a scenario write just
  // landed) and when the tab becomes visible again (finished in another tab).
  const readProgress = useCallback(() => {
    try {
      // Which rooms has the learner actually completed? Drives the soft
      // readiness hint below (via the same facade the Rooms page uses).
      const rp = getRoomProgress() as Record<string, { completedAt?: string }>;
      setDoneRooms(new Set(Object.entries(rp).filter(([, v]) => v?.completedAt).map(([id]) => id)));
      // A scenario is "completed" if it has any history record; keep the best score.
      setBestScore(bestScoresBySlug(getScenarioHistory()));
    } catch { /* storage blocked */ }
  }, []);

  useEffect(() => {
    try {
      setHidden(JSON.parse(localStorage.getItem("admin_hidden_scenarios") ?? "[]"));
    } catch { /* storage blocked */ }
    readProgress();
    const onVisible = () => { if (document.visibilityState === "visible") readProgress(); };
    window.addEventListener(PROGRESS_HYDRATED_EVENT, readProgress);
    window.addEventListener(XP_CHANGED_EVENT, readProgress);
    window.addEventListener("pageshow", readProgress);
    document.addEventListener("visibilitychange", onVisible);
    // Admin-published scenarios now live in the durable content_scenarios
    // table (migration 0019), not per-browser localStorage — this is what
    // makes them actually visible to real students for the first time.
    fetchPublishedScenarios<PublishedScenario>().then(setPublished).catch(() => { /* announced by OrgContentNotice */ });
    return () => {
      window.removeEventListener(PROGRESS_HYDRATED_EVENT, readProgress);
      window.removeEventListener(XP_CHANGED_EVENT, readProgress);
      window.removeEventListener("pageshow", readProgress);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [readProgress]);

  const prepGaps = (slug: string) =>
    (SCENARIO_PREP[slug] ?? []).filter(id => !doneRooms.has(id));

  const visibleBuiltIn = SCENARIOS.filter(s => !hidden.includes(s.slug));
  const authored = published.filter(s => s.kind === "authored" && s.scenario_id);
  const shownBuiltIn = visibleBuiltIn.filter(s => matchesDoneFilter(s.slug, bestScore, doneFilter));
  const shownAuthored = authored.filter(s => matchesDoneFilter(s.scenario_id!, bestScore, doneFilter));
  // Legacy AI-preview scenarios aren't server-graded and record no history, so
  // they can never be "completed" — show them under All / Not done only.
  const shownGenerated = doneFilter === "done" ? [] : published.filter(s => s.kind !== "authored");
  const completedCount =
    visibleBuiltIn.filter(s => bestScore[s.slug] !== undefined).length +
    authored.filter(s => bestScore[s.scenario_id!] !== undefined).length;
  const trackableCount = visibleBuiltIn.length + authored.length;
  const nothingShown =
    (visibleBuiltIn.length > 0 || published.length > 0) &&
    shownBuiltIn.length + shownAuthored.length + shownGenerated.length === 0;

  function launchGenerated(scenario: PublishedScenario) {
    try {
      localStorage.setItem("session_scenario", JSON.stringify(scenario));
    } catch { /* ignore */ }
    router.push("/scenarios/preview");
  }

  return (
    <div>
      <Topbar
        title="Attack Scenarios"
        subtitle="Run end-to-end simulations against the synthetic SOC"
        actions={undefined}
      />

      <div className="container mx-auto max-w-[1600px] px-6 py-6 space-y-6">
        <Card className="border-cyber-500/30 bg-gradient-to-br from-cyber-500/5 to-neon-purple/5">
          <div className="flex items-start gap-4">
            <div className="rounded-md border border-cyber-500/40 bg-cyber-500/10 p-3 text-cyber-300">
              <Sparkles className="h-5 w-5" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-white">How scenarios work</h3>
              <p className="mt-1 max-w-3xl text-sm text-slate-300">
                Each scenario spins up a deterministic, vendor-accurate attack chain — emails, EDR process trees,
                firewall sessions, AD authentications, cloud audit events. Triage the alerts, build a timeline,
                identify TTPs, and answer analyst questions to score XP and unlock badges.
              </p>
              <div className="mt-3 flex flex-wrap gap-2 text-[11px] text-slate-400">
                <span>· No real customer data</span>
                <span>· MITRE-mapped</span>
                <span>· Replayable</span>
                <span>· AI-graded answers</span>
              </div>
            </div>
          </div>
        </Card>

        {/* Hidden-items notice */}
        {hidden.length > 0 && (
          <div className="flex items-center gap-2 rounded border border-border/40 bg-bg-elevated px-4 py-2 text-[11px] text-slate-400">
            <EyeOff className="h-3.5 w-3.5 shrink-0" />
            {hidden.length} scenario{hidden.length > 1 ? "s" : ""} hidden by admin — manage in Admin → Content Library
          </div>
        )}

        {/* Show filter + completion count (FB-006) */}
        {trackableCount > 0 && (
          <div className="flex flex-wrap items-center gap-3">
            <div role="group" aria-label="Show scenarios" className="flex items-center gap-1 rounded-lg border border-border bg-bg-elevated p-1">
              <span className="px-2 text-[11px] text-slate-400">Show:</span>
              {DONE_FILTERS.map(f => (
                <button
                  key={f.value}
                  type="button"
                  onClick={() => setDoneFilter(f.value)}
                  aria-pressed={doneFilter === f.value}
                  className={
                    doneFilter === f.value
                      ? "rounded-md border border-cyber-500/50 bg-cyber-500/15 px-3 py-1 text-xs font-semibold text-cyber-300"
                      : "rounded-md border border-transparent px-3 py-1 text-xs text-slate-400 transition hover:text-slate-200"
                  }
                >
                  {f.label}
                </button>
              ))}
            </div>
            <span className="text-[11px] text-slate-400">
              <span className="font-semibold text-neon-green">{completedCount}</span> of {trackableCount} completed
            </span>
          </div>
        )}

        {/* Built-in scenarios */}
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          {shownBuiltIn.map((s, i) => {
            // One neutral icon: the per-attack-kind icon hinted at the verdict
            // (false-positive scenarios never had a matching icon).
            const Icon = ShieldQuestion;
            return (
              <LibraryCard
                key={s.slug}
                href={`/scenarios/${s.slug}`}
                seed={s.slug}
                index={i}
                icon={Icon}
                typeLabel="Simulation"
                title={s.title}
                subtitle={s.summary}
                cornerBadge={
                  <div className="flex items-center gap-2">
                    <AssignedChip info={assigned[`scenario:${s.slug}`]} className="backdrop-blur-sm" />
                    {bestScore[s.slug] !== undefined && (
                      <span className="rounded border border-neon-green/40 bg-neon-green/10 px-2 py-0.5 text-[10px] font-bold uppercase text-neon-green">✓ Completed{bestScore[s.slug] > 0 ? ` · ${bestScore[s.slug]}%` : ""}</span>
                    )}
                    <span className={diffPill(s.difficulty)}>{s.difficulty}</span>
                  </div>
                }
                meta={<>+250 XP · ~45 min</>}
                cta={<span className="inline-flex shrink-0 items-center gap-1 rounded-lg border border-cyber-500/50 bg-cyber-500/15 px-3 py-1.5 text-xs font-semibold text-cyber-300 transition group-hover:bg-cyber-500/25">Launch <ArrowRight className="h-3.5 w-3.5" /></span>}
              >
                {/* Soft readiness hint — recommends, never blocks. Plain labels
                    (not links): the whole card is a link, so nested anchors are
                    invalid — the recommendation stays visible as text. */}
                {prepGaps(s.slug).length > 0 && (
                  <div className="mt-3 flex items-start gap-2 rounded-md border border-amber-500/25 bg-amber-500/5 px-2.5 py-2 text-[11px] text-amber-200/90">
                    <GraduationCap className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-400" />
                    <span>Recommended first: {prepGaps(s.slug).map((id, i) => (
                      <span key={id} className="text-amber-100">{i > 0 ? ", " : ""}{ROOM_TITLE[id] ?? id}</span>
                    ))}</span>
                  </div>
                )}
              </LibraryCard>
            );
          })}

          {/* Org-authored scenarios — routed to the safe, server-graded play
              page (/scenarios/[id]), not the client-side preview. Their card
              deliberately shows only title + briefing + difficulty; the verdict,
              IOCs and answers live server-side (migration 0041). */}
          {shownAuthored.map((s, i) => (
            <LibraryCard
              key={s.scenario_id}
              href={`/scenarios/${encodeURIComponent(s.scenario_id!)}`}
              seed={s.scenario_id!}
              index={i}
              icon={Target}
              typeLabel="Custom Simulation"
              title={s.title}
              subtitle={s.briefing}
              cornerBadge={
                <div className="flex items-center gap-2">
                  <AssignedChip info={assigned[`scenario:${s.scenario_id}`]} className="backdrop-blur-sm" />
                  {bestScore[s.scenario_id!] !== undefined && (
                    <span className="rounded border border-neon-green/40 bg-neon-green/10 px-2 py-0.5 text-[10px] font-bold uppercase text-neon-green">✓ Completed{bestScore[s.scenario_id!] > 0 ? ` · ${bestScore[s.scenario_id!]}%` : ""}</span>
                  )}
                  <span className="rounded border border-cyber-500/30 bg-black/40 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider text-cyber-200 backdrop-blur-sm">Custom</span>
                  <span className={diffPill(s.difficulty)}>{s.difficulty}</span>
                </div>
              }
              meta={<>Investigation</>}
              cta={<span className="inline-flex shrink-0 items-center gap-1 rounded-lg border border-cyber-500/50 bg-cyber-500/15 px-3 py-1.5 text-xs font-semibold text-cyber-300 transition group-hover:bg-cyber-500/25">Launch <ArrowRight className="h-3.5 w-3.5" /></span>}
            />
          ))}

          {/* AI-generated / published scenarios (legacy client-preview path) */}
          {shownGenerated.map((s, i) => {
            const Icon = ICON[s.attack_kind] ?? BotIcon;
            return (
              <LibraryCard
                key={s.id}
                onClick={() => launchGenerated(s)}
                seed={s.id}
                index={i}
                icon={Icon}
                typeLabel="AI Scenario"
                title={s.title}
                subtitle={s.narrative}
                cornerBadge={
                  <div className="flex items-center gap-2">
                    <span className="rounded border border-neon-green/30 bg-black/40 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider text-neon-green backdrop-blur-sm">AI Generated</span>
                    <span className={diffPill(s.difficulty)}>{s.difficulty}</span>
                  </div>
                }
                meta={<>{new Date(s.published_at).toLocaleDateString()}</>}
                cta={<span className="inline-flex shrink-0 items-center gap-1 rounded-lg border border-cyber-500/50 bg-cyber-500/15 px-3 py-1.5 text-xs font-semibold text-cyber-300 transition group-hover:bg-cyber-500/25">Launch <ArrowRight className="h-3.5 w-3.5" /></span>}
              />
            );
          })}
        </div>

        {/* Empty result for the current Show filter */}
        {nothingShown && (
          <div className="flex flex-col items-center justify-center rounded border border-border/40 bg-bg-elevated py-12 text-center">
            <ShieldQuestion className="h-10 w-10 text-slate-400 mb-3" />
            <p className="text-sm text-slate-400">
              {doneFilter === "done"
                ? "No completed scenarios yet — finish one and it will show up here."
                : "You've completed every scenario. Nice work!"}
            </p>
            <button type="button" onClick={() => setDoneFilter("all")} className="mt-3 text-xs font-semibold text-cyber-300 hover:text-cyber-200">
              Show all
            </button>
          </div>
        )}

        {visibleBuiltIn.length === 0 && published.length === 0 && (
          <div className="flex flex-col items-center justify-center rounded border border-border/40 bg-bg-elevated py-16 text-center">
            <ShieldQuestion className="h-12 w-12 text-slate-400 mb-4" />
            <p className="text-sm text-slate-400">All scenarios are hidden.</p>
            <p className="text-xs text-slate-400 mt-1">Restore them in Admin → Content Library.</p>
          </div>
        )}
      </div>
    </div>
  );
}
