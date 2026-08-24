"use client";
import React, { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { LibraryCard } from "@/components/ui/LibraryCard";
import { SCENARIOS } from "@/lib/sim/scenarios";
import { getRoomProgress } from "@/lib/storage/progress";
import { fetchPublishedScenarios } from "@/lib/content/publicContent";
import Link from "next/link";
import {
  Sparkles, Zap, ShieldQuestion, Cloud, Mail, KeyRound, Lock, UserX,
  BotIcon, EyeOff, GraduationCap, Target, ArrowRight,
} from "lucide-react";

// ── Readiness map ──────────────────────────────────────────────────────────
// Scenarios were launchable from day 1 regardless of what the learner had
// studied — the 65% mastery gate that governs Rooms stopped at the door of the
// most meaningful practice on the platform. This maps the scenarios that assume
// specific prior knowledge to the rooms that teach it, and the card shows a
// SOFT "recommended first" hint (never a hard lock — self-paced learners keep
// full freedom). Beginner scenarios are intentionally unmapped: no hint.
const ROOM_LABEL: Record<string, string> = {
  "active-directory": "Active Directory",
  "kerberos-authentication": "Kerberos",
  "identity-basics": "Identity Basics",
  "auth-identity-monitoring": "Auth & Identity Monitoring",
  "windows-protocols-lateral": "Windows Protocols & Lateral Movement",
  "web-application-security": "Web App Security",
  "cloud-security-monitoring": "Cloud Security Monitoring",
  "tunneling-c2-channels": "Tunnelling & C2",
  "malware-analysis-fundamentals": "Malware Analysis",
  "endpoint-security-fundamentals": "Endpoint Security",
  "linux-log-analysis": "Linux Log Analysis",
  "mitre-attack": "MITRE ATT&CK",
  "windows-event-logs": "Windows Event Logs",
};
const SCENARIO_PREP: Record<string, string[]> = {
  "kerberoasting":               ["active-directory", "kerberos-authentication"],
  "asrep-roasting":              ["active-directory", "kerberos-authentication"],
  "dcsync-golden-ticket":        ["active-directory", "kerberos-authentication"],
  "ntlm-relay-responder":        ["active-directory", "windows-protocols-lateral"],
  "aitm-token-theft":            ["identity-basics", "auth-identity-monitoring"],
  "oauth-app-persistence":       ["identity-basics", "cloud-security-monitoring"],
  "oauth-consent-grant-phishing":["identity-basics", "cloud-security-monitoring"],
  "dns-tunneling":               ["tunneling-c2-channels"],
  "lolbins":                     ["windows-event-logs", "mitre-attack"],
  "web-shell-sqli":              ["web-application-security"],
  "ransomware-lockbit":          ["endpoint-security-fundamentals", "malware-analysis-fundamentals"],
  "esxi-ransomware":             ["endpoint-security-fundamentals", "malware-analysis-fundamentals"],
  "k8s-pod-escape-imds":         ["cloud-security-monitoring"],
  "cloud-cryptomining":          ["cloud-security-monitoring"],
  "linux-ssh-cryptominer":       ["linux-log-analysis"],
};

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

  useEffect(() => {
    try {
      setHidden(JSON.parse(localStorage.getItem("admin_hidden_scenarios") ?? "[]"));
      // Which rooms has the learner actually completed? Drives the soft
      // readiness hint below (via the same facade the Rooms page uses).
      const rp = getRoomProgress() as Record<string, { completedAt?: string }>;
      setDoneRooms(new Set(Object.entries(rp).filter(([, v]) => v?.completedAt).map(([id]) => id)));
    } catch { /* storage blocked */ }
    // Admin-published scenarios now live in the durable content_scenarios
    // table (migration 0019), not per-browser localStorage — this is what
    // makes them actually visible to real students for the first time.
    fetchPublishedScenarios<PublishedScenario>().then(setPublished);
  }, []);

  const prepGaps = (slug: string) =>
    (SCENARIO_PREP[slug] ?? []).filter(id => !doneRooms.has(id));

  const visibleBuiltIn = SCENARIOS.filter(s => !hidden.includes(s.slug));

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

        {/* Built-in scenarios */}
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          {visibleBuiltIn.map(s => {
            const Icon = ICON[s.attack_kind] ?? ShieldQuestion;
            return (
              <LibraryCard
                key={s.slug}
                href={`/scenarios/${s.slug}`}
                seed={s.slug}
                icon={Icon}
                typeLabel="Simulation"
                title={s.title}
                subtitle={s.summary}
                cornerBadge={<span className={diffPill(s.difficulty)}>{s.difficulty}</span>}
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
                      <span key={id} className="text-amber-100">{i > 0 ? ", " : ""}{ROOM_LABEL[id] ?? id}</span>
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
          {published.filter(s => s.kind === "authored" && s.scenario_id).map(s => (
            <LibraryCard
              key={s.scenario_id}
              href={`/scenarios/${encodeURIComponent(s.scenario_id!)}`}
              seed={s.scenario_id!}
              icon={Target}
              typeLabel="Custom Simulation"
              title={s.title}
              subtitle={s.briefing}
              cornerBadge={
                <div className="flex items-center gap-2">
                  <span className="rounded border border-cyber-500/30 bg-black/40 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider text-cyber-200 backdrop-blur-sm">Custom</span>
                  <span className={diffPill(s.difficulty)}>{s.difficulty}</span>
                </div>
              }
              meta={<>Investigation</>}
              cta={<span className="inline-flex shrink-0 items-center gap-1 rounded-lg border border-cyber-500/50 bg-cyber-500/15 px-3 py-1.5 text-xs font-semibold text-cyber-300 transition group-hover:bg-cyber-500/25">Launch <ArrowRight className="h-3.5 w-3.5" /></span>}
            />
          ))}

          {/* AI-generated / published scenarios (legacy client-preview path) */}
          {published.filter(s => s.kind !== "authored").map(s => {
            const Icon = ICON[s.attack_kind] ?? BotIcon;
            return (
              <LibraryCard
                key={s.id}
                onClick={() => launchGenerated(s)}
                seed={s.id}
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
