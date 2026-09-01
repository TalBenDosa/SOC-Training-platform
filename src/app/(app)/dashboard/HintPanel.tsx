"use client";
/**
 * HintPanel — tiered, in-flow "nudges" for a stuck analyst.
 *
 * Design principle (sacred): NO hints in the raw logs and NO premature answer.
 * These nudges are META methodology guidance shown in a SEPARATE, opt-in panel.
 * They are never injected into any event `raw`, and they never name the exact
 * IOC, the verdict, or the precise MITRE technique id.
 *
 * The student opens the panel by choice ("Need a nudge?") and reveals hints one
 * tier at a time:
 *   Tier 1 — pure methodology, story-agnostic (how to hunt in any feed).
 *   Tier 2 — narrows by the active story's MITRE TACTIC only (not the technique,
 *            not the IOC).
 *   Tier 3 — points at the CATEGORY of source/host to examine (not the exact
 *            host, IP, user, or verdict).
 *
 * No penalty: consistent with the dashboard's no-fail philosophy, requesting a
 * nudge never docks XP. Hint usage is tracked locally only (for the student's
 * own awareness) — no DB, no migration.
 *
 * Reset: the parent passes `resetKey` (the active incident / story id). When it
 * changes — a new attack arms, or a new shift starts — the panel closes and the
 * revealed tiers reset to zero.
 */
import { useEffect, useState } from "react";
import { cn } from "@/lib/utils";
import { Lightbulb, ChevronRight, X } from "lucide-react";
import { techniqueById, tacticById } from "@/lib/mitre/attack";
import type { AttackStory } from "./attackStories";
import type { LogSource, Severity } from "@/lib/sim/types";

interface Props {
  /** The story currently in play — source of the Tier 2 tactic and Tier 3 source category. */
  story: AttackStory | null;
  /** Changes when a new attack arms / new session starts → resets hint state. */
  resetKey: string | null;
}

// ── Tier 2: tactic → methodology guidance (never the technique id / IOC) ──────
// Priority order: the most investigation-guiding tactic present wins, so a
// multi-stage story points the student at its meaty middle, not "Initial Access".
const TACTIC_PRIORITY: string[] = [
  "TA0040", // Impact
  "TA0010", // Exfiltration
  "TA0006", // Credential Access
  "TA0004", // Privilege Escalation
  "TA0008", // Lateral Movement
  "TA0003", // Persistence
  "TA0011", // Command and Control
  "TA0009", // Collection
  "TA0005", // Defense Evasion
  "TA0007", // Discovery
  "TA0002", // Execution
  "TA0001", // Initial Access
];

const TACTIC_HINT: Record<string, string> = {
  TA0040: "This attack builds toward impact (encryption, destruction, or resource hijacking). Find the most damaging-looking event, then trace backwards to how it started.",
  TA0010: "This involves data exfiltration — focus on unusually large or unusual-destination outbound transfers, uploads, or email flows.",
  TA0006: "This involves credential access — focus on authentication, identity, and secrets-store events (failed/odd logons, MFA, credential dumping, token or vault activity).",
  TA0004: "This involves privilege escalation — watch for a normal account or process suddenly gaining elevated rights.",
  TA0008: "This involves lateral movement — follow the same identity or host as it appears across more than one system.",
  TA0003: "The attacker sets up persistence — look for new accounts, scheduled tasks, services, run keys, or mailbox rules being created.",
  TA0011: "This involves command-and-control — focus on repeated or beaconing outbound connections to an unfamiliar destination.",
  TA0009: "This involves data collection — look for staging, bulk file access, or new mail-forwarding / inbox rules.",
  TA0005: "The attacker tries to evade defenses — watch for cleared logs, disabled tooling, or a process masquerading under a trusted name.",
  TA0007: "This involves discovery — look for enumeration of accounts, hosts, groups, or the network.",
  TA0002: "This involves code execution — focus on unusual process launches and, crucially, their parent processes.",
  TA0001: "Start at the entry point — focus on how the first foothold was gained (a phishing email, an exploit, or valid stolen accounts).",
};

// ── Tier 3: source → category (never the exact host / IP / user) ──────────────
type SourceCategory = "identity" | "endpoint" | "cloud" | "network" | "email" | "data" | "security tooling";

const SOURCE_CATEGORY: Partial<Record<LogSource, SourceCategory>> = {
  ad: "identity", okta: "identity", iam: "identity", mfa: "identity",
  edr: "endpoint", sysmon: "endpoint", av: "endpoint", windows_security: "endpoint", linux_audit: "endpoint",
  o365: "cloud", gws: "cloud", cloudtrail: "cloud", cloud_azure: "cloud", cloud_gcp: "cloud",
  sharepoint: "cloud", teams: "cloud", k8s_audit: "cloud",
  firewall: "network", ids: "network", vpn: "network", proxy: "network", dns: "network",
  dhcp: "network", nac: "network", waf: "network",
  exchange: "email", email_gateway: "email",
  dlp: "data", db_monitor: "data",
  ueba: "security tooling", threat_intel: "security tooling", siem: "security tooling", soar: "security tooling",
};

const CATEGORY_HINT: Record<SourceCategory, string> = {
  identity: "The key evidence sits on an identity source (Active Directory / Okta / Azure AD / MFA). Concentrate your reading there.",
  endpoint: "The key evidence sits on an endpoint source (EDR / Sysmon / AV). Concentrate on the host telemetry.",
  cloud: "The key evidence sits on a cloud or SaaS source (O365 / CloudTrail / Azure / GCP). Concentrate your reading there.",
  network: "The key evidence sits on a network source (firewall / proxy / VPN / DNS). Follow the traffic.",
  email: "The key evidence sits on an email source (mail gateway / Exchange). Start from the message flow.",
  data: "The key evidence sits on a data-security source (DLP / database monitoring). Follow the data movement.",
  "security tooling": "The key evidence surfaces in a security-analytics source (UEBA / threat intel). Pivot from the flagged entity.",
};

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5, high: 4, medium: 3, low: 2, informational: 1,
};

/** Derive the highest-priority tactic present in the story (by technique ids). */
function deriveTactic(story: AttackStory | null): string | null {
  if (!story) return null;
  const present = new Set<string>();
  for (const t of story.mitre) {
    const tech = techniqueById(t);
    if (tech?.tactic) present.add(tech.tactic);
    tech?.tactics?.forEach((x) => present.add(x));
  }
  for (const id of TACTIC_PRIORITY) if (present.has(id)) return id;
  return null;
}

/** Derive the source category of the story's most significant (detection / most severe) event. */
function deriveCategory(story: AttackStory | null): SourceCategory | null {
  if (!story || story.events.length === 0) return null;
  let best = story.events[0];
  let bestScore = -1;
  for (const e of story.events) {
    const score = (e.is_detection ? 100 : 0) + (e.severity ? SEVERITY_RANK[e.severity] : 0);
    if (score > bestScore) { bestScore = score; best = e; }
  }
  return SOURCE_CATEGORY[best.source] ?? null;
}

export function HintPanel({ story, resetKey }: Props) {
  const [open, setOpen] = useState(false);
  // How many tiers have been revealed (0 = none yet). Max 3.
  const [revealed, setRevealed] = useState(0);

  // Reset when a new attack arms / new session starts.
  useEffect(() => {
    setOpen(false);
    setRevealed(0);
  }, [resetKey]);

  const tacticId = deriveTactic(story);
  const tactic = tacticId ? tacticById(tacticId) : null;
  const category = deriveCategory(story);

  // Build the tier list. Tier 2/3 fall back to generic guidance if the story
  // metadata can't supply a specific tactic/category — never a dead button.
  const tiers: { label: string; body: string }[] = [
    {
      label: "Tier 1 · Methodology",
      body: "Scan for the one event whose severity, parent process, timing, or geo looks out of place versus the routine noise. Then pivot: pick the host, user, or IP that appears in more than one alert and follow that thread across sources.",
    },
    {
      label: "Tier 2 · Attack stage",
      body: tactic
        ? `${TACTIC_HINT[tactic.id] ?? `This centers on ${tactic.name}.`} (MITRE tactic: ${tactic.name}.)`
        : "Ask which stage of an intrusion the standout event belongs to — initial access, execution, credential access, or exfiltration — and hunt for the events on either side of it.",
    },
    {
      label: "Tier 3 · Where to look",
      body: category
        ? CATEGORY_HINT[category]
        : "Narrow to the single log source carrying the most severe event, and read every entry from that source around the same timeframe.",
    },
  ];

  return (
    <div className="rounded-lg border border-neon-amber/25 bg-neon-amber/[0.04] px-4 py-2.5">
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-[9px] font-bold uppercase tracking-[0.2em] text-slate-400">
          Stuck?
        </span>
        <span className="text-[11px] text-slate-400">
          Optional nudges — they point you at where to look, never at the verdict, and asking costs nothing.
        </span>
        <button
          onClick={() => setOpen((v) => !v)}
          className={cn(
            "ml-auto flex items-center gap-1.5 rounded px-2 py-1 text-[11px] font-semibold transition",
            open ? "text-neon-amber hover:bg-neon-amber/10" : "text-neon-amber/90 hover:bg-neon-amber/10"
          )}
        >
          <Lightbulb className="h-3.5 w-3.5 shrink-0" />
          {open ? "Hide nudges" : "Need a nudge?"}
          {revealed > 0 && (
            <span className="rounded-full bg-neon-amber/15 px-1.5 py-0.5 font-mono text-[9px] text-neon-amber">
              {revealed}/3
            </span>
          )}
        </button>
      </div>

      {open && (
        <div className="mt-2 space-y-2">
          {tiers.slice(0, revealed).map((tier, i) => (
            <div key={i} className="rounded border border-border/50 bg-[#0b0a06] px-3 py-2">
              <div className="mb-1 flex items-center gap-2">
                <span className="flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-neon-amber/15 font-mono text-[9px] font-bold text-neon-amber">
                  {i + 1}
                </span>
                <span className="text-[9px] font-bold uppercase tracking-wider text-neon-amber/80">
                  {tier.label}
                </span>
              </div>
              <p className="text-[11px] leading-relaxed text-slate-300">{tier.body}</p>
            </div>
          ))}

          {revealed < tiers.length ? (
            <button
              onClick={() => setRevealed((n) => Math.min(n + 1, tiers.length))}
              className="flex items-center gap-1.5 rounded border border-neon-amber/40 bg-neon-amber/10 px-2.5 py-1 text-[11px] font-semibold text-neon-amber transition hover:bg-neon-amber/20"
            >
              <ChevronRight className="h-3.5 w-3.5" />
              {revealed === 0 ? "Show first hint" : "Show next hint"}
              <span className="font-mono text-[9px] opacity-70">({revealed + 1}/{tiers.length})</span>
            </button>
          ) : (
            <div className="flex items-center gap-2">
              <span className="text-[10px] text-slate-500">
                All nudges shown — the rest is your call. State it in the Incident Report.
              </span>
              <button
                onClick={() => { setRevealed(0); setOpen(false); }}
                className="flex items-center gap-1 rounded border border-border/60 px-2 py-0.5 text-[10px] text-slate-400 transition hover:text-slate-300"
              >
                <X className="h-3 w-3" /> Reset
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
