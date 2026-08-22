"use client";
/**
 * QUEUE-MODE PROTOTYPE (experiment Q7 — see docs/EXPERIMENT-Q7-QUEUE-VS-SINGLE-EVENT.md)
 * ---------------------------------------------------------------------------------
 * The control arm is the existing /dashboard (single-event: watch a live feed,
 * find the one attack, write a report). This is the TREATMENT arm: an alert
 * QUEUE where the analyst gives every alert a disposition (TP / FP / Escalate)
 * before writing the same incident report.
 *
 * Deliberately reuses the exact same source material as the dashboard so the
 * two arms differ ONLY in interaction model (the experiment's controlled
 * variable): same company pools, same attack stories, same FP decoys, same
 * incident-report grader. Feedback is DEFERRED to the end (no per-alert reveal
 * mid-queue) so the queue can't leak the ground truth.
 *
 * Not linked in the sidebar — reachable only at /queue, so it never reaches a
 * student who wasn't enrolled. Real A/B assignment would gate entry by a
 * per-user flag; here it's open-but-hidden for piloting. Telemetry is written
 * to localStorage for the prototype (swap for a server endpoint in the study).
 */
import { useMemo, useRef, useState } from "react";
import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { cn } from "@/lib/utils";
import {
  AlertTriangle, CheckCircle2, ChevronDown, ChevronRight, ShieldAlert, ArrowUpCircle,
  XCircle, ListChecks, FlaskConical, Clock, Target,
} from "lucide-react";
import { COMPANY_PROFILES, COMPANY_EVENTS, NEXACORP_PROFILE } from "@/lib/sim/companyProfiles";
import { BENIGN_EVENTS } from "@/app/(app)/dashboard/benignEvents";
import { pickStoryForCompany, instantiateStory } from "@/app/(app)/dashboard/attackStories";
import { IncidentReportModal } from "@/app/(app)/dashboard/IncidentReportModal";
import type { TelemetryEvent } from "@/lib/sim/types";

// ─── Reused helpers (mirrors dashboard/page.tsx; kept local to avoid touching it) ──
function getCompanyEvents(id: string): TelemetryEvent[] {
  if (id === "nexacorp") return BENIGN_EVENTS.filter(e => e.source !== "dns");
  const pool = COMPANY_EVENTS[id] ?? BENIGN_EVENTS;
  return pool.filter(e => e.source !== "dns");
}
function getCompanyProfile(id: string) {
  return COMPANY_PROFILES.find(c => c.id === id) ?? { ...NEXACORP_PROFILE };
}
/** Grader ground-truth indicators — same extraction the dashboard uses. */
function extractIndicators(events: TelemetryEvent[]): string[] {
  const out = new Set<string>();
  for (const e of events) {
    if (e.src_ip) out.add(e.src_ip);
    if (e.dst_ip) out.add(e.dst_ip);
    if (e.user_email) out.add(e.user_email);
    if (e.hostname) out.add(e.hostname);
    const dom = (e.network as { domain?: string } | undefined)?.domain;
    if (dom) out.add(dom);
    const sha = (e.file as { sha256?: string } | undefined)?.sha256;
    if (sha) out.add(sha);
    const proc = (e.process as { name?: string } | undefined)?.name;
    if (proc) out.add(proc);
  }
  return Array.from(out);
}

type Disposition = "tp" | "fp" | "escalate";
type Difficulty = "easy" | "medium" | "hard";
type Phase = "setup" | "triage" | "review" | "report" | "done";

interface Alert {
  id: string;
  event: TelemetryEvent;
  isThreat: boolean;            // ground truth: part of the attack chain
  fpReason: string | null;     // why it's benign (for the deferred review)
}

const COMPANIES = ["nexacorp", "medcore", "rocketstack", "globallogis", "quantumbank"];

function shuffle<T>(arr: T[]): T[] {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

const SEV_STYLE: Record<string, string> = {
  critical: "bg-severity-critical/15 text-severity-critical border-severity-critical/40",
  high: "bg-severity-high/15 text-severity-high border-severity-high/40",
  medium: "bg-severity-medium/15 text-severity-medium border-severity-medium/40",
  low: "bg-slate-500/15 text-slate-300 border-slate-500/40",
  informational: "bg-slate-600/15 text-slate-400 border-slate-600/40",
};

export default function QueueModePage() {
  const [phase, setPhase] = useState<Phase>("setup");
  const [companyId, setCompanyId] = useState("nexacorp");
  const [difficulty, setDifficulty] = useState<Difficulty>("medium");

  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [dispositions, setDispositions] = useState<Record<string, Disposition>>({});
  const [justifications, setJustifications] = useState<Record<string, string>>({});
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const startRef = useRef<number>(0);
  const [durationMs, setDurationMs] = useState(0);

  const profile = useMemo(() => getCompanyProfile(companyId), [companyId]);

  // Ground truth captured at build time so the report grader gets the real attack.
  const [storyTitle, setStoryTitle] = useState<string | null>(null);
  const [storyMitre, setStoryMitre] = useState<string[]>([]);
  const [realIndicators, setRealIndicators] = useState<string[]>([]);

  // ── Build the shift: attack-chain alerts (TP) + FP decoys, shuffled ──────────
  function startShift() {
    const pool = getCompanyEvents(companyId);
    const story = instantiateStory(pickStoryForCompany(companyId, difficulty), pool);
    const threatEvents = story.events.slice(0, 7);

    // FP class: prefer authored decoys (carry fp_explanation); top up with benign.
    const decoys = pool.filter(e => e.fp_explanation);
    const plainBenign = pool.filter(e => !e.fp_explanation && e.severity !== "critical");
    const fpEvents = [
      ...shuffle(decoys).slice(0, 4),
      ...shuffle(plainBenign).slice(0, 3),
    ];

    const built: Alert[] = shuffle([
      ...threatEvents.map((e, i) => ({ id: `t${i}_${e.id}`, event: e, isThreat: true, fpReason: null })),
      ...fpEvents.map((e, i) => ({
        id: `f${i}_${e.id}`, event: e, isThreat: false,
        fpReason: e.fp_explanation ?? "Routine business activity — no indicators of compromise.",
      })),
    ]);

    setStoryTitle(story.title);
    setStoryMitre(story.mitre);
    setRealIndicators(extractIndicators(story.events));
    setAlerts(built);
    setDispositions({});
    setJustifications({});
    setExpanded({});
    startRef.current = Date.now();
    setPhase("triage");
  }

  const allDispositioned = alerts.length > 0 && alerts.every(a => dispositions[a.id]);

  // ── Scoring (deferred) ───────────────────────────────────────────────────────
  const scored = useMemo(() => {
    const rows = alerts.map(a => {
      const d = dispositions[a.id];
      const correct = a.isThreat ? (d === "tp" || d === "escalate") : d === "fp";
      return { ...a, disposition: d, correct };
    });
    const threats = rows.filter(r => r.isThreat);
    const fps = rows.filter(r => !r.isThreat);
    const detection = threats.length ? threats.filter(r => r.correct).length / threats.length : 0;   // TP-recall
    const discrimination = fps.length ? fps.filter(r => r.correct).length / fps.length : 0;           // FP-precision (H1 metric)
    const overall = rows.length ? rows.filter(r => r.correct).length / rows.length : 0;
    return { rows, detection, discrimination, overall };
  }, [alerts, dispositions]);

  function submitQueue() {
    const dur = Date.now() - startRef.current;
    setDurationMs(dur);
    // Prototype telemetry (swap for a server endpoint in the real study).
    try {
      const rec = {
        ts: new Date().toISOString(), arm: "queue", companyId, difficulty,
        durationMs: dur, alertCount: alerts.length,
        overall: scored.overall, detection: scored.detection, discrimination: scored.discrimination,
        dispositions: alerts.map(a => ({ id: a.id, isThreat: a.isThreat, d: dispositions[a.id], correct: (a.isThreat ? (dispositions[a.id] === "tp" || dispositions[a.id] === "escalate") : dispositions[a.id] === "fp") })),
      };
      const key = "soc:queue_telemetry";
      const prev = JSON.parse(localStorage.getItem(key) ?? "[]");
      localStorage.setItem(key, JSON.stringify([...prev, rec].slice(-50)));
    } catch { /* ignore */ }
    setPhase("review");
  }

  const decoysForReport = useMemo(
    () => alerts.filter(a => !a.isThreat && a.fpReason).slice(0, 6).map(a => ({
      label: (a.event.description?.split(/[.—]/)[0]?.trim().slice(0, 90)) || a.event.event_type || a.event.source,
      source: a.event.source, fp_explanation: a.fpReason as string,
    })),
    [alerts],
  );

  const pct = (n: number) => `${Math.round(n * 100)}%`;

  return (
    <div>
      <Topbar title="Alert Queue — Triage Shift" subtitle={`${profile.name} · prototype`} />
      <div className="container mx-auto max-w-[1100px] px-6 py-6 space-y-6">

        <div className="flex items-center gap-2 rounded-lg border border-neon-purple/30 bg-neon-purple/5 px-4 py-2.5 text-xs text-neon-purple">
          <FlaskConical className="h-4 w-4 shrink-0" />
          Prototype — experiment Q7 (queue-mode vs single-event). Not part of the graded track.
        </div>

        {/* ── SETUP ── */}
        {phase === "setup" && (
          <Card>
            <h2 className="flex items-center gap-2 text-lg font-bold text-white">
              <ListChecks className="h-5 w-5 text-cyber-300" /> Start a triage shift
            </h2>
            <p className="mt-1 text-sm text-slate-400">
              You&apos;ll work a queue of alerts. Give each one a disposition — <strong className="text-slate-200">True Positive</strong>,
              <strong className="text-slate-200"> False Positive</strong>, or <strong className="text-slate-200">Escalate</strong> — then write the incident report.
              Some alerts are a real attack chain; most are benign noise. Feedback comes after you submit the whole queue.
            </p>

            <div className="mt-5 space-y-4">
              <div>
                <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-slate-400">Company</p>
                <div className="flex flex-wrap gap-2">
                  {COMPANIES.map(id => (
                    <button key={id} onClick={() => setCompanyId(id)}
                      className={cn("rounded-lg border px-3 py-1.5 text-sm transition",
                        companyId === id ? "border-cyber-500 bg-cyber-500/10 text-white" : "border-border bg-bg-elevated text-slate-300 hover:border-cyber-500/40")}>
                      {getCompanyProfile(id).name}
                    </button>
                  ))}
                </div>
              </div>
              <div>
                <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-slate-400">Difficulty</p>
                <div className="flex gap-2">
                  {(["easy", "medium", "hard"] as Difficulty[]).map(d => (
                    <button key={d} onClick={() => setDifficulty(d)}
                      className={cn("rounded-lg border px-4 py-1.5 text-sm capitalize transition",
                        difficulty === d ? "border-cyber-500 bg-cyber-500/10 text-white" : "border-border bg-bg-elevated text-slate-300 hover:border-cyber-500/40")}>
                      {d}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            <Button variant="primary" size="md" className="mt-6" onClick={startShift}>
              Start shift <ChevronRight className="h-4 w-4" />
            </Button>
          </Card>
        )}

        {/* ── TRIAGE (the queue) ── */}
        {phase === "triage" && (
          <>
            <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border bg-bg-elevated px-4 py-3">
              <span className="text-sm text-slate-300">
                <strong className="text-white">{alerts.length}</strong> alerts in queue ·
                <strong className="text-white"> {Object.keys(dispositions).length}</strong> dispositioned
              </span>
              <Button variant="primary" size="sm" disabled={!allDispositioned} onClick={submitQueue}>
                Submit queue ({Object.keys(dispositions).length}/{alerts.length})
              </Button>
            </div>

            <div className="space-y-2">
              {alerts.map(a => {
                const d = dispositions[a.id];
                const sev = a.event.severity ?? "informational";
                const open = !!expanded[a.id];
                return (
                  <Card key={a.id} className={cn("p-0 overflow-hidden", d && "ring-1 ring-cyber-500/30")}>
                    <div className="flex items-start gap-3 px-4 py-3">
                      <span className={cn("mt-0.5 shrink-0 rounded border px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide", SEV_STYLE[sev] ?? SEV_STYLE.informational)}>
                        {sev}
                      </span>
                      <div className="min-w-0 flex-1">
                        <p className="text-sm text-slate-100">{a.event.description || a.event.event_type}</p>
                        <p className="mt-0.5 font-mono text-[10px] text-slate-500">
                          {a.event.source}{a.event.vendor ? ` · ${a.event.vendor}` : ""}{a.event.mitre_technique ? ` · ${a.event.mitre_technique}` : ""}
                        </p>
                        <button onClick={() => setExpanded(p => ({ ...p, [a.id]: !open }))}
                          className="mt-1 inline-flex items-center gap-1 text-[11px] text-cyber-300 hover:text-cyber-200">
                          {open ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />} raw log
                        </button>
                        {open && (
                          <pre className="mt-2 max-h-64 overflow-auto rounded bg-bg p-2 font-mono text-[10px] leading-relaxed text-slate-300">
{JSON.stringify(a.event.raw, null, 2)}
                          </pre>
                        )}
                        <input
                          value={justifications[a.id] ?? ""}
                          onChange={e => setJustifications(p => ({ ...p, [a.id]: e.target.value }))}
                          placeholder="Why? (one line — optional)"
                          className="mt-2 w-full rounded border border-border bg-bg px-2 py-1 text-xs text-slate-200 placeholder:text-slate-600 focus:border-cyber-500/50 focus:outline-none"
                        />
                      </div>
                      <div className="flex shrink-0 flex-col gap-1">
                        {([
                          ["tp", "TP", ShieldAlert, "border-severity-high/50 bg-severity-high/10 text-severity-high"],
                          ["fp", "FP", XCircle, "border-slate-500/50 bg-slate-500/10 text-slate-300"],
                          ["escalate", "Escalate", ArrowUpCircle, "border-neon-purple/50 bg-neon-purple/10 text-neon-purple"],
                        ] as const).map(([val, label, Icon, active]) => (
                          <button key={val} onClick={() => setDispositions(p => ({ ...p, [a.id]: val }))}
                            className={cn("inline-flex items-center gap-1.5 rounded border px-2.5 py-1 text-[11px] font-semibold transition",
                              d === val ? active : "border-border bg-bg-elevated text-slate-400 hover:text-slate-200")}>
                            <Icon className="h-3.5 w-3.5" /> {label}
                          </button>
                        ))}
                      </div>
                    </div>
                  </Card>
                );
              })}
            </div>
          </>
        )}

        {/* ── REVIEW (deferred feedback) ── */}
        {phase === "review" && (
          <>
            <Card>
              <h2 className="flex items-center gap-2 text-lg font-bold text-white">
                <Target className="h-5 w-5 text-cyber-300" /> Shift review
              </h2>
              <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
                <Metric label="Overall accuracy" value={pct(scored.overall)} />
                <Metric label="Threat detection" value={pct(scored.detection)} hint="of real attacks caught" />
                <Metric label="FP discrimination" value={pct(scored.discrimination)} hint="benign correctly cleared" tone="accent" />
                <Metric label="Time" value={`${Math.round(durationMs / 1000)}s`} icon />
              </div>
              <p className="mt-3 text-[11px] text-slate-500">
                &quot;FP discrimination&quot; is the skill this queue-mode trains that the single-event dashboard doesn&apos;t — the H1 metric in the Q7 experiment.
              </p>
            </Card>

            <div className="space-y-2">
              {scored.rows.map(r => (
                <Card key={r.id} className={cn("border-l-2", r.correct ? "border-l-neon-green/60" : "border-l-severity-high/60")}>
                  <div className="flex items-start gap-3">
                    {r.correct
                      ? <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-neon-green" />
                      : <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-severity-high" />}
                    <div className="min-w-0 flex-1">
                      <p className="text-sm text-slate-100">{r.event.description || r.event.event_type}</p>
                      <p className="mt-1 text-xs">
                        <span className="text-slate-500">You: </span>
                        <span className="font-semibold text-slate-300 uppercase">{r.disposition}</span>
                        <span className="text-slate-500"> · Correct: </span>
                        <span className="font-semibold text-slate-300">{r.isThreat ? "TP / Escalate" : "FP"}</span>
                      </p>
                      <p className="mt-1 text-xs text-slate-400">
                        {r.isThreat
                          ? `Real attack step${r.event.mitre_technique ? ` — ${r.event.mitre_technique}` : ""}.`
                          : r.fpReason}
                      </p>
                    </div>
                  </div>
                </Card>
              ))}
            </div>

            <Button variant="primary" size="md" onClick={() => setPhase("report")}>
              Continue to incident report <ChevronRight className="h-4 w-4" />
            </Button>
          </>
        )}

        {/* ── REPORT (reused grader) ── */}
        {phase === "report" && (
          <IncidentReportModal
            companyName={profile.name}
            companyId={companyId}
            realIndicators={realIndicators}
            attackTitle={storyTitle}
            attackMitreTechniques={storyMitre}
            decoys={decoysForReport}
            onClose={() => setPhase("review")}
            onPassed={() => setPhase("done")}
          />
        )}

        {/* ── DONE ── */}
        {phase === "done" && (
          <Card>
            <h2 className="flex items-center gap-2 text-lg font-bold text-white">
              <CheckCircle2 className="h-5 w-5 text-neon-green" /> Shift complete
            </h2>
            <p className="mt-1 text-sm text-slate-400">
              Triage accuracy {pct(scored.overall)} · detection {pct(scored.detection)} · FP-discrimination {pct(scored.discrimination)}. Report filed.
            </p>
            <Button variant="primary" size="md" className="mt-4" onClick={() => setPhase("setup")}>
              New shift
            </Button>
          </Card>
        )}
      </div>
    </div>
  );
}

function Metric({ label, value, hint, tone, icon }: { label: string; value: string; hint?: string; tone?: "accent"; icon?: boolean }) {
  return (
    <div className="rounded-lg border border-border bg-bg px-3 py-2.5">
      <p className="flex items-center gap-1 text-[10px] uppercase tracking-wider text-slate-400">
        {icon && <Clock className="h-3 w-3" />}{label}
      </p>
      <p className={cn("mt-0.5 font-mono text-xl font-bold", tone === "accent" ? "text-cyber-300" : "text-white")}>{value}</p>
      {hint && <p className="mt-0.5 text-[10px] text-slate-500">{hint}</p>}
    </div>
  );
}
