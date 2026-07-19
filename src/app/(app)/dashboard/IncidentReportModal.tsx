"use client";
import { useState, useEffect } from "react";
import { X, FileText, Shield, AlertTriangle, CheckCircle2, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { Term } from "@/components/ui/Term";
import type { IncidentReportResponse } from "@/app/api/dashboard/incident-report/route";

type Phase = "form" | "grading" | "result";

function ScoreRing({ score }: { score: number }) {
  const radius = 36;
  const circ   = 2 * Math.PI * radius;
  const offset = circ - (score / 100) * circ;
  const color  = score >= 80 ? "#22c55e" : score >= 60 ? "#3b82f6" : score >= 40 ? "#f59e0b" : "#ef4444";

  return (
    <svg width="96" height="96" viewBox="0 0 96 96">
      <circle cx="48" cy="48" r={radius} fill="none" stroke="#1e293b" strokeWidth="8" />
      <circle
        cx="48" cy="48" r={radius}
        fill="none"
        stroke={color}
        strokeWidth="8"
        strokeDasharray={`${circ} ${circ}`}
        strokeDashoffset={offset}
        strokeLinecap="round"
        transform="rotate(-90 48 48)"
        style={{ transition: "stroke-dashoffset 0.8s ease" }}
      />
      <text x="48" y="44" textAnchor="middle" fill={color} fontSize="20" fontWeight="bold" fontFamily="monospace">
        {score}
      </text>
      <text x="48" y="60" textAnchor="middle" fill="#64748b" fontSize="10" fontFamily="sans-serif">
        / 100
      </text>
    </svg>
  );
}

interface Props {
  companyName: string;
  companyId: string;
  /** Real indicator values from the actual attack — grader ground truth */
  realIndicators: string[];
  attackTitle: string | null;
  /** MITRE technique IDs the real attack used — sent to grader as ground truth */
  attackMitreTechniques?: string[];
  onClose: () => void;
  onPassed: () => void;
}

export function IncidentReportModal({
  companyName,
  companyId,
  realIndicators,
  attackTitle,
  attackMitreTechniques,
  onClose,
  onPassed,
}: Props) {
  // Draft persistence — this modal unmounts entirely when closed (X / Cancel /
  // Escape), which used to wipe whatever the student had typed. Everything the
  // student writes is now saved to localStorage per company and restored the
  // next time they open the report, so closing to go re-check the feed never
  // loses their work. Cleared only once a report actually passes.
  const draftKey = `soc_report_draft_${companyId}`;
  const loadDraft = (): { guided: boolean; gWhat: string; gIocs: string; gAction: string; gImpact: string; summary: string } | null => {
    if (typeof window === "undefined") return null;
    try {
      const raw = localStorage.getItem(draftKey);
      return raw ? JSON.parse(raw) : null;
    } catch { return null; }
  };
  const draft = loadDraft();

  const [phase,   setPhase]   = useState<Phase>("form");
  const [summary, setSummary] = useState(draft?.summary ?? "");
  const [result,  setResult]  = useState<IncidentReportResponse | null>(null);
  const [passed,  setPassed]  = useState(false);

  // Guided mode: 4 labelled fields matching the grading rubric, concatenated
  // into the summary on submit — beginners get structure, the API is unchanged.
  const [guided, setGuided] = useState(() => {
    if (draft) return draft.guided;
    if (typeof window !== "undefined" && localStorage.getItem("soc_report_mode_v1") === "free") return false;
    return true;
  });
  const [gWhat,   setGWhat]   = useState(draft?.gWhat ?? "");
  const [gIocs,   setGIocs]   = useState(draft?.gIocs ?? "");
  const [gAction, setGAction] = useState(draft?.gAction ?? "");
  const [gImpact, setGImpact] = useState(draft?.gImpact ?? "");

  const setMode = (g: boolean) => {
    setGuided(g);
    if (typeof window !== "undefined") localStorage.setItem("soc_report_mode_v1", g ? "guided" : "free");
  };

  // Persist the draft on every change so closing the modal never loses text.
  useEffect(() => {
    if (typeof window === "undefined") return;
    localStorage.setItem(draftKey, JSON.stringify({ guided, gWhat, gIocs, gAction, gImpact, summary }));
  }, [draftKey, guided, gWhat, gIocs, gAction, gImpact, summary]);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onClose]);

  const buildGuidedSummary = () => [
    gWhat.trim()   && `What happened: ${gWhat.trim()}`,
    gIocs.trim()   && `Evidence (IOCs): ${gIocs.trim()}`,
    gAction.trim() && `Recommended action: ${gAction.trim()}`,
    gImpact.trim() && `Business impact: ${gImpact.trim()}`,
  ].filter(Boolean).join("\n");

  const effectiveSummary = guided ? buildGuidedSummary() : summary;
  const canSubmit = guided
    ? gWhat.trim().length >= 10 && gIocs.trim().length + gAction.trim().length >= 10 && effectiveSummary.length >= 30
    : summary.trim().length >= 30;

  const handleSubmit = async () => {
    if (!canSubmit) return;
    setPhase("grading");
    const submittedSummary = effectiveSummary;

    try {
      const res = await fetch("/api/dashboard/incident-report", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          company: companyName,
          summary: submittedSummary,
          attackTitle: attackTitle ?? undefined,
          attackMitreTechniques: attackMitreTechniques ?? [],
          realIndicators,
        }),
      });

      const data: IncidentReportResponse = await res.json();
      setResult(data);
      setPassed(data.passed);
      if (data.passed) { onPassed(); localStorage.removeItem(draftKey); }
      setPhase("result");
    } catch {
      // Fallback: simple pass if they wrote something substantial
      const fallback: IncidentReportResponse = {
        score: submittedSummary.length > 80 ? 65 : 30,
        passed: submittedSummary.length > 80,
        feedback: submittedSummary.length > 80
          ? "Report submitted. Good effort — keep practicing to improve specificity."
          : "Report too short. Add more detail about the attack and recommended action.",
        strengths: submittedSummary.length > 80 ? ["Submitted a report with some content."] : [],
        gaps: ["Add specific IOC values, attack name, and recommended response."],
      };
      setResult(fallback);
      setPassed(fallback.passed);
      if (fallback.passed) localStorage.removeItem(draftKey);
      if (fallback.passed) onPassed();
      setPhase("result");
    }
  };

  return (
    /* Docked as a side drawer, NOT a centered modal with a blocking backdrop.
       The report explicitly asks the analyst to quote IOCs from the logs
       "exactly" — so covering the event feed while they write made the task
       self-defeating. With no full-screen overlay the feed stays visible AND
       clickable: rows can still be expanded to re-read raw fields mid-write,
       which is how a real analyst works (SIEM on one side, case ticket on the
       other). Full width on narrow screens where side-by-side isn't possible. */
    <div className="fixed inset-y-0 right-0 z-50 flex w-full max-w-full sm:w-[560px]">
      <div className="relative flex h-full w-full flex-col border-l border-border bg-bg-elevated shadow-2xl shadow-black/60">
        <div className="h-1 w-full shrink-0 bg-gradient-to-r from-cyber-500 via-neon-purple to-neon-green" />

        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-4">

          {/* Header */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <FileText className="h-5 w-5 text-cyber-300 shrink-0" />
              <div>
                <p className="text-[9px] font-bold uppercase tracking-[0.2em] text-slate-500">Tier-1 Analyst Report</p>
                <h2 className="text-sm font-bold text-white">Incident Report — {companyName}</h2>
              </div>
            </div>
            <button onClick={onClose} className="rounded p-1 text-slate-400 hover:text-white transition">
              <X className="h-4 w-4" />
            </button>
          </div>

          {/* ── FORM phase ── */}
          {phase === "form" && (
            <>
              {/* Instructions */}
              <div className="rounded border border-neon-amber/20 bg-neon-amber/5 px-3 py-2.5">
                <p className="text-[10px] text-neon-amber font-semibold uppercase tracking-wider mb-1">What to include</p>
                <p className="text-[10px] text-slate-400 leading-relaxed">
                  Describe: <span className="text-slate-300">what attack occurred</span> · <span className="text-slate-300">which <Term k="ioc">IOCs</Term> from the logs prove it (real IPs, users, hosts — quote them exactly)</span> · <span className="text-slate-300">what action to take</span> · <span className="text-slate-300">business impact</span>
                </p>
                <p className="mt-2 text-[10px] text-slate-500">
                  The feed stays live beside you — click any row to re-read its raw fields while you write.
                </p>
              </div>

              {/* Mode toggle */}
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-500">Incident Summary</p>
                  {(gWhat || gIocs || gAction || gImpact || summary) && (
                    <span className="text-[9px] text-slate-600">· draft saved, safe to close and come back</span>
                  )}
                </div>
                <div className="flex rounded border border-border/60 overflow-hidden">
                  <button
                    onClick={() => setMode(true)}
                    className={cn("px-2.5 py-1 text-[10px] font-semibold transition",
                      guided ? "bg-cyber-500/20 text-cyber-300" : "text-slate-500 hover:text-slate-300")}
                  >
                    Guided
                  </button>
                  <button
                    onClick={() => setMode(false)}
                    className={cn("px-2.5 py-1 text-[10px] font-semibold transition",
                      !guided ? "bg-cyber-500/20 text-cyber-300" : "text-slate-500 hover:text-slate-300")}
                  >
                    Free text
                  </button>
                </div>
              </div>

              {/* Guided mode — 4 fields mirroring the grading rubric */}
              {guided ? (
                <div className="space-y-2.5">
                  {[
                    { label: "What happened?", req: true, value: gWhat, set: setGWhat, rows: 2,
                      ph: "Name the specific attack — e.g. \"A password spray attack against multiple accounts, followed by an account takeover of r.patel.\"" },
                    { label: "Evidence — which IOCs prove it?", req: true, value: gIocs, set: setGIocs, rows: 2,
                      ph: "Quote the values you collected — e.g. \"Source IP 91.108.4.154 (40+ failed logins), compromised user r.patel@nexacorp.com.\"" },
                    { label: "Recommended action", req: false, value: gAction, set: setGAction, rows: 2,
                      ph: "e.g. \"Block the IP at the firewall, reset r.patel's password, review all logins from that IP.\"" },
                    { label: "Business impact", req: false, value: gImpact, set: setGImpact, rows: 2,
                      ph: "e.g. \"The attacker had access to customer financial data — potential data-breach and regulatory exposure.\"" },
                  ].map((f, i) => (
                    <div key={f.label}>
                      <p className="mb-1 text-[10px] font-semibold text-slate-400">
                        {f.label} {f.req && <span className="text-neon-amber">*</span>}
                      </p>
                      <textarea
                        rows={f.rows}
                        value={f.value}
                        onChange={e => f.set(e.target.value)}
                        autoFocus={i === 0}
                        className="w-full resize-none rounded border border-border/60 bg-[#060b12] px-3 py-2 text-xs text-slate-200 placeholder-slate-600 focus:border-cyber-500/40 focus:outline-none leading-relaxed"
                        placeholder={f.ph}
                      />
                    </div>
                  ))}
                </div>
              ) : (
                /* Free-text mode — the classic single textarea */
                <div>
                  <div className="flex items-center justify-end mb-1.5">
                    <span className={cn("text-[9px] font-mono", summary.length < 30 ? "text-slate-600" : "text-neon-green")}>
                      {summary.length} chars {summary.length < 30 ? `(min 30)` : ""}
                    </span>
                  </div>
                  <textarea
                    rows={6}
                    value={summary}
                    onChange={e => setSummary(e.target.value)}
                    autoFocus
                    className="w-full resize-none rounded border border-border/60 bg-[#060b12] px-3 py-2.5 text-xs text-slate-200 placeholder-slate-600 focus:border-cyber-500/40 focus:outline-none leading-relaxed"
                    placeholder="Example: I detected a password spray attack targeting multiple accounts from IP 91.108.4.154. The attacker tried over 40 failed logins before succeeding with r.patel's credentials. I collected the source IP and compromised username as IOCs. Recommended action: block the IP at the firewall, reset r.patel's password, and review all successful logins from that IP."
                  />
                </div>
              )}

              <div className="flex items-center justify-between pt-1">
                <button onClick={onClose} className="text-xs text-slate-500 hover:text-slate-300 transition">
                  Cancel
                </button>
                <button
                  onClick={handleSubmit}
                  disabled={!canSubmit}
                  className={cn(
                    "flex items-center gap-2 rounded border px-4 py-2 text-xs font-bold transition",
                    canSubmit
                      ? "border-cyber-500/40 bg-cyber-500/10 text-cyber-300 hover:bg-cyber-500/20"
                      : "border-border/40 text-slate-600 cursor-not-allowed opacity-50"
                  )}
                >
                  <FileText className="h-3.5 w-3.5" /> Submit Report
                </button>
              </div>
            </>
          )}

          {/* ── GRADING phase ── */}
          {phase === "grading" && (
            <div className="py-8 flex flex-col items-center gap-5">
              <Loader2 className="h-8 w-8 text-cyber-300 animate-spin" />
              <div className="text-center space-y-1">
                <p className="text-sm font-semibold text-white">AI Analyst reviewing your report…</p>
                <p className="text-[11px] text-slate-400">Checking attack identification, IOC coverage, and recommended actions</p>
              </div>
            </div>
          )}

          {/* ── RESULT phase ── */}
          {phase === "result" && result && (
            <div className="space-y-4">
              {/* Score + pass/fail header */}
              <div className={cn(
                "rounded-lg border p-4 flex items-center gap-5",
                passed
                  ? "border-neon-green/30 bg-neon-green/5"
                  : "border-severity-critical/30 bg-severity-critical/5"
              )}>
                <ScoreRing score={result.score} />
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    {passed
                      ? <CheckCircle2 className="h-4 w-4 text-neon-green shrink-0" />
                      : <AlertTriangle className="h-4 w-4 text-severity-critical shrink-0" />
                    }
                    <span className={cn("text-sm font-bold", passed ? "text-neon-green" : "text-severity-critical")}>
                      {passed ? "Report Passed" : "Report Did Not Pass"}
                    </span>
                  </div>
                  <p className="text-[10px] text-slate-400">
                    {passed ? "Threshold: 60/100 — you met it." : "Threshold: 60/100 — keep monitoring and try again."}
                  </p>
                </div>
              </div>

              {/* Feedback */}
              <div className="rounded border border-border/40 bg-[#060b12] px-4 py-3 space-y-3">
                <p className="text-xs text-slate-200 leading-relaxed">{result.feedback}</p>

                {result.strengths.length > 0 && (
                  <div>
                    <p className="text-[9px] font-bold uppercase tracking-wider text-neon-green mb-1">Strengths</p>
                    {result.strengths.map((s, i) => (
                      <p key={i} className="text-[10px] text-slate-300 flex items-start gap-1.5">
                        <CheckCircle2 className="h-3 w-3 text-neon-green mt-0.5 shrink-0" />{s}
                      </p>
                    ))}
                  </div>
                )}

                {result.gaps.length > 0 && (
                  <div>
                    <p className="text-[9px] font-bold uppercase tracking-wider text-neon-amber mb-1">To Improve</p>
                    {result.gaps.map((g, i) => (
                      <p key={i} className="text-[10px] text-slate-300 flex items-start gap-1.5">
                        <AlertTriangle className="h-3 w-3 text-neon-amber mt-0.5 shrink-0" />{g}
                      </p>
                    ))}
                  </div>
                )}
              </div>

              {/* Action buttons */}
              <div className="space-y-2">
                {passed && (
                  <div className="rounded border border-neon-green/30 bg-neon-green/5 px-4 py-2.5 flex items-center gap-2">
                    <Shield className="h-4 w-4 text-neon-green shrink-0" />
                    <p className="text-[11px] text-neon-green font-semibold">
                      Objective unlocked! End your session to secure {companyName}.
                    </p>
                  </div>
                )}

                {!passed && (
                  <button
                    onClick={() => { setPhase("form"); setResult(null); }}
                    className="w-full rounded border border-neon-amber/40 bg-neon-amber/8 py-2 text-xs font-bold text-neon-amber hover:bg-neon-amber/15 transition"
                  >
                    Revise Report & Resubmit
                  </button>
                )}

                <button
                  onClick={onClose}
                  className="w-full rounded border border-cyber-500/40 bg-cyber-500/10 py-2.5 text-xs font-bold text-cyber-300 hover:bg-cyber-500/20 transition"
                >
                  {passed ? "Close & Continue Monitoring" : "Close — Keep Monitoring"}
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
