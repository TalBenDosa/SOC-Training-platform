"use client";

import { useState } from "react";
import {
  AlertTriangle, ChevronDown, ChevronRight, Eye, EyeOff,
  Mail, RefreshCw, Shield, ShieldAlert, ShieldCheck, ShieldX, X,
} from "lucide-react";
import { cn } from "@/lib/utils";
import type { HeaderScenario } from "@/lib/sim/maliciousEmailHeaders";
import { pickRandomHeaderScenario } from "@/lib/sim/maliciousEmailHeaders";

// ─── Auth badge (same logic as EmailHeaderViewer) ────────────────────────────

type AuthResult = "pass" | "fail" | "softfail" | "none" | "unknown";
function toAuthResult(v: string): AuthResult {
  const l = v.toLowerCase();
  if (l === "pass") return "pass";
  if (l === "softfail") return "softfail";
  if (l === "fail") return "fail";
  if (l === "none") return "none";
  return "unknown";
}

function AuthBadge({ label, raw }: { label: string; raw: string }) {
  const r = toAuthResult(raw);
  const cfg: Record<AuthResult, { cls: string; Icon: typeof ShieldCheck; text: string }> = {
    pass:     { cls: "border-emerald-500/50 bg-emerald-500/10 text-emerald-400", Icon: ShieldCheck, text: "pass" },
    softfail: { cls: "border-neon-amber/50 bg-neon-amber/10 text-neon-amber",   Icon: ShieldAlert, text: "softfail" },
    fail:     { cls: "border-severity-high/60 bg-severity-high/10 text-severity-high", Icon: ShieldX, text: "fail" },
    none:     { cls: "border-slate-600/60 bg-slate-700/20 text-slate-400", Icon: ShieldAlert, text: "none" },
    unknown:  { cls: "border-slate-600/60 bg-slate-700/20 text-slate-400", Icon: ShieldAlert, text: raw || "—" },
  };
  const { cls, Icon, text } = cfg[r];
  return (
    <div className="flex items-center gap-2">
      <span className="w-14 shrink-0 text-[10px] font-semibold uppercase tracking-wider text-slate-500">{label}</span>
      <span className={cn("inline-flex items-center gap-1 rounded border px-1.5 py-0.5 font-mono text-[10px] font-bold", cls)}>
        <Icon className="h-2.5 w-2.5" />{text}
      </span>
    </div>
  );
}

// ─── Field row ────────────────────────────────────────────────────────────────

function FieldRow({ label, value, warn }: { label: string; value: string; warn?: boolean }) {
  return (
    <div className="flex items-start gap-2 text-[10px]">
      <span className="w-28 shrink-0 text-slate-500">{label}</span>
      <span className={cn("break-all font-mono", warn ? "text-neon-amber" : "text-slate-200")}>{value || "—"}</span>
      {warn && <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0 text-neon-amber" />}
    </div>
  );
}

// ─── IOC severity badge ───────────────────────────────────────────────────────

const SEVERITY_CFG = {
  critical: "border-severity-critical/60 bg-severity-critical/10 text-severity-critical",
  high:     "border-severity-high/60 bg-severity-high/10 text-severity-high",
  medium:   "border-neon-amber/50 bg-neon-amber/10 text-neon-amber",
} as const;

// ─── Main component ───────────────────────────────────────────────────────────

interface Props {
  onClose: () => void;
  onXp: (xp: number) => void;
}

export function EmailHeaderInvestigation({ onClose, onXp }: Props) {
  const [scenario, setScenario] = useState<HeaderScenario>(() => pickRandomHeaderScenario());
  const [revealed, setReveal]   = useState(false);
  const [showRaw, setShowRaw]   = useState(false);
  const [showChain, setShowChain] = useState(false);
  const [xpAwarded, setXpAwarded] = useState(false);

  const refresh = () => {
    setScenario(pickRandomHeaderScenario());
    setReveal(false);
    setShowRaw(false);
    setShowChain(false);
    setXpAwarded(false);
  };

  const reveal = () => {
    setReveal(true);
    if (!xpAwarded) {
      onXp(20);
      setXpAwarded(true);
    }
  };

  const difficultyColor = {
    Easy:   "border-emerald-500/40 bg-emerald-500/10 text-emerald-400",
    Medium: "border-neon-amber/40 bg-neon-amber/10 text-neon-amber",
    Hard:   "border-severity-high/50 bg-severity-high/10 text-severity-high",
  }[scenario.difficulty];

  const attackColor = {
    BEC:                 "border-severity-critical/50 bg-severity-critical/10 text-severity-critical",
    Phishing:            "border-severity-high/50 bg-severity-high/10 text-severity-high",
    Spoofing:            "border-neon-amber/50 bg-neon-amber/10 text-neon-amber",
    Malware:             "border-severity-critical/50 bg-severity-critical/10 text-severity-critical",
    Impersonation:       "border-neon-amber/50 bg-neon-amber/10 text-neon-amber",
    "Credential Harvest": "border-severity-high/50 bg-severity-high/10 text-severity-high",
  }[scenario.attackType];

  const hasAuthWarn =
    toAuthResult(scenario.spf) !== "pass" ||
    toAuthResult(scenario.dkim) !== "pass" ||
    toAuthResult(scenario.dmarc) !== "pass";

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
      <div className="relative flex w-full max-w-3xl flex-col overflow-hidden rounded-xl border border-border bg-[#0b1320] shadow-2xl" style={{ maxHeight: "92vh" }}>

        {/* ── Top accent bar ───────────────────────────────────────────────── */}
        <div className="h-0.5 w-full bg-gradient-to-r from-cyber-500 via-neon-amber to-severity-high" />

        {/* ── Header ───────────────────────────────────────────────────────── */}
        <div className="flex shrink-0 items-start justify-between gap-4 border-b border-border/50 px-6 py-4">
          <div className="flex items-center gap-3">
            <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-neon-amber/30 bg-neon-amber/10">
              <Mail className="h-4 w-4 text-neon-amber" />
            </span>
            <div>
              <h2 className="text-sm font-bold text-white">Email Header Investigation</h2>
              <p className="text-[10px] text-slate-400 uppercase tracking-widest">
                Analyst Training — Identify the IOCs before revealing the answer
              </p>
            </div>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <button
              onClick={refresh}
              className="flex items-center gap-1.5 rounded border border-border/60 bg-slate-800/60 px-2.5 py-1.5 text-[10px] text-slate-400 hover:text-white transition-colors"
            >
              <RefreshCw className="h-3 w-3" /> New Scenario
            </button>
            <button onClick={onClose} className="rounded p-1 text-slate-500 hover:text-white transition-colors">
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* ── Scrollable body ──────────────────────────────────────────────── */}
        <div className="overflow-y-auto flex-1 px-6 py-5 space-y-5">

          {/* ── Scenario briefing ──────────────────────────────────────────── */}
          <div className="rounded-lg border border-neon-amber/25 bg-neon-amber/5 px-4 py-3">
            <div className="mb-2 flex flex-wrap items-center gap-2">
              <span className={cn("rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider", attackColor)}>
                {scenario.attackType}
              </span>
              <span className={cn("rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider", difficultyColor)}>
                {scenario.difficulty}
              </span>
              <span className="text-[11px] font-semibold text-white">{scenario.title}</span>
            </div>
            <p className="text-[11px] leading-relaxed text-slate-300">{scenario.narrative}</p>
          </div>

          {/* ── Parsed fields ──────────────────────────────────────────────── */}
          <div className="rounded-lg border border-border/50 bg-[#0d1520] px-4 py-3 space-y-4">
            <p className="text-[9px] font-bold uppercase tracking-widest text-slate-600">Envelope &amp; Headers</p>

            <div className="space-y-1.5">
              <FieldRow label="From"     value={scenario.from} />
              <FieldRow label="To"       value={scenario.to} />
              <FieldRow label="Subject"  value={scenario.subject} />
              <FieldRow
                label="Reply-To"
                value={scenario.replyTo ?? "(same as From)"}
                warn={!!scenario.replyTo && scenario.replyTo !== scenario.from}
              />
              <FieldRow
                label="Return-Path"
                value={scenario.returnPath ? `<${scenario.returnPath}>` : "(same as From)"}
                warn={
                  !!scenario.returnPath &&
                  scenario.returnPath.split("@")[1]?.toLowerCase() !==
                    (scenario.from.match(/<(.+)>/)?.[1] ?? scenario.from).split("@")[1]?.toLowerCase()
                }
              />
              <FieldRow label="Message-ID"      value={scenario.messageId} />
              <FieldRow label="Date"            value={scenario.date} />
              {scenario.xMailer      && <FieldRow label="X-Mailer"        value={scenario.xMailer} />}
              {scenario.xOriginatingIp && <FieldRow label="X-Originating-IP" value={scenario.xOriginatingIp} warn />}
              {scenario.contentType  && <FieldRow label="Content-Type"    value={scenario.contentType} />}
            </div>

            {/* Auth */}
            <div className="border-t border-border/40 pt-3 space-y-1.5">
              <p className="mb-2 text-[9px] font-bold uppercase tracking-widest text-slate-600">Authentication Results</p>
              <AuthBadge label="SPF"   raw={scenario.spf} />
              <AuthBadge label="DKIM"  raw={scenario.dkim} />
              <AuthBadge label="DMARC" raw={scenario.dmarc} />
              {hasAuthWarn && (
                <div className="mt-2 rounded border border-neon-amber/30 bg-neon-amber/5 px-2.5 py-1.5 text-[10px] text-neon-amber">
                  ⚠ One or more authentication checks failed — investigate the sending domain.
                </div>
              )}
              <div className="mt-2 rounded bg-[#080d14] px-2.5 py-2">
                <p className="mb-1 text-[9px] font-semibold text-slate-600">Authentication-Results raw</p>
                <p className="break-all font-mono text-[9px] leading-relaxed text-slate-400">{scenario.authResultsRaw}</p>
              </div>
            </div>

            {/* Received chain */}
            <div className="border-t border-border/40 pt-3">
              <button
                className="flex items-center gap-1.5 text-[9px] font-bold uppercase tracking-widest text-slate-600 hover:text-slate-400 transition-colors"
                onClick={() => setShowChain(v => !v)}
              >
                {showChain ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
                Received Chain ({scenario.receivedChain.length} {scenario.receivedChain.length === 1 ? "hop" : "hops"})
              </button>
              {showChain && (
                <div className="mt-2 space-y-2 pl-2">
                  {scenario.receivedChain.map((hop, i) => (
                    <div key={i} className="flex items-start gap-2">
                      <span className="mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full border border-slate-700 bg-slate-800 text-[8px] font-bold text-slate-500">
                        {i + 1}
                      </span>
                      <span className="break-all font-mono text-[9px] leading-relaxed text-slate-400">{hop}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* ── Raw header toggle ─────────────────────────────────────────── */}
          <div className="rounded-lg border border-border/50 bg-[#0d1520]">
            <button
              className="flex w-full items-center justify-between px-4 py-2.5"
              onClick={() => setShowRaw(v => !v)}
            >
              <div className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                {showRaw ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                Raw Email Header (View Source)
              </div>
              {showRaw ? <ChevronDown className="h-3.5 w-3.5 text-slate-500" /> : <ChevronRight className="h-3.5 w-3.5 text-slate-500" />}
            </button>
            {showRaw && (
              <div className="border-t border-border/40 px-4 py-3">
                <pre className="overflow-x-auto whitespace-pre-wrap break-all font-mono text-[9px] leading-relaxed text-slate-400">
                  {scenario.rawHeader}
                </pre>
              </div>
            )}
          </div>

          {/* ── Analyst prompt ────────────────────────────────────────────── */}
          {!revealed && (
            <div className="rounded-lg border border-cyber-500/30 bg-cyber-500/5 px-4 py-3 text-center">
              <Shield className="mx-auto mb-2 h-6 w-6 text-cyber-400" />
              <p className="text-[11px] font-semibold text-white mb-1">What looks suspicious?</p>
              <p className="text-[10px] text-slate-400 mb-3">
                Examine the fields above. Look at the sender domain, Reply-To, auth results, X-Mailer,
                originating IP, and Received chain. Identify every red flag before revealing the answer.
              </p>
              <button
                onClick={reveal}
                className="inline-flex items-center gap-2 rounded border border-severity-high/60 bg-severity-high/10 px-4 py-2 text-[11px] font-bold text-severity-high hover:bg-severity-high/20 transition-colors"
              >
                <Eye className="h-3.5 w-3.5" />
                Reveal IOCs — Show Answer
              </button>
            </div>
          )}

          {/* ── IOC Reveal ───────────────────────────────────────────────── */}
          {revealed && (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <p className="text-[9px] font-bold uppercase tracking-widest text-slate-500">
                  IOC Analysis — {scenario.iocs.length} Indicators Found
                </p>
                {xpAwarded && (
                  <span className="rounded border border-emerald-500/40 bg-emerald-500/10 px-2 py-0.5 text-[9px] font-bold text-emerald-400">
                    +20 XP Earned
                  </span>
                )}
              </div>

              {scenario.iocs.map((ioc, i) => (
                <div
                  key={i}
                  className={cn(
                    "rounded-lg border px-4 py-3",
                    ioc.severity === "critical" ? "border-severity-critical/40 bg-severity-critical/5" :
                    ioc.severity === "high"     ? "border-severity-high/40 bg-severity-high/5" :
                                                  "border-neon-amber/30 bg-neon-amber/5"
                  )}
                >
                  <div className="mb-1.5 flex flex-wrap items-center gap-2">
                    <span className={cn(
                      "rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider",
                      SEVERITY_CFG[ioc.severity]
                    )}>
                      {ioc.severity}
                    </span>
                    <span className="text-[10px] font-semibold text-white">{ioc.field}</span>
                  </div>
                  <p className="mb-1 font-mono text-[9px] text-slate-400 break-all">
                    {ioc.value}
                  </p>
                  <p className="text-[10px] leading-relaxed text-slate-300">
                    {ioc.explanation}
                  </p>
                </div>
              ))}

              {/* Next action */}
              <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 px-4 py-3">
                <p className="text-[10px] font-bold text-emerald-400 mb-1">What to do next?</p>
                <p className="text-[10px] leading-relaxed text-slate-300">
                  {scenario.attackType === "BEC" || scenario.attackType === "Impersonation" || scenario.attackType === "Spoofing"
                    ? "Block the sender domain, quarantine the email, notify the potential victim via a separate channel. Check mail server logs for other recipients. If wire transfer was requested — call the requester directly on a known phone number."
                    : scenario.attackType === "Malware"
                    ? "Quarantine the email and block the sender. If any user opened the attachment: isolate the endpoint, trigger EDR scan, review process creation logs for cmd.exe / powershell.exe spawned by Word/Excel."
                    : "Quarantine the email, block the sending domain, and reset credentials for any user who clicked the link. Check O365 sign-in logs for new sessions from unusual IPs."
                  }
                </p>
              </div>

              <button
                onClick={refresh}
                className="flex w-full items-center justify-center gap-2 rounded border border-cyber-500/40 bg-cyber-500/10 py-2 text-[11px] font-semibold text-cyber-400 hover:bg-cyber-500/20 transition-colors"
              >
                <RefreshCw className="h-3.5 w-3.5" /> Investigate Another Header
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
