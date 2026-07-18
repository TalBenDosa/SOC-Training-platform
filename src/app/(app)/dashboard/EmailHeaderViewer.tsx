"use client";

import { useState } from "react";
import { Mail, ChevronDown, ChevronRight, ShieldCheck, ShieldX, ShieldAlert, AlertTriangle, Search } from "lucide-react";
import { cn } from "@/lib/utils";
import type { LiveEvent } from "./useLiveEvents";
import { EmailHeaderInvestigation } from "./EmailHeaderInvestigation";

// ─── Field helpers ────────────────────────────────────────────────────────────

function extractStr(raw: Record<string, unknown>, ...keys: string[]): string {
  for (const k of keys) {
    const v = raw[k];
    if (typeof v === "string" && v) return v;
  }
  return "";
}

function domainOf(email: string): string {
  return email.split("@")[1]?.toLowerCase().replace(/[<>]/g, "") ?? "";
}

function stripAngle(s: string): string {
  return s.replace(/^<|>$/g, "").trim();
}

// ─── Auth badge ───────────────────────────────────────────────────────────────

type AuthResult = "pass" | "fail" | "softfail" | "none" | "neutral" | "unknown";

function authResult(v: string): AuthResult {
  const l = v.toLowerCase();
  if (l.startsWith("pass")) return "pass";
  if (l.startsWith("softfail")) return "softfail";
  if (l.startsWith("fail")) return "fail";
  if (l === "none") return "none";
  if (l === "neutral") return "neutral";
  return "unknown";
}

function AuthBadge({ label, raw }: { label: string; raw: string }) {
  const r = authResult(raw);
  const cfg: Record<AuthResult, { cls: string; Icon: typeof ShieldCheck; text: string }> = {
    pass:     { cls: "border-emerald-500/50 bg-emerald-500/10 text-emerald-400", Icon: ShieldCheck, text: "pass" },
    softfail: { cls: "border-neon-amber/50 bg-neon-amber/10 text-neon-amber",  Icon: ShieldAlert, text: "softfail" },
    fail:     { cls: "border-severity-high/60 bg-severity-high/10 text-severity-high", Icon: ShieldX, text: "fail" },
    none:     { cls: "border-slate-600/60 bg-slate-700/20 text-slate-400", Icon: ShieldAlert, text: "none" },
    neutral:  { cls: "border-slate-600/60 bg-slate-700/20 text-slate-400", Icon: ShieldAlert, text: "neutral" },
    unknown:  { cls: "border-slate-600/60 bg-slate-700/20 text-slate-400", Icon: ShieldAlert, text: raw || "—" },
  };
  const { cls, Icon, text } = cfg[r];
  return (
    <div className="flex items-center gap-2">
      <span className="w-12 shrink-0 text-[10px] font-semibold uppercase tracking-wider text-slate-500">{label}</span>
      <span className={cn("inline-flex items-center gap-1 rounded border px-1.5 py-0.5 font-mono text-[10px] font-bold", cls)}>
        <Icon className="h-2.5 w-2.5" />
        {text}
      </span>
    </div>
  );
}

// ─── Warning row ─────────────────────────────────────────────────────────────

function WarnRow({ label, value, warn, detail }: { label: string; value: string; warn?: boolean; detail?: string }) {
  return (
    <div className="flex items-start gap-2">
      <span className="w-28 shrink-0 text-[10px] text-slate-500">{label}</span>
      <div className="flex min-w-0 flex-col gap-0.5">
        <span className={cn("break-all font-mono text-[10px]", warn ? "text-neon-amber" : "text-slate-200")}>
          {value || "—"}
        </span>
        {warn && detail && (
          <span className="flex items-center gap-1 text-[9px] text-neon-amber/80">
            <AlertTriangle className="h-2.5 w-2.5 shrink-0" />
            {detail}
          </span>
        )}
      </div>
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export function EmailHeaderViewer({ event, onXp }: { event: LiveEvent; onXp?: (xp: number) => void }) {
  const [open, setOpen] = useState(true);
  const [showChain, setShowChain] = useState(false);
  const [showInvestigation, setShowInvestigation] = useState(false);

  const isEmail =
    event.event_type === "email_received" ||
    event.event_type === "email_sent" ||
    event.event_type === "email_clicked" ||
    event.event_type === "email_blocked" ||
    event.event_type === "email_quarantined";

  if (!isEmail) return null;

  const raw = (event.raw ?? {}) as Record<string, unknown>;

  // ── Extract header fields ─────────────────────────────────────────────────
  const from       = extractStr(raw, "email.from.address", "email.headers.from", "data.office365.P2Sender", "data.office365.P1Sender");
  const replyTo    = extractStr(raw, "email.headers.reply_to", "email.reply_to");
  const returnPath = extractStr(raw, "email.headers.return_path", "email.return_path");
  const msgId      = extractStr(raw, "email.headers.message_id", "email.message_id", "data.office365.InternetMessageId");
  const origIp     = extractStr(raw, "email.headers.x_originating_ip", "email.x_originating_ip", "data.office365.SenderIp", "source.ip", "email.headers.x_sender_ip");
  const xMailer    = extractStr(raw, "email.headers.x_mailer", "email.x_mailer");
  const subject    = extractStr(raw, "email.subject", "email.headers.subject", "data.office365.Subject");
  const to         = extractStr(raw, "email.to.address", "email.headers.to", "data.office365.Recipients");
  const contentType = extractStr(raw, "email.headers.content_type", "email.content_type");

  // ── Auth fields ───────────────────────────────────────────────────────────
  const spf   = extractStr(raw, "email.spf",  "email.spf_result")  || extractStr(raw, "email.auth_results").match(/spf=(\S+)/i)?.[1] || "";
  const dkim  = extractStr(raw, "email.dkim", "email.dkim_result") || extractStr(raw, "email.auth_results").match(/dkim=(\S+)/i)?.[1] || "";
  const dmarc = extractStr(raw, "email.dmarc","email.dmarc_result")|| extractStr(raw, "email.auth_results").match(/dmarc=(\S+)/i)?.[1] || "";
  const compAuth = extractStr(raw, "data.office365.AuthDetails.Value");
  const authResultsFull = extractStr(raw, "email.auth_results");

  // ── Received chain ────────────────────────────────────────────────────────
  const receivedHops: string[] = [];
  for (let i = 0; i <= 5; i++) {
    const hop = extractStr(raw, `email.headers.received_${i}`, `email.received.${i}`);
    if (hop) receivedHops.push(hop);
  }

  // ── Mismatch indicators ───────────────────────────────────────────────────
  const fromDomain    = domainOf(from);
  const replyToDomain = domainOf(replyTo);
  const returnDomain  = domainOf(stripAngle(returnPath));

  const replyToMismatch  = replyTo  && replyToDomain  && replyToDomain  !== fromDomain;
  const returnPathMismatch = returnPath && returnDomain && returnDomain !== fromDomain;

  const hasWarn =
    replyToMismatch ||
    returnPathMismatch ||
    authResult(spf) === "fail" ||
    authResult(spf) === "softfail" ||
    authResult(dkim) === "fail" ||
    authResult(dmarc) === "fail";

  const hasAuth = spf || dkim || dmarc || compAuth;
  const hasChain = receivedHops.length > 0;

  return (
    <>
    <div className={cn(
      "rounded border px-4 py-3",
      hasWarn
        ? "border-neon-amber/40 bg-neon-amber/5"
        : "border-border/60 bg-[#0d1520]"
    )}>
      {/* Header row */}
      <div className="flex w-full items-center justify-between gap-2">
        <button
          className="flex flex-1 items-center gap-2 min-w-0"
          onClick={() => setOpen(v => !v)}
        >
          <Mail className={cn("h-3.5 w-3.5 shrink-0", hasWarn ? "text-neon-amber" : "text-slate-400")} />
          <span className={cn("text-[10px] font-semibold uppercase tracking-[0.15em]", hasWarn ? "text-neon-amber" : "text-slate-500")}>
            Email Header Analysis
          </span>
          {hasWarn && (
            <span className="inline-flex items-center gap-1 rounded border border-neon-amber/60 bg-neon-amber/15 px-1.5 py-0.5 text-[9px] font-bold text-neon-amber">
              <AlertTriangle className="h-2.5 w-2.5" /> Suspicious Indicators
            </span>
          )}
        </button>
        <div className="flex shrink-0 items-center gap-1.5">
          <button
            onClick={() => setShowInvestigation(true)}
            className="inline-flex items-center gap-1 rounded border border-cyber-500/40 bg-cyber-500/10 px-2 py-1 text-[9px] font-semibold text-cyber-400 hover:bg-cyber-500/20 transition-colors"
          >
            <Search className="h-2.5 w-2.5" />
            חקור Header זדוני
          </button>
          {open
            ? <ChevronDown className="h-3.5 w-3.5 text-slate-500" />
            : <ChevronRight className="h-3.5 w-3.5 text-slate-500" />
          }
        </div>
      </div>

      {open && (
        <div className="mt-3 space-y-4">

          {/* ── Section 1: Envelope ────────────────────────────────────── */}
          <div className="space-y-1.5">
            <p className="text-[9px] font-bold uppercase tracking-widest text-slate-600">Envelope &amp; Headers</p>
            {subject   && <WarnRow label="Subject"     value={subject} />}
            {from      && <WarnRow label="From"        value={from} />}
            {to        && <WarnRow label="To"          value={to} />}
            <WarnRow
              label="Reply-To"
              value={replyTo || "(same as From)"}
              warn={!!replyToMismatch}
              detail={replyToMismatch ? `Domain mismatch — From: ${fromDomain} / Reply-To: ${replyToDomain}` : undefined}
            />
            <WarnRow
              label="Return-Path"
              value={returnPath || "(same as From)"}
              warn={!!returnPathMismatch}
              detail={returnPathMismatch ? `Envelope sender domain differs — From: ${fromDomain} / Return-Path: ${returnDomain}` : undefined}
            />
            {msgId     && <WarnRow label="Message-ID"  value={msgId} />}
            {origIp    && <WarnRow label="Originating IP" value={origIp} />}
            {xMailer   && <WarnRow label="X-Mailer"    value={xMailer} />}
            {contentType && <WarnRow label="Content-Type" value={contentType} />}
          </div>

          {/* ── Section 2: Authentication ──────────────────────────────── */}
          {(hasAuth || authResultsFull) && (
            <div className="space-y-1.5 border-t border-border/40 pt-3">
              <p className="mb-2 text-[9px] font-bold uppercase tracking-widest text-slate-600">Authentication Results</p>
              {spf   && <AuthBadge label="SPF"   raw={spf} />}
              {dkim  && <AuthBadge label="DKIM"  raw={dkim} />}
              {dmarc && <AuthBadge label="DMARC" raw={dmarc} />}
              {compAuth && !spf && !dkim && !dmarc && (
                <div className="flex items-center gap-2">
                  <span className="w-20 shrink-0 text-[10px] font-semibold uppercase tracking-wider text-slate-500">CompAuth</span>
                  <span className={cn(
                    "inline-flex items-center gap-1 rounded border px-1.5 py-0.5 font-mono text-[10px] font-bold",
                    compAuth.startsWith("pass") ? "border-emerald-500/50 bg-emerald-500/10 text-emerald-400" : "border-severity-high/60 bg-severity-high/10 text-severity-high"
                  )}>
                    {compAuth.startsWith("pass") ? <ShieldCheck className="h-2.5 w-2.5" /> : <ShieldX className="h-2.5 w-2.5" />}
                    {compAuth}
                  </span>
                </div>
              )}
              {authResultsFull && (
                <div className="mt-1.5 rounded bg-[#080d14] px-2.5 py-2">
                  <p className="mb-1 text-[9px] font-semibold text-slate-600">Authentication-Results raw header</p>
                  <p className="break-all font-mono text-[9px] leading-relaxed text-slate-400">{authResultsFull}</p>
                </div>
              )}
            </div>
          )}

          {/* ── Section 3: Received Chain ──────────────────────────────── */}
          {hasChain && (
            <div className="border-t border-border/40 pt-3">
              <button
                className="flex items-center gap-1.5 text-[9px] font-bold uppercase tracking-widest text-slate-600 hover:text-slate-400 transition-colors"
                onClick={() => setShowChain(v => !v)}
              >
                {showChain ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
                Received Chain ({receivedHops.length} {receivedHops.length === 1 ? "hop" : "hops"})
              </button>
              {showChain && (
                <div className="mt-2 space-y-1.5 pl-2">
                  {receivedHops.map((hop, i) => (
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
          )}

          {/* ── Analyst note ───────────────────────────────────────────── */}
          {!hasWarn && !hasAuth && !hasChain && (
            <p className="text-[10px] text-slate-600 italic">No header anomalies detected in this event's raw data.</p>
          )}

        </div>
      )}
    </div>

    {showInvestigation && (
      <EmailHeaderInvestigation
        onClose={() => setShowInvestigation(false)}
        onXp={(xp) => onXp?.(xp)}
      />
    )}
    </>
  );
}
