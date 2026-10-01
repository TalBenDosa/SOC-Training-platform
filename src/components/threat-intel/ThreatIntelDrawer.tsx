"use client";

/**
 * Threat-intel drawer — the "Check Hash / Check IP / Check Domain" surface.
 *
 * Lifted out of the dashboard's EventFeed so the scenario log viewer can offer
 * the identical affordance instead of a second, divergent implementation. The
 * verdict and every enrichment detail come from src/lib/edr/iocIntel.ts: the
 * scenario's IOC truth table when the caller passes one (so an attacker IOC is
 * never "Comcast residential, 0/90"), otherwise the event's own vendor fields —
 * with ASN / WHOIS / detection counts seeded by the IOC value, so the same IOC
 * returns the same answer on every lookup surface (URL and domain included).
 */

import { useEffect } from "react";
import { motion } from "framer-motion";
import { Shield, X } from "lucide-react";
import { cn } from "@/lib/utils";
import type { TelemetryEvent } from "@/lib/sim/types";
import {
  hashIntel, ipIntel, domainIntel,
  type HashIntel, type IpIntel, type DomainIntel, type IocTruth, type IocVerdict,
} from "@/lib/edr/iocIntel";

// The field predicates the log viewers use to decide where a "Check …" button goes.
// They live with the intel logic now; re-exported so existing imports keep working.
export { isSha256Field, isIpCheckField, isDomainCheckField } from "@/lib/edr/iocIntel";
export type { IocTruth } from "@/lib/edr/iocIntel";

// ─── Threat Intel types ────────────────────────────────────────────────────────

/**
 * A lookup request. `truth` is the scenario's IOC truth table (built server-side by
 * buildIocTruth over the full bundle) — when present it decides the verdict, so an
 * attacker IOC enriches as malicious on every surface even though the client-side
 * event has had its description / MITRE mapping stripped. Without it the verdict
 * falls back to what the event itself says. Every detail (ASN, WHOIS age, counts)
 * is seeded by the IOC value, so the same IOC always returns the same answer.
 */
export type ThreatQuery =
  | { type: "hash";   value: string; event: TelemetryEvent; truth?: IocTruth | null }
  | { type: "ip";     value: string; event: TelemetryEvent; truth?: IocTruth | null }
  | { type: "domain"; value: string; event: TelemetryEvent; truth?: IocTruth | null };

type HashIntelData = HashIntel;
type IpIntelData = IpIntel;
type DomainIntelData = DomainIntel;

const COUNTRY_FLAGS: Record<string, string> = {
  "Germany": "🇩🇪", "Russia": "🇷🇺", "United States": "🇺🇸",
  "China": "🇨🇳", "Netherlands": "🇳🇱", "France": "🇫🇷",
  "Ukraine": "🇺🇦", "Romania": "🇷🇴", "Brazil": "🇧🇷",
  "United Kingdom": "🇬🇧", "Singapore": "🇸🇬", "India": "🇮🇳",
  "North Korea": "🇰🇵", "Iran": "🇮🇷", "Moldova": "🇲🇩", "Hong Kong": "🇭🇰", "Nigeria": "🇳🇬",
};

/** Verdict → headline + colour classes, shared by the three panels. */
function verdictStyle(v: IocVerdict, badWord = "MALICIOUS") {
  if (v === "malicious") return { label: `⚠ ${badWord}`, text: "text-severity-critical", box: "border-severity-critical/40 bg-severity-critical/10", bar: "bg-severity-critical" };
  if (v === "suspicious") return { label: "⚠ SUSPICIOUS", text: "text-neon-amber", box: "border-neon-amber/40 bg-neon-amber/10", bar: "bg-neon-amber" };
  if (v === "internal") return { label: "INTERNAL", text: "text-slate-300", box: "border-border/60 bg-black/20", bar: "bg-slate-500" };
  return { label: "✓ CLEAN", text: "text-neon-green", box: "border-neon-green/40 bg-neon-green/10", bar: "bg-neon-green" };
}

// ─── Hash Intel Panel ──────────────────────────────────────────────────────────

function HashPanel({ data, onClose }: { data: HashIntelData; onClose: () => void }) {
  const detected = data.engines.filter(e => e.detected).length;
  const total    = data.engines.length;
  const pct      = Math.round((detected / total) * 100);
  const isMal    = data.malicious;
  const vs       = verdictStyle(data.verdict);

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between border-b border-border/60 px-5 py-4 shrink-0">
        <div className="flex items-center gap-2">
          <Shield className="h-4 w-4 text-cyber-300" />
          <span className="text-xs font-bold uppercase tracking-widest text-slate-300">Threat Intelligence</span>
          <span className="rounded border border-border/60 bg-black/30 px-1.5 py-0.5 text-[9px] font-semibold uppercase text-slate-400">File Hash</span>
        </div>
        <button onClick={onClose} aria-label="Close threat intelligence" className="text-slate-400 hover:text-white transition rounded p-0.5">
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-5 space-y-4">
        {/* Hash */}
        <div>
          <p className="text-[9px] font-semibold uppercase tracking-widest text-slate-400 mb-1">SHA-256</p>
          <p className="font-mono text-[10px] text-neon-amber break-all leading-relaxed">{data.hash}</p>
        </div>

        {/* Verdict */}
        <div className={cn("rounded border px-4 py-3", vs.box)}>
          <div className="flex items-center justify-between mb-2">
            <span className={cn("text-base font-black tracking-wider", vs.text)}>{vs.label}</span>
            <span className={cn("font-mono text-sm font-bold", vs.text)}>
              {detected} / {total}
            </span>
          </div>
          <div className="w-full h-2 rounded-full bg-slate-700/60 overflow-hidden">
            <div className={cn("h-full rounded-full", vs.bar)} style={{ width: `${pct}%` }} />
          </div>
          <p className="text-[10px] text-slate-400 mt-1.5">
            {detected > 0
              ? `${detected} of ${total} security vendors flagged this file`
              : "No security vendor flagged this file"}
          </p>
        </div>

        {/* Malware details */}
        {isMal && (
          <div className="rounded border border-border/60 bg-[#0d1520] px-4 py-3 space-y-2">
            <p className="text-[9px] font-semibold uppercase tracking-widest text-slate-400 mb-2">Malware Classification</p>
            {data.malwareName && (
              <div className="flex gap-3 items-baseline">
                <span className="w-28 shrink-0 text-[10px] text-slate-400">Detection Name</span>
                <span className="font-mono text-[10px] text-severity-critical">{data.malwareName}</span>
              </div>
            )}
            {data.malwareFamily && (
              <div className="flex gap-3 items-baseline">
                <span className="w-28 shrink-0 text-[10px] text-slate-400">Family</span>
                <span className="font-mono text-[10px] text-slate-200">{data.malwareFamily}</span>
              </div>
            )}
            <div className="flex gap-3 items-baseline">
              <span className="w-28 shrink-0 text-[10px] text-slate-400">File Type</span>
              <span className="font-mono text-[10px] text-slate-200">{data.fileType}</span>
            </div>
            {data.fileName && (
              <div className="flex gap-3 items-baseline">
                <span className="w-28 shrink-0 text-[10px] text-slate-400">File Name</span>
                <span className="font-mono text-[10px] text-slate-200">{data.fileName}</span>
              </div>
            )}
            {data.originalFileName && (
              <div className="flex gap-3 items-baseline">
                <span className="w-28 shrink-0 text-[10px] text-slate-400">Original Name (PE)</span>
                <span className="font-mono text-[10px] text-slate-200">{data.originalFileName}</span>
              </div>
            )}
            <div className="flex gap-3 items-baseline">
              <span className="w-28 shrink-0 text-[10px] text-slate-400">First Seen</span>
              <span className="font-mono text-[10px] text-slate-200">{data.firstSeen}</span>
            </div>
            <div className="flex gap-3 items-baseline">
              <span className="w-28 shrink-0 text-[10px] text-slate-400">Last Seen</span>
              <span className="font-mono text-[10px] text-slate-200">{data.lastSeen}</span>
            </div>
          </div>
        )}

        {/* Tags */}
        {data.tags.length > 0 && (
          <div>
            <p className="text-[9px] font-semibold uppercase tracking-widest text-slate-400 mb-2">Tags</p>
            <div className="flex flex-wrap gap-1.5">
              {data.tags.map(tag => (
                <span key={tag} className="rounded border border-border/60 bg-black/20 px-2 py-0.5 font-mono text-[9px] text-slate-400">
                  {tag}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Engine table */}
        <div>
          <p className="text-[9px] font-semibold uppercase tracking-widest text-slate-400 mb-2">
            Security Vendor Analysis &nbsp;<span className="text-slate-400">({detected}/{total} detected)</span>
          </p>
          <div className="rounded border border-border/60 overflow-hidden text-[10px]">
            {data.engines.map((eng, i) => (
              <div key={eng.name} className={cn(
                "flex items-center justify-between px-3 py-2",
                i > 0 && "border-t border-border/30",
                eng.detected ? (data.verdict === "suspicious" ? "bg-neon-amber/5" : "bg-severity-critical/5") : ""
              )}>
                <span className={cn("font-medium w-[140px] shrink-0", eng.detected ? "text-slate-200" : "text-slate-400")}>{eng.name}</span>
                {eng.detected
                  ? <span className={cn("font-mono truncate", data.verdict === "suspicious" ? "text-neon-amber" : "text-severity-critical")}>{eng.result}</span>
                  : <span className="text-slate-700">— (no detection)</span>
                }
              </div>
            ))}
          </div>
        </div>

        {/* Disclaimer */}
        <div className="rounded border border-border/30 bg-black/20 px-3 py-2">
          <p className="text-[9px] text-slate-400 leading-relaxed">
            Simulated threat intelligence for training purposes. Results are derived from log metadata and do not represent live external lookups.
          </p>
        </div>
      </div>
    </div>
  );
}

// ─── IP Intel Panel ────────────────────────────────────────────────────────────

function IpPanel({ data, onClose }: { data: IpIntelData; onClose: () => void }) {
  const pct = data.confidence;
  const vs = verdictStyle(data.verdict, "ABUSIVE");
  const flag = (data.country && COUNTRY_FLAGS[data.country]) || "🌐";

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between border-b border-border/60 px-5 py-4 shrink-0">
        <div className="flex items-center gap-2">
          <Shield className="h-4 w-4 text-neon-blue" />
          <span className="text-xs font-bold uppercase tracking-widest text-slate-300">Threat Intelligence</span>
          <span className="rounded border border-border/60 bg-black/30 px-1.5 py-0.5 text-[9px] font-semibold uppercase text-slate-400">IP Address</span>
        </div>
        <button onClick={onClose} aria-label="Close threat intelligence" className="text-slate-400 hover:text-white transition rounded p-0.5">
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-5 space-y-4">
        {/* IP */}
        <div>
          <p className="text-[9px] font-semibold uppercase tracking-widest text-slate-400 mb-1">IP Address</p>
          <p className="font-mono text-base font-bold text-neon-blue">{data.ip}</p>
        </div>

        {/* Verdict */}
        <div className={cn("rounded border px-4 py-3", vs.box)}>
          <div className="flex items-center justify-between mb-2">
            <span className={cn("text-base font-black tracking-wider", vs.text)}>{vs.label}</span>
            <span className={cn("font-mono text-sm font-bold", vs.text)}>
              {data.verdict === "internal" ? "private range" : `${pct}% confidence`}
            </span>
          </div>
          <div className="w-full h-2 rounded-full bg-slate-700/60 overflow-hidden">
            <div className={cn("h-full rounded-full", vs.bar)} style={{ width: `${pct}%` }} />
          </div>
          <p className="text-[10px] text-slate-400 mt-1.5">
            {data.verdict === "internal"
              ? "Internal address — no public reputation; investigate it through your own asset inventory"
              : data.abusive
                ? `${data.totalReports.toLocaleString()} abuse reports on record`
                : "No abuse reports on record"}
          </p>
        </div>

        {/* IP info */}
        <div className="rounded border border-border/60 bg-[#0d1520] px-4 py-3 space-y-2">
          <p className="text-[9px] font-semibold uppercase tracking-widest text-slate-400 mb-2">IP Information</p>
          {data.country && (
            <div className="flex gap-3 items-baseline">
              <span className="w-28 shrink-0 text-[10px] text-slate-400">Country</span>
              <span className="text-[10px] text-slate-200">{data.verdict === "internal" ? "" : `${flag} `}{data.country}</span>
            </div>
          )}
          {data.asn && (
            <div className="flex gap-3 items-baseline">
              <span className="w-28 shrink-0 text-[10px] text-slate-400">ASN</span>
              <span className="font-mono text-[10px] text-slate-200">{data.asn}</span>
            </div>
          )}
          {data.isp && (
            <div className="flex gap-3 items-baseline">
              <span className="w-28 shrink-0 text-[10px] text-slate-400">ISP / Org</span>
              <span className="font-mono text-[10px] text-slate-200">{data.isp}</span>
            </div>
          )}
          {data.usageType && (
            <div className="flex gap-3 items-baseline">
              <span className="w-28 shrink-0 text-[10px] text-slate-400">Usage Type</span>
              <span className="text-[10px] text-slate-200">{data.usageType}</span>
            </div>
          )}
          {data.abusive && data.totalReports > 0 && (
            <>
              <div className="flex gap-3 items-baseline">
                <span className="w-28 shrink-0 text-[10px] text-slate-400">Total Reports</span>
                <span className="font-mono text-[10px] text-severity-critical">{data.totalReports.toLocaleString()}</span>
              </div>
              {data.lastReported && (
                <div className="flex gap-3 items-baseline">
                  <span className="w-28 shrink-0 text-[10px] text-slate-400">Last Reported</span>
                  <span className="font-mono text-[10px] text-slate-200">{data.lastReported}</span>
                </div>
              )}
            </>
          )}
        </div>

        {/* Categories */}
        {data.categories.length > 0 && (
          <div>
            <p className="text-[9px] font-semibold uppercase tracking-widest text-slate-400 mb-2">Abuse Categories</p>
            <div className="flex flex-wrap gap-1.5">
              {data.categories.map(cat => (
                <span key={cat} className="rounded border border-severity-critical/40 bg-severity-critical/10 px-2 py-0.5 text-[9px] font-semibold text-severity-critical">
                  {cat}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Disclaimer */}
        <div className="rounded border border-border/30 bg-black/20 px-3 py-2">
          <p className="text-[9px] text-slate-400 leading-relaxed">
            Simulated threat intelligence for training purposes. Results are derived from log metadata and do not represent live external lookups.
          </p>
        </div>
      </div>
    </div>
  );
}

// ─── Domain Intel Panel ────────────────────────────────────────────────────────

function DomainPanel({ data, onClose }: { data: DomainIntelData; onClose: () => void }) {
  const vs = verdictStyle(data.verdict);
  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between border-b border-border/60 px-5 py-4 shrink-0">
        <div className="flex items-center gap-2">
          <Shield className="h-4 w-4 text-neon-green" />
          <span className="text-xs font-bold uppercase tracking-widest text-slate-300">Threat Intelligence</span>
          <span className="rounded border border-border/60 bg-black/30 px-1.5 py-0.5 text-[9px] font-semibold uppercase text-slate-400">Domain</span>
        </div>
        <button onClick={onClose} aria-label="Close threat intelligence" className="text-slate-400 hover:text-white transition rounded p-0.5">
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-5 space-y-4">
        {/* Domain */}
        <div>
          <p className="text-[9px] font-semibold uppercase tracking-widest text-slate-400 mb-1">Domain</p>
          <p className="font-mono text-sm font-bold text-neon-green break-all">{data.domain}</p>
          {data.lookedUp && (
            <p className="mt-1 font-mono text-[9px] text-slate-500 break-all">looked up from URL: {data.lookedUp}</p>
          )}
        </div>

        {/* Verdict */}
        <div className={cn("rounded border px-4 py-3", vs.box)}>
          <div className="flex items-center justify-between mb-2">
            <span className={cn("text-base font-black tracking-wider", vs.text)}>{vs.label}</span>
            <span className={cn("font-mono text-sm font-bold", vs.text)}>
              {data.detectionCount} / {data.total} vendors
            </span>
          </div>
          <p className="text-[10px] text-slate-400 mt-1.5">
            {data.malicious
              ? `${data.detectionCount} security vendors flagged this domain`
              : "No security vendor flagged this domain"}
          </p>
        </div>

        {/* WHOIS-style info */}
        <div className="rounded border border-border/60 bg-[#0d1520] px-4 py-3 space-y-2">
          <p className="text-[9px] font-semibold uppercase tracking-widest text-slate-400 mb-2">Registration Info</p>
          {data.registrar && (
            <div className="flex gap-3 items-baseline">
              <span className="w-28 shrink-0 text-[10px] text-slate-400">Registrar</span>
              <span className="font-mono text-[10px] text-slate-200">{data.registrar}</span>
            </div>
          )}
          {data.creationDate && (
            <div className="flex gap-3 items-baseline">
              <span className="w-28 shrink-0 text-[10px] text-slate-400">Created</span>
              <span className={cn("font-mono text-[10px]", data.malicious && data.ageDays <= 30 ? "text-severity-critical" : "text-slate-200")}>
                {data.creationDate} ({data.ageDays} day{data.ageDays === 1 ? "" : "s"} old)
              </span>
            </div>
          )}
        </div>

        {/* Categories */}
        {data.categories.length > 0 && (
          <div>
            <p className="text-[9px] font-semibold uppercase tracking-widest text-slate-400 mb-2">Categories</p>
            <div className="flex flex-wrap gap-1.5">
              {data.categories.map(cat => (
                <span key={cat} className="rounded border border-severity-critical/40 bg-severity-critical/10 px-2 py-0.5 text-[9px] font-semibold text-severity-critical">
                  {cat}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Tags */}
        {data.tags.length > 0 && (
          <div>
            <p className="text-[9px] font-semibold uppercase tracking-widest text-slate-400 mb-2">Tags</p>
            <div className="flex flex-wrap gap-1.5">
              {data.tags.map(tag => (
                <span key={tag} className="rounded border border-border/60 bg-black/20 px-2 py-0.5 font-mono text-[9px] text-slate-400">
                  {tag}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Disclaimer */}
        <div className="rounded border border-border/30 bg-black/20 px-3 py-2">
          <p className="text-[9px] text-slate-400 leading-relaxed">
            Simulated threat intelligence for training purposes. Results are derived from log metadata and do not represent live external lookups.
          </p>
        </div>
      </div>
    </div>
  );
}

// ─── Threat Intel Drawer (right-side panel) ────────────────────────────────────

export function ThreatIntelDrawer({ query, onClose, truth }: {
  query: ThreatQuery;
  onClose: () => void;
  /** Scenario IOC truth table (server-built). Also accepted on the query itself. */
  truth?: IocTruth | null;
}) {
  // Close on Escape
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onClose]);

  const opts = { event: query.event, truth: query.truth ?? truth ?? null };
  const hashData   = query.type === "hash"   ? hashIntel(query.value, opts)   : null;
  const ipData     = query.type === "ip"     ? ipIntel(query.value, opts)     : null;
  const domainData = query.type === "domain" ? domainIntel(query.value, opts) : null;

  return (
    <>
      <motion.div
        initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
        className="fixed inset-0 bg-black/50 z-40"
        onClick={onClose}
      />
      <motion.div
        initial={{ x: 460 }} animate={{ x: 0 }} exit={{ x: 460 }}
        transition={{ type: "spring", damping: 28, stiffness: 260 }}
        className="fixed right-0 top-0 h-screen w-full sm:w-[440px] bg-[#080d14] border-l border-border/80 z-50 shadow-2xl"
      >
        {hashData   && <HashPanel   data={hashData}   onClose={onClose} />}
        {ipData     && <IpPanel     data={ipData}     onClose={onClose} />}
        {domainData && <DomainPanel data={domainData} onClose={onClose} />}
      </motion.div>
    </>
  );
}
