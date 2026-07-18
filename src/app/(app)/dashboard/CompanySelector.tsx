"use client";
import { cn } from "@/lib/utils";
import { COMPANY_PROFILES } from "@/lib/sim/companyProfiles";
import { CheckCircle2, Cloud, Lock, Shield, Building2, Server, Users } from "lucide-react";

const INDUSTRY_ICON: Record<string, string> = {
  "Financial Services":          "💹",
  "Technology / SaaS":           "🚀",
  "Healthcare":                  "🏥",
  "Logistics / Manufacturing":   "🏭",
  "Banking / Finance":           "🏦",
};

const SIZE_LABEL = (n: number) =>
  n < 500 ? "Small" : n < 2000 ? "Mid-size" : n < 5000 ? "Large" : "Enterprise";

interface Props {
  currentId?: string;
  onSelect: (id: string) => void;
  onClose?: () => void;
  unlockedIds?: string[];
  clearedIds?: string[];
}

export function CompanySelector({ currentId, onSelect, onClose, unlockedIds, clearedIds }: Props) {
  const clearedCount = clearedIds?.length ?? 0;
  const totalCount   = COMPANY_PROFILES.length;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
      <div className="w-full max-w-5xl rounded-2xl border border-border bg-bg-elevated shadow-2xl overflow-hidden">

        {/* Top gradient bar */}
        <div className="h-1 w-full bg-gradient-to-r from-cyber-500 via-neon-purple to-severity-critical" />

        {/* Header */}
        <div className="flex items-start justify-between gap-4 border-b border-border px-8 py-6">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <Shield className="h-5 w-5 text-cyber-300" />
              <span className="text-[10px] font-bold uppercase tracking-[0.2em] text-cyber-300">SOC OPERATOR CONSOLE</span>
            </div>
            <h2 className="text-xl font-bold text-white">Select Organisation to Monitor</h2>
            <p className="mt-1 text-sm text-slate-400">
              Each organisation runs a distinct security stack.
            </p>
          </div>
          <div className="flex flex-col items-end gap-2">
            {onClose && (
              <button onClick={onClose} className="text-slate-500 hover:text-slate-300 transition text-xs border border-border rounded px-2 py-1">
                ESC
              </button>
            )}
            {unlockedIds && (
              <div className="text-right">
                <p className="text-[10px] font-bold uppercase tracking-widest text-neon-green">
                  {clearedCount}/{totalCount} Secured
                </p>
                <div className="mt-1 flex gap-1">
                  {COMPANY_PROFILES.map(c => (
                    <div
                      key={c.id}
                      className={cn(
                        "h-1.5 w-6 rounded-full",
                        clearedIds?.includes(c.id) ? "bg-neon-green" :
                        unlockedIds.includes(c.id) ? "bg-cyber-500/60" :
                        "bg-slate-700"
                      )}
                    />
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Company grid */}
        <div className="grid grid-cols-1 gap-3 p-6 sm:grid-cols-2 lg:grid-cols-3 max-h-[65vh] overflow-y-auto">
          {COMPANY_PROFILES.map((c) => {
            const isActive  = c.id === currentId;
            const isLocked  = unlockedIds ? !unlockedIds.includes(c.id) : false;
            const isCleared = clearedIds?.includes(c.id) ?? false;

            return (
              <button
                key={c.id}
                onClick={() => !isLocked && onSelect(c.id)}
                disabled={isLocked}
                className={cn(
                  "group relative flex flex-col rounded-xl border p-5 text-left transition-all duration-150",
                  isLocked
                    ? "border-border/30 bg-[#0a0f18] opacity-50 cursor-not-allowed"
                    : isActive
                      ? "border-cyber-500/60 bg-cyber-500/10 ring-1 ring-cyber-500/30"
                      : "border-border/60 bg-[#0d1520] hover:border-border-strong hover:bg-bg-hover"
                )}
              >
                {/* Status badge */}
                {isLocked && (
                  <span className="absolute right-3 top-3 flex items-center gap-1 rounded-full bg-slate-800 border border-slate-700 px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider text-slate-500">
                    <Lock className="h-2.5 w-2.5" /> Locked
                  </span>
                )}
                {!isLocked && isCleared && !isActive && (
                  <span className="absolute right-3 top-3 flex items-center gap-1 rounded-full bg-neon-green/15 border border-neon-green/30 px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider text-neon-green">
                    <CheckCircle2 className="h-2.5 w-2.5" /> Cleared
                  </span>
                )}
                {isActive && (
                  <span className="absolute right-3 top-3 flex items-center gap-1 rounded-full bg-cyber-500/20 px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider text-cyber-300">
                    <CheckCircle2 className="h-2.5 w-2.5" /> Active
                  </span>
                )}

                {/* Lock overlay */}
                {isLocked && (
                  <div className="absolute inset-0 flex items-center justify-center rounded-xl">
                    <Lock className="h-8 w-8 text-slate-600" />
                  </div>
                )}

                {/* Industry + name */}
                <div className="flex items-start gap-3 mb-3">
                  <span className="text-2xl">{INDUSTRY_ICON[c.industry] ?? "🏢"}</span>
                  <div className="min-w-0">
                    <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">{c.industry}</p>
                    <h3 className="text-sm font-bold text-white leading-tight">{c.name}</h3>
                    <p className="text-[10px] text-slate-400">{c.tagline}</p>
                  </div>
                </div>

                {/* Meta row */}
                <div className="flex items-center gap-3 mb-3 text-[10px] text-slate-500">
                  <span className="flex items-center gap-1">
                    <Building2 className="h-3 w-3" /> {c.hq}
                  </span>
                  <span className="flex items-center gap-1">
                    <Users className="h-3 w-3" /> {c.size.toLocaleString()} · {SIZE_LABEL(c.size)}
                  </span>
                </div>

                {/* Architecture stack */}
                <div className="mt-auto space-y-1.5 rounded-lg border border-border/40 bg-bg/60 px-3 py-2.5">
                  <p className="text-[9px] font-bold uppercase tracking-wider text-slate-600 mb-1.5">Security Stack</p>
                  <StackRow icon={<Shield className="h-3 w-3" />} label="EDR"      value={c.architecture.edr}      color="text-cyber-300" />
                  <StackRow icon={<Cloud  className="h-3 w-3" />} label="Cloud"    value={c.architecture.cloud}    color="text-neon-blue" />
                  <StackRow icon={<Server className="h-3 w-3" />} label="Identity" value={c.architecture.idp}      color="text-neon-purple" />
                  <StackRow icon={<Shield className="h-3 w-3" />} label="Firewall" value={c.architecture.firewall} color="text-severity-high" />
                </div>

                {/* Source tags */}
                <div className="mt-3 flex flex-wrap gap-1">
                  {c.architecture.sources.map(s => (
                    <span key={s} className="rounded border border-border/50 bg-bg px-1.5 py-0.5 font-mono text-[9px] text-slate-400 uppercase">
                      {s}
                    </span>
                  ))}
                </div>
              </button>
            );
          })}
        </div>

        {/* Footer */}
        <div className="border-t border-border/60 bg-bg/40 px-8 py-3 text-[10px] text-slate-500">
          Identify the attack and submit an escalation ticket to secure a company and unlock the next one.
        </div>
      </div>
    </div>
  );
}

function StackRow({
  icon, label, value, color,
}: { icon: React.ReactNode; label: string; value: string; color: string }) {
  return (
    <div className="flex items-center gap-1.5">
      <span className="text-slate-600">{icon}</span>
      <span className="w-14 shrink-0 text-[9px] text-slate-600 uppercase tracking-wider">{label}</span>
      <span className={cn("text-[10px] font-medium truncate", color)}>{value}</span>
    </div>
  );
}
