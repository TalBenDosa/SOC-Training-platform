"use client";
import { ChevronRight, Shield, Trophy } from "lucide-react";

interface Props {
  clearedCompanyName: string;
  nextCompanyName: string | null;
  onContinue: () => void;
}

export function CompanyClearedModal({ clearedCompanyName, nextCompanyName, onContinue }: Props) {
  return (
    <div className="fixed inset-0 z-[70] flex items-center justify-center bg-black/85 backdrop-blur-md p-4">
      <div className="w-full max-w-md rounded-2xl border border-neon-green/40 bg-bg-elevated shadow-[0_0_60px_0_rgba(57,255,20,0.15)] overflow-hidden">
        <div className="h-1 w-full bg-gradient-to-r from-neon-green via-cyber-500 to-neon-green" />
        <div className="p-8 text-center space-y-6">

          <div className="flex justify-center">
            <div className="flex h-24 w-24 items-center justify-center rounded-full border-2 border-neon-green/50 bg-neon-green/10">
              <Shield className="h-12 w-12 text-neon-green" />
            </div>
          </div>

          <div>
            <p className="text-[11px] font-bold uppercase tracking-[0.25em] text-neon-green mb-2">Company Secured</p>
            <h2 className="text-2xl font-bold text-white">{clearedCompanyName}</h2>
            <p className="text-sm text-slate-400 mt-2 leading-relaxed">
              You identified the threat and completed the investigation.
            </p>
          </div>

          {nextCompanyName ? (
            <div className="rounded-xl border border-cyber-500/30 bg-cyber-500/10 px-5 py-4 space-y-1">
              <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-1">Now Unlocked</p>
              <p className="text-lg font-bold text-cyber-300">{nextCompanyName}</p>
            </div>
          ) : (
            <div className="rounded-xl border border-neon-amber/30 bg-neon-amber/10 px-5 py-4 space-y-2">
              <Trophy className="h-6 w-6 text-neon-amber mx-auto" />
              <p className="text-sm font-bold text-neon-amber">All Companies Secured!</p>
              <p className="text-xs text-slate-400">You are a Master SOC Analyst.</p>
            </div>
          )}

          <button
            onClick={onContinue}
            className="w-full flex items-center justify-center gap-2 rounded-xl bg-neon-green py-3 text-sm font-bold text-bg hover:bg-neon-green/90 transition"
          >
            {nextCompanyName ? `Start ${nextCompanyName}` : "Finish"}
            <ChevronRight className="h-4 w-4" />
          </button>
        </div>
      </div>
    </div>
  );
}
