"use client";
import { Bell, Search, ShieldAlert, User } from "lucide-react";

export function Topbar({ title, subtitle, actions }: { title?: string; subtitle?: string; actions?: React.ReactNode }) {
  return (
    <header className="sticky top-0 z-30 flex items-center gap-4 border-b border-border bg-bg/80 px-6 py-3 backdrop-blur">
      <div className="flex flex-1 items-center gap-4">
        {title && (
          <div>
            <h1 className="text-lg font-semibold text-white">{title}</h1>
            {subtitle && <p className="text-xs text-slate-400">{subtitle}</p>}
          </div>
        )}
        <div className="ml-auto flex items-center gap-2">
          <div className="relative hidden md:block">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
            <input
              placeholder="Search alerts, IOCs, hosts, users…"
              className="h-9 w-72 rounded-md border border-border bg-bg-elevated pl-9 pr-3 text-sm text-slate-200 placeholder-slate-500 focus:border-cyber-500/50 focus:outline-none focus:ring-2 focus:ring-cyber-500/30"
            />
          </div>
          {actions}
          <button className="relative inline-flex h-9 w-9 items-center justify-center rounded-md border border-border bg-bg-elevated text-slate-300 hover:bg-bg-hover" aria-label="Alerts">
            <Bell className="h-4 w-4" />
            <span className="absolute -right-1 -top-1 h-4 min-w-4 rounded-full bg-severity-critical px-1 text-[10px] font-bold leading-4 text-white">7</span>
          </button>
          <button className="inline-flex h-9 w-9 items-center justify-center rounded-md border border-border bg-bg-elevated text-slate-300 hover:bg-bg-hover" aria-label="Threat level">
            <ShieldAlert className="h-4 w-4 text-severity-high" />
          </button>
          <button className="flex items-center gap-2 rounded-md border border-border bg-bg-elevated px-2 py-1.5 hover:bg-bg-hover">
            <span className="flex h-6 w-6 items-center justify-center rounded-full bg-cyber-500/20 text-cyber-300 text-xs font-bold">A</span>
            <span className="hidden md:flex flex-col items-start leading-tight">
              <span className="text-xs font-semibold text-slate-100">Analyst</span>
              <span className="text-[10px] text-slate-500 font-mono">tier-2</span>
            </span>
          </button>
        </div>
      </div>
    </header>
  );
}
