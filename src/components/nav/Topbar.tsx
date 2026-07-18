"use client";

// Note: this Topbar intentionally has no search box, notification bell, or
// "threat level" icon. All three used to render here but did nothing when
// clicked/typed into (a decorative control that never responds trains users
// to distrust the rest of the UI's feedback) — see PLATFORM_REVIEW.md P2.2.
// Any page that genuinely needs search has its own working search field
// (e.g. the Dashboard's live event feed).
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
          {actions}
          <span className="flex items-center gap-2 rounded-md border border-border bg-bg-elevated px-2 py-1.5">
            <span className="flex h-6 w-6 items-center justify-center rounded-full bg-cyber-500/20 text-cyber-300 text-xs font-bold">A</span>
            <span className="hidden md:flex flex-col items-start leading-tight">
              <span className="text-xs font-semibold text-slate-100">Analyst</span>
              <span className="text-[10px] text-slate-500 font-mono">tier-2</span>
            </span>
          </span>
        </div>
      </div>
    </header>
  );
}
