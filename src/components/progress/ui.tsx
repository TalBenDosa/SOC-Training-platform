"use client";
/** Small building blocks shared by the Progress page tabs. */
import { useId, useState } from "react";
import { Info } from "lucide-react";
import { cn } from "@/lib/utils";

/** "How is this computed": one plain sentence behind an ⓘ toggle (keyboard and screen-reader friendly). */
export function InfoTip({ text, className }: { text: string; className?: string }) {
  const [open, setOpen] = useState(false);
  const id = useId();
  return (
    <span className={cn("inline-flex flex-col", className)}>
      <button type="button" aria-expanded={open} aria-controls={id} onClick={() => setOpen(o => !o)}
        className="inline-flex h-5 w-5 items-center justify-center rounded text-slate-400 hover:text-cyber-300 focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyber-400">
        <Info aria-hidden="true" className="h-3.5 w-3.5" />
        <span className="sr-only">How this is computed</span>
      </button>
      {open && <span id={id} role="note" className="mt-1 max-w-xs text-[11px] font-normal normal-case tracking-normal text-slate-300">{text}</span>}
    </span>
  );
}

export function SectionTitle({ icon, children, right, info }: { icon?: React.ReactNode; children: React.ReactNode; right?: React.ReactNode; info?: string }) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-2">
      <h3 className="flex items-start gap-2 text-sm font-semibold text-white">
        {icon && <span className="mt-0.5 shrink-0">{icon}</span>}
        <span>{children}</span>
        {info && <InfoTip text={info} />}
      </h3>
      {right}
    </div>
  );
}

export function EmptyState({ title, body, action }: { title: string; body: string; action?: React.ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-border px-4 py-10 text-center">
      <p className="text-sm font-semibold text-slate-200">{title}</p>
      <p className="mt-1 max-w-md text-xs text-slate-400">{body}</p>
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function Tile({ label, value, sub, info, tone = "text-white" }: { label: string; value: React.ReactNode; sub?: React.ReactNode; info?: string; tone?: string }) {
  return (
    <div className="min-w-0 rounded-lg border border-border bg-bg-elevated p-3 sm:p-4">
      <div className="flex items-start justify-between gap-1">
        <p className="text-[10px] font-semibold uppercase tracking-widest text-slate-400 sm:text-[11px]">{label}</p>
        {info && <InfoTip text={info} />}
      </div>
      <p className={cn("mt-1.5 font-mono text-2xl font-semibold tabular-nums sm:text-3xl", tone)}>{value}</p>
      {sub && <p className="mt-0.5 text-[11px] text-slate-400">{sub}</p>}
    </div>
  );
}

export function LinkButton({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <a href={href} className="inline-flex shrink-0 items-center rounded-md border border-cyber-500/40 bg-cyber-500/10 px-3 py-1.5 text-xs font-semibold text-cyber-300 hover:bg-cyber-500/20 focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyber-400">
      {children}
    </a>
  );
}

/** A horizontal bar for a 0-100 value. */
export function Bar({ value, cls = "bg-cyber-400", label }: { value: number | null; cls?: string; label: string }) {
  const v = value === null ? 0 : Math.max(0, Math.min(100, value));
  return (
    <div className="h-2 w-full overflow-hidden rounded-full bg-bg" role="img" aria-label={label}>
      <div className={cn("h-full rounded-full", cls)} style={{ width: `${v}%` }} />
    </div>
  );
}
