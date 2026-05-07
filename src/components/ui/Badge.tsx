import { cn } from "@/lib/utils";

export function Badge({
  children, className, variant = "default",
}: {
  children: React.ReactNode;
  className?: string;
  variant?: "default" | "outline" | "solid";
}) {
  const base = "inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-medium tracking-wide uppercase";
  const variants: Record<string, string> = {
    default: "bg-bg-elevated border border-border text-slate-200",
    outline: "border border-border-strong text-slate-300",
    solid:   "bg-cyber-500 text-bg",
  };
  return <span className={cn(base, variants[variant], className)}>{children}</span>;
}

export function SeverityBadge({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    critical:      "text-severity-critical bg-severity-critical/10 border-severity-critical/40",
    high:          "text-severity-high bg-severity-high/10 border-severity-high/40",
    medium:        "text-severity-medium bg-severity-medium/10 border-severity-medium/40",
    low:           "text-severity-low bg-severity-low/10 border-severity-low/40",
    informational: "text-severity-info bg-severity-info/10 border-severity-info/40",
  };
  return (
    <span className={cn(
      "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[10px] font-bold tracking-widest uppercase",
      map[severity] ?? map.informational
    )}>
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {severity}
    </span>
  );
}

export function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    new:            "text-cyber-300 bg-cyber-500/10 border-cyber-500/30",
    triaging:       "text-neon-amber bg-neon-amber/10 border-neon-amber/30",
    investigating:  "text-neon-blue bg-neon-blue/10 border-neon-blue/30",
    contained:      "text-neon-green bg-neon-green/10 border-neon-green/30",
    resolved:       "text-neon-green bg-neon-green/10 border-neon-green/30",
    false_positive: "text-slate-400 bg-slate-500/10 border-slate-500/30",
    escalated:      "text-severity-critical bg-severity-critical/10 border-severity-critical/30",
  };
  return (
    <span className={cn(
      "inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] font-semibold tracking-wider uppercase",
      map[status] ?? map.new
    )}>
      {status.replace("_"," ")}
    </span>
  );
}
