import { cn } from "@/lib/utils";

export function Card({
  children, className, glow = false, padded = true,
}: {
  children: React.ReactNode;
  className?: string;
  glow?: boolean;
  padded?: boolean;
}) {
  return (
    <div className={cn(
      "rounded-lg border border-border bg-bg-elevated/60 backdrop-blur-sm",
      glow && "shadow-glow",
      padded && "p-5",
      className,
    )}>
      {children}
    </div>
  );
}

export function StatCard({
  label, value, delta, icon, accent = "cyber",
}: {
  label: string;
  value: string | number;
  delta?: { value: string; positive?: boolean };
  icon?: React.ReactNode;
  accent?: "cyber" | "red" | "green" | "amber" | "purple";
}) {
  const accentMap: Record<string,string> = {
    cyber:  "from-cyber-500/15 to-transparent text-cyber-300",
    red:    "from-severity-critical/20 to-transparent text-severity-critical",
    green:  "from-neon-green/15 to-transparent text-neon-green",
    amber:  "from-severity-medium/20 to-transparent text-severity-medium",
    purple: "from-neon-purple/15 to-transparent text-neon-purple",
  };
  return (
    <div className={cn("relative overflow-hidden rounded-lg border border-border bg-bg-elevated p-4")}>
      <div className={cn("pointer-events-none absolute inset-0 bg-gradient-to-br opacity-60", accentMap[accent])} />
      <div className="relative flex items-start justify-between">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-widest text-slate-400">{label}</p>
          <p className="mt-2 font-mono text-3xl font-semibold text-white">{value}</p>
          {delta && (
            <p className={cn("mt-1 text-xs font-medium", delta.positive ? "text-neon-green" : "text-severity-critical")}>
              {delta.positive ? "▲" : "▼"} {delta.value}
            </p>
          )}
        </div>
        {icon && <div className={cn("rounded-lg border border-border p-2", accentMap[accent])}>{icon}</div>}
      </div>
    </div>
  );
}
