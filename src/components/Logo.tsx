import { cn } from "@/lib/utils";

export function Logo({ className, size = "md" }: { className?: string; size?: "sm" | "md" | "lg" }) {
  const text = size === "lg" ? "text-2xl" : size === "sm" ? "text-sm" : "text-lg";
  return (
    <div className={cn("flex items-center gap-2.5 font-mono font-bold", className)}>
      <span className="relative flex h-7 w-7 items-center justify-center rounded-md border border-cyber-500/60 bg-cyber-500/10 shadow-glow">
        <svg viewBox="0 0 24 24" className="h-4 w-4 text-cyber-300" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M12 2L3 6v6c0 5 3.5 9.5 9 10 5.5-.5 9-5 9-10V6l-9-4z" strokeLinejoin="round" />
          <path d="M9 12l2 2 4-4" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
        <span className="absolute inset-0 animate-pulse-slow rounded-md bg-cyber-400/10" />
      </span>
      <div className={cn("flex items-baseline gap-1 leading-none", text)}>
        <span className="tracking-[0.18em] text-white">HACK</span>
        <span className="tracking-[0.18em] text-cyber-400 text-glow">THE</span>
        <span className="tracking-[0.18em] text-white">SOC</span>
      </div>
    </div>
  );
}
