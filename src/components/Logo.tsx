"use client";
import { cn } from "@/lib/utils";
import { useBrand } from "@/lib/brand/BrandContext";

export function Logo({ className, size = "md" }: { className?: string; size?: "sm" | "md" | "lg" }) {
  const brand = useBrand();
  const text = size === "lg" ? "text-2xl" : size === "sm" ? "text-sm" : "text-lg";

  // White label (src/lib/brand): the organization's own logo and name, never the platform's.
  if (brand.whiteLabel) {
    const img = size === "lg" ? "h-14" : size === "sm" ? "h-8" : "h-11";
    return (
      <div className={cn("flex min-w-0 items-center gap-2.5 font-bold", className)}>
        {brand.logoSrc && (
          // eslint-disable-next-line @next/next/no-img-element -- same-origin logo route, any aspect ratio
          <img src={brand.logoSrc} alt={brand.logoHasName ? brand.productName : ""} className={cn(img, "w-auto max-w-[180px] object-contain")} />
        )}
        {/* Long product names wrap to two lines instead of being cut off in the sidebar. */}
        {!brand.logoHasName && <span className={cn("line-clamp-2 min-w-0 leading-tight text-white", size === "lg" ? "text-2xl" : size === "sm" ? "text-sm" : "text-[15px]")}>{brand.productName}</span>}
      </div>
    );
  }

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
