"use client";
import { cn } from "@/lib/utils";
import { useBrand } from "@/lib/brand/BrandContext";

export function Logo({ className, size = "md", stacked = false }: { className?: string; size?: "sm" | "md" | "lg"; stacked?: boolean }) {
  const brand = useBrand();
  const text = size === "lg" ? "text-2xl" : size === "sm" ? "text-sm" : "text-lg";

  // White label (src/lib/brand): the organization's own logo and name, never the platform's.
  if (brand.whiteLabel && stacked) {
    // Centered above a form (sign-in pages): a large mark with the name under it.
    return (
      <div className={cn("flex flex-col items-center gap-3 text-center", className)}>
        {brand.logoSrc && (
          // eslint-disable-next-line @next/next/no-img-element -- same-origin logo route, any aspect ratio
          <img src={brand.logoSrc} alt={brand.logoHasName ? brand.productName : ""} className="h-52 w-auto max-w-[460px] object-contain drop-shadow-[0_0_36px_rgb(var(--cyber-400)/0.22)] sm:h-64" />
        )}
        {!brand.logoHasName && <span className="text-3xl font-bold leading-tight text-white sm:text-4xl">{brand.productName}</span>}
      </div>
    );
  }

  if (brand.whiteLabel) {
    // Big enough to read the organization's mark at a glance (sidebar, sign-in, drawer).
    // A logo that already carries the name (a wordmark / lockup) fills the whole header slot;
    // a mark alone sits next to the name.
    // Sized to the navigation rail, like the platform lockup (mark + name on one line): a mark
    // sits at 40 px beside the name; a logo that already carries the name stays at 48 px.
    const img = brand.logoHasName
      ? (size === "lg" ? "h-20" : size === "sm" ? "h-9" : "h-12")
      : (size === "lg" ? "h-16" : size === "sm" ? "h-9" : "h-12");
    return (
      <div className={cn("flex min-w-0 items-center gap-3 font-bold", className)}>
        {brand.logoSrc && (
          // eslint-disable-next-line @next/next/no-img-element -- same-origin logo route, any aspect ratio
          <img src={brand.logoSrc} alt={brand.logoHasName ? brand.productName : ""} className={cn(img, "w-auto shrink-0 object-contain", brand.logoHasName ? "max-w-[140px]" : "max-w-[120px]")} />
        )}
        {/* Long product names wrap to two lines instead of being cut off in the sidebar. */}
        {!brand.logoHasName && <span className={cn("line-clamp-2 min-w-0 leading-tight text-white", size === "lg" ? "text-3xl" : size === "sm" ? "text-base" : "text-[22px] tracking-wide")}>{brand.productName}</span>}
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
