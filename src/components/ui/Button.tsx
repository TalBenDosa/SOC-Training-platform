import { cn } from "@/lib/utils";
import * as React from "react";

type Variant = "primary" | "secondary" | "ghost" | "danger" | "outline";
type Size = "sm" | "md" | "lg";

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
}

const base = "inline-flex items-center justify-center gap-2 rounded-md font-semibold tracking-wide transition focus:outline-none focus:ring-2 focus:ring-cyber-400/50 disabled:opacity-50 disabled:pointer-events-none";
const sizes: Record<Size,string> = {
  sm: "h-8 px-3 text-xs",
  md: "h-10 px-4 text-sm",
  lg: "h-12 px-5 text-base",
};
const variants: Record<Variant,string> = {
  primary:   "bg-cyber-500 text-bg hover:bg-cyber-400 shadow-glow",
  secondary: "bg-bg-elevated text-slate-100 border border-border hover:bg-bg-hover",
  ghost:     "text-slate-300 hover:bg-bg-hover",
  // red-600: white text 4.8:1 (severity-critical #ff2d55 was 3.65:1 — WCAG 1.4.3)
  danger:    "bg-red-600 text-white hover:bg-red-700 shadow-glow-red",
  outline:   "border border-cyber-500/40 text-cyber-300 hover:bg-cyber-500/10",
};

/**
 * Button styling as a class string, for elements that must LOOK like a
 * button but are semantically something else (e.g. a Next <Link>). Use this
 * instead of nesting <Button> inside <Link>, which creates nested interactive
 * elements (WCAG 4.1.2).
 */
export function buttonClasses(variant: Variant = "primary", size: Size = "md", className?: string): string {
  return cn(base, sizes[size], variants[variant], className);
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { className, variant = "primary", size = "md", children, ...rest }, ref,
) {
  return (
    <button ref={ref} className={buttonClasses(variant, size, className)} {...rest}>
      {children}
    </button>
  );
});
