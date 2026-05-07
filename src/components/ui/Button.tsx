import { cn } from "@/lib/utils";
import * as React from "react";

type Variant = "primary" | "secondary" | "ghost" | "danger" | "outline";
type Size = "sm" | "md" | "lg";

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { className, variant = "primary", size = "md", children, ...rest }, ref,
) {
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
    danger:    "bg-severity-critical text-white hover:bg-severity-critical/90 shadow-glow-red",
    outline:   "border border-cyber-500/40 text-cyber-300 hover:bg-cyber-500/10",
  };
  return (
    <button ref={ref} className={cn(base, sizes[size], variants[variant], className)} {...rest}>
      {children}
    </button>
  );
});
