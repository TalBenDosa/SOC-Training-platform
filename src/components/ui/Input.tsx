import * as React from "react";
import { cn } from "@/lib/utils";

export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  function Input({ className, ...rest }, ref) {
    return (
      <input ref={ref}
        className={cn(
          "h-10 w-full rounded-md border border-border bg-bg-elevated px-3 text-sm text-slate-100 placeholder-slate-500",
          "focus:border-cyber-500/50 focus:outline-none focus:ring-2 focus:ring-cyber-500/30",
          className,
        )}
        {...rest}
      />
    );
  },
);

export const Textarea = React.forwardRef<HTMLTextAreaElement, React.TextareaHTMLAttributes<HTMLTextAreaElement>>(
  function Textarea({ className, ...rest }, ref) {
    return (
      <textarea ref={ref}
        className={cn(
          "min-h-[96px] w-full rounded-md border border-border bg-bg-elevated px-3 py-2 text-sm text-slate-100 placeholder-slate-500",
          "focus:border-cyber-500/50 focus:outline-none focus:ring-2 focus:ring-cyber-500/30 font-mono",
          className,
        )}
        {...rest}
      />
    );
  },
);
