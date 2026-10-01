"use client";
import Link from "next/link";
import { useEffect } from "react";
import { AlertTriangle, RotateCcw } from "lucide-react";

/**
 * Shared fallback for the route error boundaries (P5-05). Before these existed,
 * any exception thrown while rendering a page replaced the WHOLE app — sidebar,
 * navigation and the "Report a problem" button included — with Next's bare
 * "Application error" screen and no way back.
 */
export function ErrorPanel({ error, reset }: { error: Error & { digest?: string }; reset?: () => void }) {
  useEffect(() => {
    // Keep the details in the console for whoever investigates; the user sees plain words.
    console.error("[page error]", error);
  }, [error]);

  return (
    <div className="mx-auto flex min-h-[60vh] max-w-lg flex-col items-center justify-center px-6 py-16 text-center">
      <AlertTriangle className="h-10 w-10 text-neon-amber" aria-hidden="true" />
      <h1 className="mt-4 text-lg font-semibold text-white">Something went wrong on this page</h1>
      <p className="mt-2 text-sm text-slate-400">
        Your progress is saved. Try again — if it keeps happening, use “Report a problem” so we can fix it.
      </p>
      {error.digest && <p className="mt-2 font-mono text-[11px] text-slate-500">Reference: {error.digest}</p>}
      <div className="mt-6 flex flex-wrap justify-center gap-3">
        {reset && (
          <button onClick={reset}
            className="inline-flex items-center gap-1.5 rounded-md border border-cyber-500/40 bg-cyber-500/10 px-4 py-2 text-sm font-semibold text-cyber-300 hover:bg-cyber-500/20 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyber-400/50">
            <RotateCcw className="h-4 w-4" aria-hidden="true" /> Try again
          </button>
        )}
        <Link href="/dashboard" className="rounded-md border border-border px-4 py-2 text-sm text-slate-300 hover:bg-white/5">Go to the dashboard</Link>
      </div>
    </div>
  );
}
