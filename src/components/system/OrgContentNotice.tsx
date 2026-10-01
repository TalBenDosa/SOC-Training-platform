"use client";
import { useEffect, useState } from "react";
import { RefreshCw, X } from "lucide-react";
import { ORG_CONTENT_ERROR_EVENT } from "@/lib/content/publicContent";

/**
 * Says so when the college's own content couldn't be loaded (QA phase 7, E-11) —
 * it used to just be missing from the page. Hidden the rest of the time.
 */
export function OrgContentNotice() {
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    const on = () => setFailed(true);
    window.addEventListener(ORG_CONTENT_ERROR_EVENT, on);
    return () => window.removeEventListener(ORG_CONTENT_ERROR_EVENT, on);
  }, []);
  if (!failed) return null;
  return (
    <div role="status" aria-live="polite"
      className="fixed bottom-4 right-4 z-[60] flex w-[min(92vw,24rem)] items-start gap-2 rounded-xl border border-neon-amber/40 bg-[#1a1408] px-4 py-3 shadow-2xl">
      <div className="min-w-0 flex-1">
        <p className="text-sm font-semibold text-neon-amber">Couldn&apos;t load your college&apos;s content</p>
        <p className="mt-0.5 text-[11px] leading-relaxed text-slate-300">Rooms, scenarios or lessons your college published may be missing from this page.</p>
        <button onClick={() => window.location.reload()} className="mt-2 inline-flex items-center gap-1.5 rounded-lg border border-neon-amber/40 bg-neon-amber/10 px-2.5 py-1 text-[11px] font-bold text-neon-amber hover:bg-neon-amber/20">
          <RefreshCw className="h-3 w-3" /> Reload
        </button>
      </div>
      <button onClick={() => setFailed(false)} aria-label="Dismiss" className="rounded p-0.5 text-slate-400 hover:text-white"><X className="h-3.5 w-3.5" /></button>
    </div>
  );
}
