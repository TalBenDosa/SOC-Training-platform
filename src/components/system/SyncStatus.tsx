"use client";
/**
 * Sync-failure banner.
 *
 * Shows only when a write actually failed — silent the rest of the time, which
 * is almost always. Two states, matching the two failure classes in
 * syncState.ts: writes that will replay themselves on reconnect, and writes
 * that need the student to say "yes, try again" because replaying them blindly
 * could duplicate a row.
 */
import { useEffect, useState } from "react";
import { CloudOff, RefreshCw, Check } from "lucide-react";
import { SYNC_STATE_EVENT, getSyncState, requestSyncRetry, type SyncState } from "@/lib/storage/syncState";

export function SyncStatus() {
  const [state, setState] = useState<SyncState>({ retrying: 0, needsRetry: 0 });
  const [justRetried, setJustRetried] = useState(false);

  useEffect(() => {
    setState(getSyncState());
    const onState = (e: Event) => {
      const next = (e as CustomEvent<SyncState>).detail;
      setState(next);
      if (next.retrying === 0 && next.needsRetry === 0) setJustRetried(false);
    };
    window.addEventListener(SYNC_STATE_EVENT, onState);
    return () => window.removeEventListener(SYNC_STATE_EVENT, onState);
  }, []);

  const total = state.retrying + state.needsRetry;
  if (total === 0) return null;

  return (
    <div
      role="status" aria-live="polite"
      className="fixed bottom-4 left-1/2 z-[60] w-[min(92vw,26rem)] -translate-x-1/2 rounded-xl border border-neon-amber/40 bg-[#1a1408] px-4 py-3 shadow-2xl"
    >
      <div className="flex items-start gap-3">
        <CloudOff className="mt-0.5 h-4 w-4 shrink-0 text-neon-amber" />
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-neon-amber">Some progress hasn&apos;t saved</p>
          <p className="mt-0.5 text-[11px] leading-relaxed text-slate-300">
            {state.needsRetry > 0
              ? "Check your connection. Your work is safe on this device — press retry once you're back online."
              : "We'll retry automatically as soon as you're back online."}
          </p>

          {state.needsRetry > 0 && (
            <button
              onClick={() => { requestSyncRetry(); setJustRetried(true); }}
              className="mt-2 inline-flex items-center gap-1.5 rounded-lg border border-neon-amber/40 bg-neon-amber/10 px-2.5 py-1 text-[11px] font-bold text-neon-amber transition hover:bg-neon-amber/20"
            >
              {justRetried ? <><Check className="h-3 w-3" /> Retrying…</> : <><RefreshCw className="h-3 w-3" /> Retry now</>}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
