"use client";
import React, { useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";
import { Play, SkipForward, Volume2, VolumeX } from "lucide-react";
import type { StoryClip } from "@/lib/rooms/experience";

/**
 * A story film between stations: full-screen, 16:9, skippable. It tries to
 * play with sound (the learner just clicked something); if the browser blocks
 * that, the poster shows a Play button instead of starting muted behind their
 * back. Ends, skips and load errors all hand control back through onDone.
 */
export function StoryPlayer({ clip, label, onDone }: { clip: StoryClip; label: string; onDone: () => void }) {
  const ref = useRef<HTMLVideoElement>(null);
  const [blocked, setBlocked] = useState(false);
  const [muted, setMuted] = useState(false);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    const v = ref.current;
    if (!v) return;
    v.play().catch(() => setBlocked(true));
  }, [clip.src]);

  // A missing or blocked file must never trap the learner in front of a black box.
  useEffect(() => {
    if (!failed) return;
    const t = window.setTimeout(onDone, 1500);
    return () => window.clearTimeout(t);
  }, [failed, onDone]);

  function start() {
    const v = ref.current;
    if (!v) return;
    setBlocked(false);
    v.play().catch(() => setBlocked(true));
  }

  return (
    <motion.div
      initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
      role="dialog" aria-modal="true" aria-label={`${label}: ${clip.title}`}
      className="absolute inset-0 z-50 flex flex-col items-center justify-center bg-black/90 px-4 backdrop-blur"
      onKeyDown={e => { if (e.key === "Escape") onDone(); }}
    >
      <div className="w-full max-w-5xl">
        <div className="mb-3 flex items-end justify-between gap-3">
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-[0.3em] text-cyber-300">{label}</p>
            <h2 className="text-xl font-extrabold text-white sm:text-2xl">{clip.title}</h2>
          </div>
          <button autoFocus onClick={onDone} className="inline-flex shrink-0 items-center gap-2 rounded-full border border-white/20 px-4 py-2 text-sm font-semibold text-slate-200 hover:border-white/50">
            Skip <SkipForward className="h-4 w-4" />
          </button>
        </div>
        <div className="relative aspect-video w-full overflow-hidden rounded-2xl border border-white/10 bg-black shadow-2xl">
          <video
            ref={ref}
            src={clip.src}
            poster={clip.poster}
            muted={muted}
            playsInline
            preload="auto"
            onEnded={onDone}
            onError={() => setFailed(true)}
            className="h-full w-full object-contain"
          />
          {blocked && !failed && (
            <button onClick={start} className="absolute inset-0 grid place-items-center bg-black/40" aria-label="Play the film">
              <span className="grid h-20 w-20 place-items-center rounded-full bg-gradient-to-br from-cyber-400 to-indigo-400 text-bg shadow-glow">
                <Play className="ml-1 h-9 w-9 fill-current" />
              </span>
            </button>
          )}
          {failed && (
            <p role="status" className="absolute inset-0 grid place-items-center text-sm text-slate-400">The film could not load. Continuing the mission…</p>
          )}
          {!blocked && !failed && (
            <button onClick={() => setMuted(m => !m)} aria-label={muted ? "Unmute" : "Mute"}
              className="absolute bottom-3 right-3 grid h-10 w-10 place-items-center rounded-full bg-black/60 text-white hover:bg-black/80">
              {muted ? <VolumeX className="h-5 w-5" /> : <Volume2 className="h-5 w-5" />}
            </button>
          )}
        </div>
      </div>
    </motion.div>
  );
}
