"use client";
import React, { useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";
import { Loader2, Play, SkipForward, Volume2, VolumeX } from "lucide-react";
import type { StoryClip } from "@/lib/rooms/experience";

/** A film that stops making progress for this long is treated as unplayable, and control
 *  hands back so the learner is never trapped waiting on a frozen frame (feedback 2026-11-14:
 *  room films were getting stuck). The Skip button is always there for anyone who waits less. */
const STALL_CONTINUE_MS = 15_000;

/**
 * A story film between stations: full-screen, 16:9, skippable. It tries to
 * play with sound (the learner just clicked something); if the browser blocks
 * that, the poster shows a Play button instead of starting muted behind their
 * back. Ends, skips and load errors all hand control back through onDone.
 *
 * The films stream from storage, so a slow link can STALL mid-play: the frame
 * freezes without an error or an "ended" event, and onDone never fires. A stall
 * shows a Loading spinner (so a frozen frame reads as loading, not broken), nudges
 * playback to resume, and if it cannot recover within STALL_CONTINUE_MS the mission
 * continues on its own.
 */
export function StoryPlayer({ clip, label, onDone }: { clip: StoryClip; label: string; onDone: () => void }) {
  const ref = useRef<HTMLVideoElement>(null);
  const [blocked, setBlocked] = useState(false);
  const [muted, setMuted] = useState(false);
  const [failed, setFailed] = useState(false);
  const [buffering, setBuffering] = useState(false);
  // Watchdog: armed while the film is stalled, cleared the moment it makes progress.
  const stallTimer = useRef<number | null>(null);
  const clearStall = () => { if (stallTimer.current !== null) { window.clearTimeout(stallTimer.current); stallTimer.current = null; } };

  useEffect(() => {
    const v = ref.current;
    if (!v) return;
    setBuffering(false);
    clearStall();
    v.play().catch(() => setBlocked(true));
    return clearStall;
  }, [clip.src]);

  // A missing or blocked file must never trap the learner in front of a black box.
  useEffect(() => {
    if (!failed) return;
    const t = window.setTimeout(onDone, 1500);
    return () => window.clearTimeout(t);
  }, [failed, onDone]);

  // Autoplay was blocked: the film is paused waiting for the learner to press Play, which is not a
  // stall, so drop any spinner and disarm the watchdog (it must not auto-continue past the Play button).
  useEffect(() => {
    if (blocked) { setBuffering(false); clearStall(); }
  }, [blocked]);

  function start() {
    const v = ref.current;
    if (!v) return;
    setBlocked(false);
    v.play().catch(() => setBlocked(true));
  }

  // The film stopped feeding frames: show it is loading, try to resume, and start the watchdog.
  // A paused video (autoplay blocked, waiting for Play) is not a stall and must not arm the watchdog.
  function onStall() {
    const v = ref.current;
    if (!v || v.paused || blocked || failed) return;
    setBuffering(true);
    v.play().catch(() => {});
    if (stallTimer.current === null) stallTimer.current = window.setTimeout(onDone, STALL_CONTINUE_MS);
  }
  // Progress again: clear the spinner and disarm the watchdog.
  function onProgress() {
    if (buffering) setBuffering(false);
    clearStall();
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
            onWaiting={onStall}
            onStalled={onStall}
            onPlaying={onProgress}
            onTimeUpdate={onProgress}
            className="h-full w-full object-contain"
          />
          {buffering && !blocked && !failed && (
            <div role="status" aria-label="Loading the film" className="pointer-events-none absolute inset-0 grid place-items-center bg-black/30">
              <div className="flex flex-col items-center gap-2 text-slate-200">
                <Loader2 className="h-9 w-9 animate-spin text-cyber-300" aria-hidden="true" />
                <span className="text-xs font-medium">Loading… you can Skip if it does not start</span>
              </div>
            </div>
          )}
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
