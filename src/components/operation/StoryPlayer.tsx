"use client";
import React, { useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";
import { Loader2, Pause, Play, RotateCcw, SkipForward, Volume2, VolumeX } from "lucide-react";
import type { StoryClip } from "@/lib/rooms/experience";
import { pauseWorlds } from "./worldPause";
import { sendFilmEvent, type FilmEventKind } from "@/lib/media/filmTelemetry";

/** A film that has been waiting for data this long offers the learner a choice: try again or move on. */
export const SLOW_STALL_MS = 10_000;
/** Stall events sent per film at most (a flapping connection must not flood the log). */
const MAX_STALL_EVENTS = 5;

export function formatClock(s: number): string {
  if (!Number.isFinite(s) || s < 0) return "0:00";
  const m = Math.floor(s / 60), r = Math.floor(s % 60);
  return `${m}:${String(r).padStart(2, "0")}`;
}

/**
 * A story film between stations: full-screen, 16:9, skippable, with the controls a learner expects
 * (learner feedback 2026-11-21): play/pause, a seek bar, back 10 seconds, mute. Space pauses, the
 * arrow keys jump 5 seconds. It tries to play with sound (the learner just clicked something); if the
 * browser blocks that, the poster shows a Play button instead of starting muted behind their back.
 * Ends and skips hand control back through onDone; a file that cannot load continues on its own.
 *
 * While it is open the 3D room world behind it stops rendering (worldPause.ts) so the video decoder
 * has the machine to itself. A film that stalls shows a spinner, and after SLOW_STALL_MS offers
 * "Try again" (reloads from the same second) or "Continue the mission"; it never skips on its own,
 * so a learner on a slow line does not lose the story. Stalls are reported (filmTelemetry.ts).
 */
export function StoryPlayer({ clip, label, onDone, roomId, clipKey }: {
  clip: StoryClip; label: string; onDone: () => void; roomId?: string; clipKey?: string;
}) {
  const ref = useRef<HTMLVideoElement>(null);
  const [blocked, setBlocked] = useState(false);
  const [muted, setMuted] = useState(false);
  const [failed, setFailed] = useState(false);
  const [buffering, setBuffering] = useState(false);
  const [slow, setSlow] = useState(false);
  const [playing, setPlaying] = useState(false);
  const [time, setTime] = useState(0);
  const [duration, setDuration] = useState(0);

  const slowTimer = useRef<number | null>(null);
  const stallStart = useRef<number | null>(null);
  const stallEvents = useRef(0);
  const started = useRef(false);
  const finished = useRef(false);
  const resumeAt = useRef<number | null>(null);

  const track = (kind: FilmEventKind, extra: { waitMs?: number } = {}) => {
    const v = ref.current;
    sendFilmEvent({ kind, roomId, clipKey, src: clip.src, positionS: v?.currentTime, durationS: v?.duration, ...extra });
  };
  const clearSlow = () => { if (slowTimer.current !== null) { window.clearTimeout(slowTimer.current); slowTimer.current = null; } };

  // The room world behind the film pauses for as long as the film is open.
  useEffect(() => pauseWorlds(), []);

  useEffect(() => {
    const v = ref.current;
    if (!v) return;
    setBuffering(false); setSlow(false); clearSlow();
    v.play().catch(() => setBlocked(true));
    return clearSlow;
  }, [clip.src]);

  // A missing or blocked file must never trap the learner in front of a black box.
  useEffect(() => {
    if (!failed) return;
    const t = window.setTimeout(() => leave("error"), 1500);
    return () => window.clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [failed]);

  // Autoplay was blocked: the film waits for the learner's Play, which is not a stall.
  useEffect(() => {
    if (blocked) { setBuffering(false); setSlow(false); clearSlow(); }
  }, [blocked]);

  /** Hand control back once, recording how the film ended. */
  function leave(kind: "ended" | "skipped" | "continue" | "error") {
    if (finished.current) return;
    finished.current = true;
    clearSlow();
    track(kind);
    onDone();
  }

  function play() {
    const v = ref.current;
    if (!v) return;
    setBlocked(false);
    v.play().catch(() => setBlocked(true));
  }
  function togglePlay() {
    const v = ref.current;
    if (!v || failed) return;
    if (v.paused || v.ended) play(); else v.pause();
  }
  function seekTo(s: number) {
    const v = ref.current;
    if (!v || !Number.isFinite(s)) return;
    const end = Number.isFinite(v.duration) ? v.duration : s;
    v.currentTime = Math.min(Math.max(0, s), Math.max(0, end - 0.05));
    setTime(v.currentTime);
  }

  // The film stopped feeding frames: show it is loading, nudge it, and after a while offer a choice.
  // A paused film (the learner paused, or autoplay waits for Play) is not a stall.
  function onStall(e: React.SyntheticEvent<HTMLVideoElement>) {
    const v = ref.current;
    if (!v || v.paused || blocked || failed) return;
    setBuffering(true);
    if (e.type === "waiting" && stallStart.current === null) {
      stallStart.current = Date.now();
      if (stallEvents.current < MAX_STALL_EVENTS) { stallEvents.current++; track("stall"); }
    }
    v.play().catch(() => {});
    if (slowTimer.current === null) slowTimer.current = window.setTimeout(() => setSlow(true), SLOW_STALL_MS);
  }
  // Frames are flowing: clear the spinner and the choice, and report how long the wait was.
  function onProgress() {
    const v = ref.current;
    if (v) setTime(v.currentTime);
    if (buffering) setBuffering(false);
    if (slow) setSlow(false);
    clearSlow();
    if (stallStart.current !== null) {
      track("recovered", { waitMs: Date.now() - stallStart.current });
      stallStart.current = null;
    }
  }
  function retry() {
    const v = ref.current;
    if (!v) return;
    track("retry");
    resumeAt.current = v.currentTime;
    setSlow(false); clearSlow();
    if (stallStart.current === null) stallStart.current = Date.now();
    v.load();
    v.play().catch(() => setBlocked(true));
  }

  function onKey(e: React.KeyboardEvent) {
    if (e.key === "Escape") { leave("skipped"); return; }
    const t = e.target as HTMLElement;
    if (t.tagName === "INPUT" || t.tagName === "BUTTON") return; // the slider and buttons handle their own keys
    const v = ref.current;
    if (!v) return;
    if (e.key === " " || e.key === "k") { e.preventDefault(); togglePlay(); }
    else if (e.key === "ArrowLeft") { e.preventDefault(); seekTo(v.currentTime - 5); }
    else if (e.key === "ArrowRight") { e.preventDefault(); seekTo(v.currentTime + 5); }
  }

  const controlsOn = !blocked && !failed;
  return (
    <motion.div
      initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
      role="dialog" aria-modal="true" aria-label={`${label}: ${clip.title}`}
      // Solid, no backdrop blur: a blur over the WebGL canvas costs every frame of the film, and on a
      // phone the briefing text behind a translucent backdrop competes with the film. Fixed, not
      // absolute: on a phone the room's own layer scrolls (the briefing is taller than the screen),
      // and an absolute film rode up with it, cutting off its top and uncovering the buttons below.
      className="fixed inset-0 z-50 flex flex-col items-center justify-center bg-black px-4"
      onKeyDown={onKey}
    >
      <div className="w-full max-w-5xl">
        <div className="mb-3 flex items-end justify-between gap-3">
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-[0.3em] text-cyber-300">{label}</p>
            <h2 className="text-xl font-extrabold text-white sm:text-2xl">{clip.title}</h2>
          </div>
          <button autoFocus onClick={() => leave("skipped")} className="inline-flex shrink-0 items-center gap-2 rounded-full border border-white/20 px-4 py-2 text-sm font-semibold text-slate-200 hover:border-white/50">
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
            onClick={togglePlay}
            onEnded={() => leave("ended")}
            onError={() => setFailed(true)}
            onWaiting={onStall}
            onStalled={onStall}
            onPlay={() => setPlaying(true)}
            onPause={() => { setPlaying(false); setBuffering(false); setSlow(false); clearSlow(); }}
            onPlaying={() => {
              setPlaying(true);
              if (!started.current) { started.current = true; track("start"); }
              onProgress();
            }}
            onTimeUpdate={onProgress}
            onLoadedMetadata={() => {
              const v = ref.current;
              if (!v) return;
              setDuration(v.duration);
              if (resumeAt.current !== null) { v.currentTime = resumeAt.current; resumeAt.current = null; }
            }}
            onDurationChange={() => { const v = ref.current; if (v) setDuration(v.duration); }}
            className="h-full w-full cursor-pointer object-contain"
          />
          {buffering && !slow && controlsOn && (
            <div role="status" aria-label="Loading the film" className="pointer-events-none absolute inset-0 grid place-items-center bg-black/30">
              <div className="flex flex-col items-center gap-2 text-slate-200">
                <Loader2 className="h-9 w-9 animate-spin text-cyber-300" aria-hidden="true" />
                <span className="text-xs font-medium">Loading the film…</span>
              </div>
            </div>
          )}
          {slow && controlsOn && (
            <div role="alertdialog" aria-label="The film is loading slowly" className="absolute inset-0 grid place-items-center bg-black/70 px-6 text-center">
              <div className="max-w-sm">
                <p className="text-base font-bold text-white">The film is loading slowly</p>
                <p className="mt-1 text-sm text-slate-300">Your connection is not keeping up. Try loading it again, or carry on: you can watch it later from the mission board.</p>
                <div className="mt-4 flex flex-wrap justify-center gap-2">
                  <button onClick={retry} className="inline-flex items-center gap-2 rounded-xl bg-cyber-400 px-4 py-2 text-sm font-bold text-bg hover:bg-cyber-300">
                    <RotateCcw className="h-4 w-4" /> Try again
                  </button>
                  <button onClick={() => leave("continue")} className="inline-flex items-center gap-2 rounded-xl border border-white/25 px-4 py-2 text-sm font-semibold text-slate-100 hover:border-white/60">
                    Continue the mission <SkipForward className="h-4 w-4" />
                  </button>
                </div>
              </div>
            </div>
          )}
          {blocked && !failed && (
            <button onClick={play} className="absolute inset-0 grid place-items-center bg-black/40" aria-label="Play the film">
              <span className="grid h-20 w-20 place-items-center rounded-full bg-gradient-to-br from-cyber-400 to-indigo-400 text-bg shadow-glow">
                <Play className="ml-1 h-9 w-9 fill-current" />
              </span>
            </button>
          )}
          {failed && (
            <p role="status" className="absolute inset-0 grid place-items-center text-sm text-slate-400">The film could not load. Continuing the mission…</p>
          )}
        </div>
        {controlsOn && (
          <div className="mt-3 flex items-center gap-2 text-slate-200 sm:gap-3">
            <button onClick={togglePlay} aria-label={playing ? "Pause" : "Play"}
              className="grid h-10 w-10 shrink-0 place-items-center rounded-full bg-white/10 hover:bg-white/20">
              {playing ? <Pause className="h-5 w-5 fill-current" /> : <Play className="ml-0.5 h-5 w-5 fill-current" />}
            </button>
            <button onClick={() => seekTo((ref.current?.currentTime ?? 0) - 10)} aria-label="Back 10 seconds"
              className="inline-flex h-10 shrink-0 items-center gap-1 rounded-full bg-white/10 px-3 text-xs font-semibold hover:bg-white/20">
              <RotateCcw className="h-4 w-4" /> 10s
            </button>
            <input
              type="range" min={0} max={duration > 0 ? duration : 0} step={0.1} value={Math.min(time, duration || 0)}
              onChange={e => seekTo(Number(e.target.value))}
              aria-label="Seek" aria-valuetext={`${formatClock(time)} of ${formatClock(duration)}`}
              disabled={!(duration > 0)}
              className="h-2 min-w-0 flex-1 cursor-pointer accent-cyber-400"
            />
            <span className="shrink-0 font-mono text-xs tabular-nums text-slate-300">{formatClock(time)} / {formatClock(duration)}</span>
            <button onClick={() => setMuted(m => !m)} aria-label={muted ? "Unmute" : "Mute"}
              className="grid h-10 w-10 shrink-0 place-items-center rounded-full bg-white/10 hover:bg-white/20">
              {muted ? <VolumeX className="h-5 w-5" /> : <Volume2 className="h-5 w-5" />}
            </button>
          </div>
        )}
      </div>
    </motion.div>
  );
}
