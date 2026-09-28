"use client";
/**
 * "Listen" — reads a piece of reading content aloud with the browser's Web
 * Speech API (feedback FB-009). No server, no audio files, no third party: the
 * OS/browser voice does the work. Hidden entirely where the API is missing.
 *
 * - Play / pause / resume / stop, plus a 0.9× / 1× / 1.25× speed control.
 * - Prefers an English voice (the app's content is English).
 * - Long text is queued as sentence-grouped chunks (Chrome stops a single long
 *   utterance after ~15 s).
 * - Stops on unmount (task/page navigation), on `pagehide`, when the text
 *   changes, and when another Listen button on the page starts.
 */
import React, { useCallback, useEffect, useId, useRef, useState } from "react";
import { Pause, Play, Square, Volume2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { toSpeechText, chunkForSpeech } from "./speechText";

const RATES = [0.9, 1, 1.25] as const;

// Only one Listen button speaks at a time (speechSynthesis is a global queue).
let activeOwner: string | null = null;

function pickEnglishVoice(voices: SpeechSynthesisVoice[]): SpeechSynthesisVoice | null {
  const en = voices.filter(v => v.lang?.toLowerCase().startsWith("en"));
  if (en.length === 0) return null;
  const score = (v: SpeechSynthesisVoice) =>
    (v.lang.toLowerCase() === "en-us" ? 4 : v.lang.toLowerCase().startsWith("en-gb") ? 3 : 1) +
    (/natural|neural|google|online/i.test(v.name) ? 2 : 0) +
    (v.localService ? 0 : 0.5);
  return en.slice().sort((a, b) => score(b) - score(a))[0] ?? null;
}

type PlayState = "idle" | "playing" | "paused";

export function ListenButton({ text, className, label = "Listen" }: { text: string; className?: string; label?: string }) {
  const ownerId = useId();
  const [supported, setSupported] = useState(false);
  const [state, setState] = useState<PlayState>("idle");
  const [rate, setRate] = useState<number>(1);

  const chunksRef = useRef<string[]>([]);
  const idxRef = useRef(0);
  const tokenRef = useRef(0);          // bumps invalidate stale utterance callbacks
  const rateRef = useRef(1);
  const voiceRef = useRef<SpeechSynthesisVoice | null>(null);
  const stateRef = useRef<PlayState>("idle");
  const setPlayState = (s: PlayState) => { stateRef.current = s; setState(s); };

  const synth = () => (typeof window !== "undefined" ? window.speechSynthesis : undefined);

  const speakFrom = useCallback((i: number, token: number) => {
    const s = synth();
    if (!s || token !== tokenRef.current || activeOwner !== ownerId) return;
    if (i >= chunksRef.current.length) {
      activeOwner = null;
      idxRef.current = 0;
      setPlayState("idle");
      return;
    }
    idxRef.current = i;
    const u = new SpeechSynthesisUtterance(chunksRef.current[i]);
    u.lang = voiceRef.current?.lang ?? "en-US";
    if (voiceRef.current) u.voice = voiceRef.current;
    u.rate = rateRef.current;
    u.onend = () => {
      if (token !== tokenRef.current) return;
      if (activeOwner !== ownerId) { setPlayState("idle"); return; }
      speakFrom(i + 1, token);
    };
    u.onerror = (e) => {
      if (token !== tokenRef.current) return;
      if (e.error === "interrupted" || e.error === "canceled") return;
      activeOwner = null;
      setPlayState("idle");
    };
    s.speak(u);
  }, [ownerId]);

  const stop = useCallback(() => {
    tokenRef.current++;
    idxRef.current = 0;
    if (activeOwner === ownerId) {
      activeOwner = null;
      synth()?.cancel();
    }
    setPlayState("idle");
  }, [ownerId]);

  // Feature detection + voice loading + teardown.
  useEffect(() => {
    const s = synth();
    const ok = !!s && typeof window.SpeechSynthesisUtterance === "function";
    setSupported(ok);
    if (!ok || !s) return;
    const pick = () => { voiceRef.current = pickEnglishVoice(s.getVoices()); };
    pick();
    s.addEventListener?.("voiceschanged", pick);
    const onHide = () => stop();
    window.addEventListener("pagehide", onHide);
    return () => {
      s.removeEventListener?.("voiceschanged", pick);
      window.removeEventListener("pagehide", onHide);
      stop();
    };
  }, [stop]);

  // New content (e.g. next lesson page) → stop reading the old one.
  useEffect(() => {
    if (stateRef.current !== "idle") stop();
  }, [text, stop]);

  function play() {
    const s = synth();
    if (!s) return;
    if (stateRef.current === "paused" && activeOwner === ownerId) {
      s.resume();
      setPlayState("playing");
      return;
    }
    s.cancel();
    activeOwner = ownerId;
    chunksRef.current = chunkForSpeech(toSpeechText(text));
    if (chunksRef.current.length === 0) { activeOwner = null; return; }
    const token = ++tokenRef.current;
    setPlayState("playing");
    speakFrom(0, token);
  }

  function pause() {
    synth()?.pause();
    setPlayState("paused");
  }

  function changeRate(r: number) {
    rateRef.current = r;
    setRate(r);
    // Apply immediately: restart the current chunk at the new speed.
    if (stateRef.current === "playing" && activeOwner === ownerId) {
      const s = synth();
      const token = ++tokenRef.current;
      s?.cancel();
      speakFrom(idxRef.current, token);
    }
  }

  if (!supported || !text.trim()) return null;

  const playing = state === "playing";
  return (
    <div
      role="group"
      aria-label="Listen to this reading"
      className={cn("inline-flex flex-wrap items-center gap-1.5 rounded-lg border border-border/60 bg-bg-elevated/40 p-1", className)}
    >
      <button
        type="button"
        onClick={playing ? pause : play}
        aria-pressed={playing}
        aria-label={playing ? "Pause reading aloud" : state === "paused" ? "Resume reading aloud" : "Read this section aloud"}
        className={cn(
          "inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-semibold transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-cyber-500/50",
          playing ? "bg-cyber-500/15 text-cyber-200" : "text-slate-300 hover:bg-bg-hover hover:text-white",
        )}
      >
        {playing ? <Pause className="h-3.5 w-3.5" aria-hidden /> : state === "paused" ? <Play className="h-3.5 w-3.5" aria-hidden /> : <Volume2 className="h-3.5 w-3.5" aria-hidden />}
        {playing ? "Pause" : state === "paused" ? "Resume" : label}
      </button>
      {state !== "idle" && (
        <button
          type="button"
          onClick={stop}
          aria-label="Stop reading aloud"
          className="inline-flex items-center rounded-md px-2 py-1 text-xs text-slate-400 transition-colors hover:bg-bg-hover hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-cyber-500/50"
        >
          <Square className="h-3 w-3" aria-hidden />
        </button>
      )}
      <span className="mx-0.5 h-4 w-px bg-border/60" aria-hidden />
      <div role="group" aria-label="Reading speed" className="inline-flex items-center gap-0.5">
        {RATES.map(r => (
          <button
            key={r}
            type="button"
            onClick={() => changeRate(r)}
            aria-pressed={rate === r}
            aria-label={`Speed ${r}×`}
            className={cn(
              "rounded px-1.5 py-0.5 font-mono text-[10px] transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-cyber-500/50",
              rate === r ? "bg-cyber-500/15 text-cyber-200" : "text-slate-500 hover:text-slate-200",
            )}
          >
            {r}×
          </button>
        ))}
      </div>
      <span className="sr-only" aria-live="polite">
        {state === "playing" ? "Reading aloud" : state === "paused" ? "Paused" : ""}
      </span>
    </div>
  );
}

export default ListenButton;
