"use client";
import React, { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Volume2, VolumeX } from "lucide-react";

/**
 * The moment a learner finishes a room: confetti cannons from both bottom corners,
 * a rain from the top, and a short fanfare. A full-screen canvas that ignores the
 * pointer, so everything under it stays clickable. With reduced motion there is no
 * confetti and no movement; the screen itself still says what was achieved.
 */
const COLOURS = ["#22d3ee", "#34d399", "#fbbf24", "#f472b6", "#a78bfa", "#fb7185", "#ffffff"];
const SOUND_KEY = "celebration_sound";

type Bit = { x: number; y: number; vx: number; vy: number; rot: number; spin: number; w: number; h: number; c: string; life: number; round: boolean };

function reducedMotion() {
  return typeof window !== "undefined" && !!window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
}

function fanfare() {
  try {
    const Ctx = window.AudioContext ?? (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
    if (!Ctx) return;
    const ctx = new Ctx();
    // C, E, G, then a held high C: a short, rising "you did it".
    [[523.25, 0, 0.14], [659.25, 0.13, 0.14], [783.99, 0.26, 0.14], [1046.5, 0.39, 0.6]].forEach(([f, at, len]) => {
      const o = ctx.createOscillator(), g = ctx.createGain();
      o.type = "triangle"; o.frequency.value = f;
      const t = ctx.currentTime + at;
      g.gain.setValueAtTime(0.0001, t);
      g.gain.exponentialRampToValueAtTime(0.09, t + 0.02);
      g.gain.exponentialRampToValueAtTime(0.0001, t + len);
      o.connect(g).connect(ctx.destination);
      o.start(t); o.stop(t + len + 0.02);
    });
    setTimeout(() => { void ctx.close().catch(() => {}); }, 1600);
  } catch { /* no audio on this device */ }
}

export function Celebration({ burstMs = 4200 }: { burstMs?: number }) {
  const ref = useRef<HTMLCanvasElement>(null);
  const [sound, setSound] = useState(true);

  useEffect(() => {
    let on = true;
    try { on = localStorage.getItem(SOUND_KEY) !== "off"; } catch { /* storage blocked */ }
    setSound(on);
    if (on) fanfare();
  }, []);

  useEffect(() => {
    const canvas = ref.current;
    const ctx = canvas?.getContext?.("2d");
    if (!canvas || !ctx || reducedMotion()) return;
    const size = () => { canvas.width = window.innerWidth; canvas.height = window.innerHeight; };
    size();
    window.addEventListener("resize", size);

    const bits: Bit[] = [];
    const add = (x: number, y: number, angle: number, power: number, n: number) => {
      for (let i = 0; i < n; i++) {
        const a = angle + (Math.random() - 0.5) * 0.9, v = power * (0.45 + Math.random() * 0.75);
        bits.push({
          x, y, vx: Math.cos(a) * v, vy: Math.sin(a) * v, rot: Math.random() * 6.28, spin: (Math.random() - 0.5) * 0.35,
          w: 5 + Math.random() * 7, h: 8 + Math.random() * 9, c: COLOURS[i % COLOURS.length], life: 1, round: Math.random() < 0.25,
        });
      }
    };
    const volley = () => {
      const W = canvas.width, H = canvas.height, power = Math.max(15, Math.min(25, H / 34));
      add(0, H, -Math.PI / 3, power, 90);
      add(W, H, -(2 * Math.PI) / 3, power, 90);
    };
    const start = performance.now();
    volley();
    const second = setTimeout(volley, 700);
    const third = setTimeout(volley, 1500);

    let raf = 0;
    const tick = (now: number) => {
      const elapsed = now - start;
      if (elapsed < burstMs) for (let i = 0; i < 3; i++) add(Math.random() * canvas.width, -12, Math.PI / 2, 3, 1);
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      for (let i = bits.length - 1; i >= 0; i--) {
        const b = bits[i];
        b.vy += 0.26; b.vx *= 0.988; b.vy *= 0.988;
        b.x += b.vx + Math.sin(b.rot) * 0.7; b.y += b.vy; b.rot += b.spin;
        if (elapsed > burstMs) b.life -= 0.012;
        if (b.y > canvas.height + 24 || b.life <= 0) { bits.splice(i, 1); continue; }
        ctx.save();
        ctx.globalAlpha = Math.max(0, b.life);
        ctx.fillStyle = b.c;
        ctx.translate(b.x, b.y);
        ctx.rotate(b.rot);
        if (b.round) { ctx.beginPath(); ctx.arc(0, 0, b.w / 2, 0, 6.28); ctx.fill(); }
        else { ctx.scale(1, Math.abs(Math.cos(b.rot * 1.6)) * 0.85 + 0.15); ctx.fillRect(-b.w / 2, -b.h / 2, b.w, b.h); }
        ctx.restore();
      }
      if (bits.length > 0 || elapsed < burstMs) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => { cancelAnimationFrame(raf); clearTimeout(second); clearTimeout(third); window.removeEventListener("resize", size); };
  }, [burstMs]);

  const toggle = () => {
    const next = !sound;
    setSound(next);
    try { localStorage.setItem(SOUND_KEY, next ? "on" : "off"); } catch { /* storage blocked */ }
    if (next) fanfare();
  };

  // Portalled to the body: a transformed ancestor (the completion overlay animates in) would
  // otherwise make "fixed" mean "inside that card" and clip the confetti to it.
  return createPortal(
    <>
      <canvas ref={ref} aria-hidden className="pointer-events-none fixed inset-0 z-[70]" />
      <button onClick={toggle} aria-label={sound ? "Turn celebration sound off" : "Turn celebration sound on"}
        className="fixed right-4 top-4 z-[71] rounded-full border border-white/15 bg-black/40 p-2 text-slate-300 hover:text-white">
        {sound ? <Volume2 className="h-4 w-4" /> : <VolumeX className="h-4 w-4" />}
      </button>
    </>,
    document.body,
  );
}

/** Celebrates a room once: a finished room reopens on its completion screen, and a
 *  revisit is not a new win. Stored per browser, like the sound choice. */
export function RoomCelebration({ roomId }: { roomId: string }) {
  const [go, setGo] = useState(false);
  useEffect(() => {
    const key = `room_celebrated:${roomId}`;
    try {
      if (localStorage.getItem(key)) return;
      localStorage.setItem(key, "1");
    } catch { /* storage blocked: celebrate anyway */ }
    setGo(true);
  }, [roomId]);
  return go ? <Celebration /> : null;
}

/** Counts up to a number once, so the reward lands instead of just appearing. */
export function CountUp({ to, ms = 1400, prefix = "", suffix = "" }: { to: number; ms?: number; prefix?: string; suffix?: string }) {
  const [n, setN] = useState(0);
  useEffect(() => {
    if (reducedMotion()) { setN(to); return; }
    const start = performance.now();
    let raf = 0;
    const tick = (now: number) => {
      const p = Math.min(1, (now - start) / ms);
      setN(Math.round(to * (1 - Math.pow(1 - p, 3))));
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [to, ms]);
  return <>{prefix}{n}{suffix}</>;
}

/** A title earned for the run: the score is the room's real score. */
export function roomRank(scorePct: number): { title: string; line: string } {
  if (scorePct >= 95) return { title: "Flawless analyst", line: "Nothing got past you. That is senior-level work." };
  if (scorePct >= 85) return { title: "Sharp analyst", line: "You read the evidence and made the right calls." };
  if (scorePct >= 75) return { title: "Solid analyst", line: "The job is done, and you know why it was done." };
  return { title: "Case closed", line: "You stayed with it to the end. That is what analysts do." };
}
