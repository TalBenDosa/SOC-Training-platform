"use client";
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/Button";
import { MousePointerClick, X } from "lucide-react";

/**
 * First-use guided tour of a role's screen: each step spotlights one real element (by its
 * `data-tour` anchor), dims the rest, and explains what it is, what to do and where to click.
 * A step may switch a view before it shows (the SOC Manager's menu). Keyboard: Right / Enter
 * next, Left back, Esc closes. If an anchor is not on screen right now (e.g. no containment
 * request yet), the card shows centred and says when the element appears.
 */

export interface TourStep {
  /** `data-tour` anchor to spotlight; omit for a centred card. */
  target?: string;
  title: string;
  body: string;
  /** "Where to click": the concrete action, shown highlighted. */
  action?: string;
  /** Shown when the anchor is not on screen (the element only appears in some situations). */
  absent?: string;
  /** Runs before the step shows (e.g. switch the manager's view). */
  before?: () => void;
}

const PAD = 8;
const CARD_W = 340;
type Rect = { top: number; left: number; width: number; height: number };
const same = (a: Rect | null, b: Rect | null) => !!a && !!b && Math.abs(a.top - b.top) < 1 && Math.abs(a.left - b.left) < 1 && Math.abs(a.width - b.width) < 1 && Math.abs(a.height - b.height) < 1;

export function GuidedTour({ steps, title, onClose }: { steps: TourStep[]; title: string; onClose: () => void }) {
  const [i, setI] = useState(0);
  const [rect, setRect] = useState<Rect | null>(null);
  const [vp, setVp] = useState({ w: 1280, h: 800 });
  const [cardH, setCardH] = useState(260);
  const cardRef = useRef<HTMLDivElement>(null);
  const step = steps[i];
  const last = i === steps.length - 1;
  const find = useCallback(() => (step.target ? document.querySelector<HTMLElement>(`[data-tour="${step.target}"]`) : null), [step.target]);

  // Switch views first, then bring the element into view.
  useEffect(() => {
    step.before?.();
    const reduce = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    const t = setTimeout(() => {
      const el = find();
      if (!el) return;
      // A tall panel scrolls to its top (its header is what the step talks about), a small one to the centre.
      const tall = el.getBoundingClientRect().height > window.innerHeight * 0.6;
      el.scrollIntoView({ block: tall ? "start" : "center", inline: "nearest", behavior: reduce ? "auto" : "smooth" });
    }, 80);
    return () => clearTimeout(t);
  }, [i]); // eslint-disable-line react-hooks/exhaustive-deps

  // Follow the element while the page scrolls, resizes or re-renders.
  useEffect(() => {
    let raf = 0;
    let prev: Rect | null = null;
    const tick = () => {
      setVp(v => (v.w === window.innerWidth && v.h === window.innerHeight ? v : { w: window.innerWidth, h: window.innerHeight }));
      const h = cardRef.current?.offsetHeight;
      if (h) setCardH(prevH => (Math.abs(prevH - h) < 2 ? prevH : h));
      const el = find();
      const r = el?.getBoundingClientRect();
      const next = r && r.width > 0 && r.height > 0 ? { top: r.top, left: r.left, width: r.width, height: r.height } : null;
      if (!(next === null && prev === null) && !same(prev, next)) { prev = next; setRect(next); }
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [find]);

  useLayoutEffect(() => { cardRef.current?.focus(); }, [i]);

  const next = useCallback(() => (last ? onClose() : setI(n => n + 1)), [last, onClose]);
  const back = useCallback(() => setI(n => Math.max(0, n - 1)), []);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { e.preventDefault(); onClose(); }
      else if (e.key === "ArrowRight" || (e.key === "Enter" && (e.target as HTMLElement)?.tagName !== "BUTTON")) { e.preventDefault(); next(); }
      else if (e.key === "ArrowLeft") { e.preventDefault(); back(); }
      else if (e.key === "Tab" && cardRef.current) {
        // keep focus inside the card
        const f = cardRef.current.querySelectorAll<HTMLElement>("button");
        if (!f.length) return;
        const first = f[0], lastEl = f[f.length - 1];
        if (e.shiftKey && document.activeElement === first) { e.preventDefault(); lastEl.focus(); }
        else if (!e.shiftKey && document.activeElement === lastEl) { e.preventDefault(); first.focus(); }
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [next, back, onClose]);

  // The visible part of the element (a tall panel may run past the screen).
  const hole = rect ? (() => {
    const top = Math.max(rect.top - PAD, 4), left = Math.max(rect.left - PAD, 4);
    const bottom = Math.min(rect.top + rect.height + PAD, vp.h - 4), right = Math.min(rect.left + rect.width + PAD, vp.w - 4);
    return bottom > top && right > left ? { top, left, width: right - left, height: bottom - top } : null;
  })() : null;

  // Card placement: beside the element if there is room, else below / above, else inside its corner.
  const narrow = vp.w < 640;
  const cardStyle: React.CSSProperties = (() => {
    const w = Math.min(CARD_W, vp.w - 24);
    if (narrow || !hole) return narrow ? { left: 12, right: 12, bottom: 12 } : { left: (vp.w - w) / 2, top: Math.max(24, (vp.h - cardH) / 2), width: w };
    const clampTop = (t: number) => Math.max(12, Math.min(t, vp.h - cardH - 12));
    if (hole.left + hole.width + 16 + w <= vp.w - 12) return { left: hole.left + hole.width + 16, top: clampTop(hole.top), width: w };
    if (hole.left - 16 - w >= 12) return { left: hole.left - 16 - w, top: clampTop(hole.top), width: w };
    const left = Math.min(Math.max(12, hole.left), vp.w - w - 12);
    if (hole.top + hole.height + 16 + cardH <= vp.h) return { left, top: hole.top + hole.height + 16, width: w };
    if (hole.top - 16 - cardH >= 12) return { left, top: hole.top - 16 - cardH, width: w };
    return { left: Math.max(12, hole.left + hole.width - w - 12), top: clampTop(hole.top + hole.height - cardH - 12), width: w };
  })();

  const missing = !!step.target && !rect;
  return (
    <div className="fixed inset-0 z-[60]" aria-hidden={false}>
      {/* Blocks the page while the tour runs; the spotlight dims everything but the element. */}
      <div className="absolute inset-0" onClick={e => e.stopPropagation()} />
      {hole ? (
        <div className="pointer-events-none absolute rounded-lg ring-2 ring-neon-purple transition-all duration-200 motion-reduce:transition-none"
          style={{ ...hole, boxShadow: "0 0 0 9999px rgba(3, 8, 16, 0.74)" }} />
      ) : (
        <div className="pointer-events-none absolute inset-0 bg-[rgba(3,8,16,0.74)]" />
      )}
      <div ref={cardRef} role="dialog" aria-modal="true" aria-labelledby="tour-step-title" aria-describedby="tour-step-body" tabIndex={-1}
        className="absolute rounded-xl border border-neon-purple/50 bg-bg-elevated p-4 shadow-2xl outline-none" style={cardStyle}>
        <div className="flex items-center gap-2">
          <span className="font-mono text-[10px] uppercase tracking-wider text-neon-purple">{title} · {i + 1} / {steps.length}</span>
          <button type="button" onClick={onClose} aria-label="Close the tour" className="ml-auto rounded p-1 text-slate-400 hover:bg-white/5 hover:text-white focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyber-400"><X className="h-4 w-4" /></button>
        </div>
        <h2 id="tour-step-title" className="mt-1 text-sm font-bold text-white">{step.title}</h2>
        <p id="tour-step-body" className="mt-1.5 text-xs leading-relaxed text-slate-300">{step.body}</p>
        {step.action && (
          <p className="mt-2 flex gap-1.5 rounded-lg border border-cyber-500/30 bg-cyber-500/[0.07] px-2 py-1.5 text-xs text-cyber-100">
            <MousePointerClick className="mt-0.5 h-3.5 w-3.5 shrink-0 text-cyber-300" aria-hidden /> <span>{step.action}</span>
          </p>
        )}
        {missing && step.absent && <p className="mt-2 text-[11px] text-neon-amber">{step.absent}</p>}
        <div className="mt-3 flex items-center gap-1.5">
          <div className="flex flex-1 gap-1" aria-hidden>
            {steps.map((_, k) => <span key={k} className={`h-1 flex-1 rounded-full ${k <= i ? "bg-neon-purple" : "bg-slate-700"}`} />)}
          </div>
        </div>
        <div className="mt-3 flex items-center gap-1.5">
          {i > 0 && <Button variant="ghost" size="sm" onClick={back}>Back</Button>}
          {!last && <button type="button" onClick={onClose} className="text-[11px] text-slate-400 underline-offset-2 hover:text-slate-200 hover:underline">Skip tour</button>}
          <Button variant="primary" size="sm" className="ml-auto" onClick={next}>{last ? "Start working" : "Next"}</Button>
        </div>
        <p className="sr-only" aria-live="polite">{`Step ${i + 1} of ${steps.length}: ${step.title}`}</p>
      </div>
    </div>
  );
}
