"use client";
/**
 * A hover/focus card that is never clipped (demo feedback 2026-11: "hover text is hidden or
 * runs off the screen"). It renders in a portal on <body> with position: fixed, measured from
 * its anchor, clamped inside the viewport, and flips above the anchor when there is no room
 * below. The scroll containers around the log table (overflow-auto, overflow-hidden cards)
 * used to cut absolute-positioned tips off at the table edge.
 */
import { useLayoutEffect, useRef, useState, type ReactNode, type RefObject } from "react";
import { createPortal } from "react-dom";

const GAP = 6;
const MARGIN = 8;

export function FloatingTip({ anchor, open, width = 256, children, onMouseEnter, onMouseLeave, id }: {
  anchor: RefObject<HTMLElement | null>;
  open: boolean;
  width?: number;
  children: ReactNode;
  onMouseEnter?: () => void;
  onMouseLeave?: () => void;
  id?: string;
}) {
  const box = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState<{ left: number; top: number } | null>(null);

  useLayoutEffect(() => {
    if (!open) { setPos(null); return; }
    const place = () => {
      const a = anchor.current?.getBoundingClientRect();
      if (!a) return;
      const vw = window.innerWidth, vh = window.innerHeight;
      const w = Math.min(width, vw - 2 * MARGIN);
      const h = box.current?.offsetHeight ?? 0;
      const left = Math.max(MARGIN, Math.min(a.left, vw - w - MARGIN));
      const below = a.bottom + GAP;
      const top = below + h > vh - MARGIN && a.top - GAP - h >= MARGIN ? a.top - GAP - h : Math.min(below, Math.max(MARGIN, vh - h - MARGIN));
      setPos({ left, top });
    };
    place();
    // Measure again once the card has its real height, and follow scroll and resize.
    const raf = requestAnimationFrame(place);
    window.addEventListener("scroll", place, true);
    window.addEventListener("resize", place);
    return () => { cancelAnimationFrame(raf); window.removeEventListener("scroll", place, true); window.removeEventListener("resize", place); };
  }, [open, anchor, width]);

  if (!open || typeof document === "undefined") return null;
  return createPortal(
    <div
      ref={box}
      id={id}
      role="tooltip"
      onMouseEnter={onMouseEnter}
      onMouseLeave={onMouseLeave}
      style={{ position: "fixed", left: pos?.left ?? -9999, top: pos?.top ?? -9999, width: Math.min(width, (typeof window !== "undefined" ? window.innerWidth : width) - 2 * MARGIN), zIndex: 1000 }}
      className="max-h-[70vh] overflow-y-auto rounded-lg border border-border/80 bg-bg-elevated shadow-2xl [overflow-wrap:anywhere]"
    >
      {children}
    </div>,
    document.body,
  );
}
