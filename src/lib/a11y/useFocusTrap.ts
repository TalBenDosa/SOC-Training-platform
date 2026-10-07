"use client";
/**
 * useFocusTrap — modal-dialog keyboard behaviour (WCAG 2.1.2 / 2.4.3).
 *
 * While `active`:
 *   - focus moves into the container (to `initialFocus` if given, else the
 *     first focusable element, else the container itself — give it tabIndex={-1});
 *   - Tab / Shift+Tab cycle inside the container;
 *   - Escape calls `onEscape`;
 *   - focus that escapes by any other route (e.g. a backdrop click) is pulled back.
 * When it turns inactive (or unmounts), focus returns to whatever element had
 * focus before it opened — normally the trigger button.
 *
 * Mirrors the trap in src/components/plans/PlanAnnouncementModal.tsx.
 */
import { useEffect, useRef, type RefObject } from "react";

export const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

function focusables(root: HTMLElement): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter(
    n => n.offsetParent !== null || n === document.activeElement,
  );
}

export function useFocusTrap(
  active: boolean,
  containerRef: RefObject<HTMLElement | null>,
  options: { onEscape?: () => void; initialFocus?: RefObject<HTMLElement | null> } = {},
) {
  // Latest callbacks in a ref so the effect only re-runs when `active` flips.
  const optsRef = useRef(options);
  optsRef.current = options;

  useEffect(() => {
    if (!active) return;
    const previous = document.activeElement as HTMLElement | null;

    const focusInitial = () => {
      const root = containerRef.current;
      if (!root) return;
      const target = optsRef.current.initialFocus?.current ?? focusables(root)[0] ?? root;
      target.focus();
    };
    focusInitial();

    const onKey = (e: KeyboardEvent) => {
      const root = containerRef.current;
      if (!root) return;
      if (e.key === "Escape") {
        if (optsRef.current.onEscape) {
          e.preventDefault();
          e.stopPropagation();
          optsRef.current.onEscape();
        }
        return;
      }
      if (e.key !== "Tab") return;
      const nodes = focusables(root);
      if (nodes.length === 0) { e.preventDefault(); root.focus(); return; }
      const first = nodes[0];
      const last = nodes[nodes.length - 1];
      const activeEl = document.activeElement as HTMLElement | null;
      const inside = activeEl ? root.contains(activeEl) : false;
      if (e.shiftKey && (activeEl === first || activeEl === root || !inside)) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && (activeEl === last || !inside)) { e.preventDefault(); first.focus(); }
    };
    const onFocusIn = (e: FocusEvent) => {
      const root = containerRef.current;
      if (root && e.target instanceof Node && !root.contains(e.target)) focusInitial();
    };

    document.addEventListener("keydown", onKey, true);
    document.addEventListener("focusin", onFocusIn);
    return () => {
      document.removeEventListener("keydown", onKey, true);
      document.removeEventListener("focusin", onFocusIn);
      if (previous && document.contains(previous)) previous.focus();
    };
  }, [active, containerRef]);
}
