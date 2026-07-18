"use client";
import { MotionConfig } from "framer-motion";

/**
 * Makes every framer-motion animation in the app respect the user's OS
 * "reduce motion" setting (WCAG 2.3.3). CSS transitions/animations are handled
 * separately by the prefers-reduced-motion media query in globals.css; this
 * covers the JS-driven framer-motion transitions (feed rows, drawers, tour).
 */
export function MotionProvider({ children }: { children: React.ReactNode }) {
  return <MotionConfig reducedMotion="user">{children}</MotionConfig>;
}
