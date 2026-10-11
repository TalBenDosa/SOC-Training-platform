"use client";
/**
 * Native-format rendering for the feed UI. The page that owns the feed (dashboard,
 * team room) provides a function that renders an event in its source's native
 * format under the session's stack; the feed components only consume it. The
 * function is computed at DISPLAY time, after the feed has stamped the event's
 * final time, so native timestamps always match what the analyst sees.
 *
 * The registry itself (32 source modules) is loaded lazily by the provider, so it
 * never weighs on first load.
 */
import { createContext, useContext, useMemo } from "react";
import type { TelemetryEvent } from "@/lib/sim/types";
import type { NativeLog } from "./types";

export interface NativeView { log: NativeLog; product: string }
export type NativeRenderer = (ev: TelemetryEvent) => NativeView | null;

const Ctx = createContext<NativeRenderer | null>(null);
export const NativeLogProvider = Ctx.Provider;

/** The native view of an event, or null (no provider yet, or no native module for it). */
export function useNativeLog(ev: TelemetryEvent | null | undefined): NativeView | null {
  const render = useContext(Ctx);
  return useMemo(() => {
    if (!render || !ev) return null;
    try { return render(ev); } catch { return null; }
    // ts is part of the key: the feed re-stamps events as they stream in.
  }, [render, ev]);
}

/** Flatten a native record into [path, value] rows for the fields table (arrays indexed). */
export function nativeRows(record: Record<string, unknown>): [string, string][] {
  const out: [string, string][] = [];
  const walk = (v: unknown, p: string) => {
    if (Array.isArray(v)) {
      if (v.length === 0) { out.push([p, "[]"]); return; }
      v.forEach((x, i) => walk(x, `${p}[${i}]`));
      return;
    }
    if (v !== null && typeof v === "object") {
      const e = Object.entries(v as Record<string, unknown>);
      if (e.length === 0) { out.push([p, "{}"]); return; }
      for (const [k, x] of e) walk(x, p ? `${p}.${k}` : k);
      return;
    }
    if (v === undefined) return;
    out.push([p, v === null ? "null" : String(v)]);
  };
  walk(record, "");
  return out;
}
